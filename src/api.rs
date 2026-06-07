//! FFI API surface for flutter_rust_bridge v2.
//!
//! All public functions and structs here use FRB-friendly types only:
//! `Vec<u8>`, `u32`, `String`, `bool`, and flat structs containing these.
//! FRB's codegen reads this module to produce Dart bindings automatically.
//!
//! Design:
//! - Stateless key generation returns flat byte structs.
//! - Sessions (mutable, stateful) live in a global `RwLock<HashMap<u32, Session>>`
//!   and are referenced by opaque `u32` handles from Dart.
//! - All fallible operations return `Result<T, String>` which FRB maps to Dart exceptions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, RwLock};

use crate::aead;
use crate::identity::{IdentityKeyPair, OneTimePreKey, SignedPreKey};
use crate::mls;
use crate::ratchet::header::MessageHeader;
use crate::ratchet::Session;
use crate::x3dh;
use crate::x3dh::PreKeyBundle;

// ---------------------------------------------------------------------------
// Session storage — global handle map
// ---------------------------------------------------------------------------

static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);
static SESSIONS: LazyLock<RwLock<HashMap<u32, Session>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

// MLS state store — each handle maps to an opaque group-state blob (Vec<u8>).
static NEXT_MLS_ID: AtomicU32 = AtomicU32::new(1);
static MLS_STATES: LazyLock<RwLock<HashMap<u32, Vec<u8>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

// ---------------------------------------------------------------------------
// FRB-friendly result structs (all fields are Vec<u8> / u32 / bool / String)
// ---------------------------------------------------------------------------

/// Returned by `generate_identity_keypair`.
pub struct IdentityKeyResult {
    /// X25519 secret seed (32 bytes) — store in secure storage on device.
    pub identity_secret: Vec<u8>,
    /// X25519 public key (32 bytes) — upload to server.
    pub identity_public: Vec<u8>,
    /// Ed25519 signing key (32 bytes) — store in secure storage on device.
    pub signing_secret: Vec<u8>,
    /// Ed25519 verifying key (32 bytes) — upload to server.
    pub signing_public: Vec<u8>,
}

/// Returned by `generate_signed_pre_key`.
pub struct SignedPreKeyResult {
    /// X25519 secret seed (32 bytes).
    pub secret: Vec<u8>,
    /// X25519 public key (32 bytes).
    pub public_key: Vec<u8>,
    /// Ed25519 signature over the public key (64 bytes).
    pub signature: Vec<u8>,
}

/// Returned by `generate_one_time_pre_keys` (one per key).
pub struct OneTimePreKeyResult {
    pub id: u32,
    /// X25519 public key (32 bytes).
    pub public_key: Vec<u8>,
    /// X25519 secret seed (32 bytes).
    pub secret: Vec<u8>,
}

/// Returned by `x3dh_initiate`.
pub struct X3dhInitResult {
    /// Derived shared secret (32 bytes).
    pub shared_secret: Vec<u8>,
    /// Alice's ephemeral public key (32 bytes) — send to Bob.
    pub ephemeral_public: Vec<u8>,
}

/// Returned by `x3dh_respond`.
pub struct X3dhRespondResult {
    /// Derived shared secret (32 bytes) — same value Alice computed.
    pub shared_secret: Vec<u8>,
}

/// Flat representation of a Double Ratchet message header.
pub struct MessageHeaderData {
    /// Sender's current DH ratchet public key (32 bytes).
    pub dh_public_key: Vec<u8>,
    /// Message number within the current sending chain.
    pub message_number: u32,
    /// Length of the previous sending chain.
    pub previous_chain_length: u32,
}

/// Returned by `session_encrypt`.
pub struct EncryptResult {
    pub header: MessageHeaderData,
    /// AEAD ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (12 bytes).
    pub nonce: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `Vec<u8>` to an `x25519_dalek::PublicKey`, validating length.
fn bytes_to_public_key(bytes: &[u8]) -> Result<x25519_dalek::PublicKey, String> {
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for public key, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(x25519_dalek::PublicKey::from(arr))
}

/// Convert 32 raw bytes into an Ed25519 verifying key.
fn bytes_to_verifying_key(bytes: &[u8]) -> Result<ed25519_dalek::VerifyingKey, String> {
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for verifying key, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| format!("Invalid Ed25519 verifying key: {e}"))
}

/// Map any `CryptoError` (or anything with Display) into a plain `String`.
fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------
// 1. Identity key generation (stateless)
// ---------------------------------------------------------------------------

/// Generate a fresh identity keypair (X25519 + Ed25519).
///
/// Returns all four key components as raw bytes so the Dart side can persist
/// secrets in secure storage and upload public keys to the server.
pub fn generate_identity_keypair() -> IdentityKeyResult {
    let kp = IdentityKeyPair::generate();
    IdentityKeyResult {
        identity_secret: kp.secret_bytes().to_vec(),
        identity_public: kp.public_key().as_bytes().to_vec(),
        signing_secret: kp.signing_secret_bytes().to_vec(),
        signing_public: kp.verifying_key().as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// 2. Signed pre-key generation
// ---------------------------------------------------------------------------

/// Generate a signed pre-key from an existing identity keypair (provided as raw bytes).
///
/// The identity secret (32 bytes) and signing secret (32 bytes) are the values
/// originally returned by `generate_identity_keypair`.
pub fn generate_signed_pre_key(
    identity_secret: Vec<u8>,
    signing_secret: Vec<u8>,
) -> Result<SignedPreKeyResult, String> {
    let identity = IdentityKeyPair::from_bytes(&identity_secret, &signing_secret)
        .map_err(map_err)?;
    let spk = SignedPreKey::generate(&identity);

    Ok(SignedPreKeyResult {
        secret: spk.secret_bytes().to_vec(),
        public_key: spk.public_key().as_bytes().to_vec(),
        signature: spk.signature().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// 3. One-time pre-key batch generation
// ---------------------------------------------------------------------------

/// Generate a batch of one-time pre-keys with sequential IDs starting from 0.
pub fn generate_one_time_pre_keys(count: u32) -> Vec<OneTimePreKeyResult> {
    let keys = OneTimePreKey::generate_batch(count as usize);
    keys.into_iter()
        .map(|k| OneTimePreKeyResult {
            id: k.id(),
            public_key: k.public_key().as_bytes().to_vec(),
            secret: k.secret_bytes().to_vec(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 4. X3DH initiation (Alice side)
// ---------------------------------------------------------------------------

/// Perform the X3DH key agreement as the initiator (Alice).
///
/// Requires Alice's identity key bytes and Bob's public pre-key bundle
/// (all as raw bytes). Returns the shared secret and Alice's ephemeral
/// public key that must be sent to Bob.
pub fn x3dh_initiate(
    alice_identity_secret: Vec<u8>,
    alice_signing_secret: Vec<u8>,
    bob_identity_public: Vec<u8>,
    bob_signing_public: Vec<u8>,
    bob_spk_public: Vec<u8>,
    bob_spk_signature: Vec<u8>,
    bob_opk_public: Option<Vec<u8>>,
) -> Result<X3dhInitResult, String> {
    let alice_identity =
        IdentityKeyPair::from_bytes(&alice_identity_secret, &alice_signing_secret)
            .map_err(map_err)?;

    let bob_ik = bytes_to_public_key(&bob_identity_public)?;
    let bob_spk = bytes_to_public_key(&bob_spk_public)?;
    let bob_vk = bytes_to_verifying_key(&bob_signing_public)?;
    let bob_opk = match bob_opk_public {
        Some(ref bytes) => Some(bytes_to_public_key(bytes)?),
        None => None,
    };

    let bundle = PreKeyBundle {
        identity_key: bob_ik,
        identity_verifying_key: bob_vk,
        signed_pre_key: bob_spk,
        signature: bob_spk_signature,
        one_time_pre_key: bob_opk,
    };

    let result = x3dh::initiate(&alice_identity, &bundle).map_err(map_err)?;

    Ok(X3dhInitResult {
        shared_secret: result.shared_secret,
        ephemeral_public: result.ephemeral_key.as_bytes().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// 4b. X3DH respond (Bob side)
// ---------------------------------------------------------------------------

/// Perform the X3DH key agreement as the responder (Bob).
///
/// Bob uses his own identity key, signed pre-key, and Alice's identity +
/// ephemeral public keys to derive the same shared secret Alice computed.
pub fn x3dh_respond(
    bob_identity_secret: Vec<u8>,
    bob_signing_secret: Vec<u8>,
    bob_spk_secret: Vec<u8>,
    bob_spk_public: Vec<u8>,
    bob_spk_signature: Vec<u8>,
    alice_identity_public: Vec<u8>,
    alice_ephemeral_public: Vec<u8>,
) -> Result<X3dhRespondResult, String> {
    let bob_identity =
        IdentityKeyPair::from_bytes(&bob_identity_secret, &bob_signing_secret)
            .map_err(map_err)?;

    let bob_spk = SignedPreKey::from_bytes(&bob_spk_secret, &bob_spk_public, &bob_spk_signature)
        .map_err(map_err)?;

    let alice_ik = bytes_to_public_key(&alice_identity_public)?;
    let alice_ek = bytes_to_public_key(&alice_ephemeral_public)?;

    // No OPK for now (consumed on first use, not tracked in FFI)
    let result = x3dh::respond(&bob_identity, &bob_spk, None, &alice_ik, &alice_ek)
        .map_err(map_err)?;

    Ok(X3dhRespondResult {
        shared_secret: result.shared_secret,
    })
}

// ---------------------------------------------------------------------------
// 5. Session creation — initiator (Alice)
// ---------------------------------------------------------------------------

/// Create a Double Ratchet session as the initiator (Alice).
///
/// Takes the shared secret from X3DH and Bob's signed pre-key public bytes.
/// Returns an opaque session handle (`u32`) used in subsequent encrypt/decrypt calls.
pub fn create_session_initiator(
    shared_secret: Vec<u8>,
    responder_spk_public: Vec<u8>,
) -> Result<u32, String> {
    let bob_spk_pub = bytes_to_public_key(&responder_spk_public)?;
    let session = Session::init_alice(&shared_secret, bob_spk_pub);

    let handle = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    SESSIONS
        .write()
        .map_err(|e| format!("Session lock poisoned: {}", e))?
        .insert(handle, session);

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 6. Session creation — responder (Bob)
// ---------------------------------------------------------------------------

/// Create a Double Ratchet session as the responder (Bob).
///
/// Requires the shared secret from X3DH and Bob's signed pre-key
/// (secret + public + signature bytes) so we can reconstruct the full
/// `SignedPreKey` that `Session::init_bob` expects.
pub fn create_session_responder(
    shared_secret: Vec<u8>,
    our_spk_secret: Vec<u8>,
    our_spk_public: Vec<u8>,
    our_spk_signature: Vec<u8>,
) -> Result<u32, String> {
    let spk = SignedPreKey::from_bytes(&our_spk_secret, &our_spk_public, &our_spk_signature)
        .map_err(map_err)?;
    let session = Session::init_bob(&shared_secret, &spk);

    let handle = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    SESSIONS
        .write()
        .map_err(|e| format!("Session lock poisoned: {}", e))?
        .insert(handle, session);

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 7. Session encrypt
// ---------------------------------------------------------------------------

/// Encrypt a plaintext message using the session identified by `session_handle`.
///
/// Returns the message header (needed by the receiver to ratchet), the
/// AEAD ciphertext, and the 12-byte nonce.
pub fn session_encrypt(
    session_handle: u32,
    plaintext: Vec<u8>,
) -> Result<EncryptResult, String> {
    let mut sessions = SESSIONS
        .write()
        .map_err(|e| format!("Session lock poisoned: {}", e))?;

    let session = sessions
        .get_mut(&session_handle)
        .ok_or_else(|| format!("No session with handle {}", session_handle))?;

    let (header, encrypted) = session.encrypt(&plaintext).map_err(map_err)?;

    Ok(EncryptResult {
        header: MessageHeaderData {
            dh_public_key: header.dh_public_key,
            message_number: header.message_number,
            previous_chain_length: header.previous_chain_length,
        },
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
    })
}

// ---------------------------------------------------------------------------
// 8. Session decrypt
// ---------------------------------------------------------------------------

/// Decrypt a received message using the session identified by `session_handle`.
///
/// The caller provides the header data, ciphertext, and nonce exactly as
/// received from `session_encrypt` on the sender's side.
pub fn session_decrypt(
    session_handle: u32,
    header: MessageHeaderData,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut sessions = SESSIONS
        .write()
        .map_err(|e| format!("Session lock poisoned: {}", e))?;

    let session = sessions
        .get_mut(&session_handle)
        .ok_or_else(|| format!("No session with handle {}", session_handle))?;

    let msg_header = MessageHeader {
        dh_public_key: header.dh_public_key,
        message_number: header.message_number,
        previous_chain_length: header.previous_chain_length,
    };

    let encrypted = aead::Encrypted {
        nonce,
        ciphertext,
    };

    session.decrypt(&msg_header, &encrypted).map_err(map_err)
}

// ---------------------------------------------------------------------------
// 9. Session destruction
// ---------------------------------------------------------------------------

/// Remove a session from the global session store.
///
/// Returns `true` if a session with that handle existed and was removed,
/// `false` if no such session was found.
pub fn destroy_session(session_handle: u32) -> bool {
    match SESSIONS.write() {
        Ok(mut sessions) => sessions.remove(&session_handle).is_some(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// 10. Simple AES-256-GCM encrypt/decrypt (stateless, key provided by caller)
// ---------------------------------------------------------------------------

/// Result of a simple AES-256-GCM encryption.
pub struct SimpleEncryptResult {
    /// AEAD ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes).
    pub nonce: Vec<u8>,
}

/// Simple AES-256-GCM encrypt with a caller-provided 32-byte key.
///
/// Used for the simple key-agreement encryption scheme where the shared
/// key is derived from sorted identity public keys. No session state needed.
pub fn aes_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<SimpleEncryptResult, String> {
    if key.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", key.len()));
    }
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let encrypted = crate::aead::encrypt(&key_arr, &plaintext, &[]).map_err(|e| e.to_string())?;
    Ok(SimpleEncryptResult {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
    })
}

/// Simple AES-256-GCM decrypt with a caller-provided 32-byte key.
///
/// Counterpart to `aes_encrypt`. Decrypts ciphertext using the same key
/// and the nonce that was returned from encryption.
pub fn aes_decrypt(key: Vec<u8>, ciphertext: Vec<u8>, nonce: Vec<u8>) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", key.len()));
    }
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let encrypted = crate::aead::Encrypted { ciphertext, nonce };
    crate::aead::decrypt(&key_arr, &encrypted, &[]).map_err(|e| e.to_string())
}

// ===========================================================================
// 11. MLS — Key Package Generation
// ===========================================================================

/// Result of MLS key package generation (FRB-friendly).
pub struct MlsKeyPackageResult {
    /// TLS-serialized key package — share with the server.
    pub key_package: Vec<u8>,
    /// Opaque secret bundle — store privately on device.
    pub secret_bundle: Vec<u8>,
}

/// Generate an MLS key package for the given identity bytes.
pub fn mls_generate_key_package(identity: Vec<u8>) -> Result<MlsKeyPackageResult, String> {
    let result = mls::generate_key_package(&identity).map_err(map_err)?;
    Ok(MlsKeyPackageResult {
        key_package: result.key_package,
        secret_bundle: result.secret_bundle,
    })
}

// ===========================================================================
// 12. MLS — Create Group
// ===========================================================================

/// Result of creating an MLS group (FRB-friendly).
pub struct MlsCreateGroupResult {
    /// Handle referencing the group state stored in the global MLS_STATES map.
    pub handle: u32,
    /// The group identifier.
    pub group_id: Vec<u8>,
    /// Initial epoch.
    pub epoch: u64,
}

/// Create a new MLS group with the caller as sole member.
/// Returns a handle to the stored group state.
pub fn mls_create_group(identity: Vec<u8>) -> Result<MlsCreateGroupResult, String> {
    let result = mls::create_group(&identity).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsCreateGroupResult {
        handle,
        group_id: result.group_id,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 13. MLS — Add Member
// ===========================================================================

/// Result of adding a member to an MLS group (FRB-friendly).
pub struct MlsAddMemberResult {
    /// Handle referencing the updated group state.
    pub handle: u32,
    /// TLS-serialized commit — broadcast to existing members.
    pub commit: Vec<u8>,
    /// TLS-serialized welcome — send to the new member.
    pub welcome: Vec<u8>,
    /// New epoch after the add.
    pub epoch: u64,
}

/// Add a member to the MLS group referenced by `group_handle`.
pub fn mls_add_member(
    group_handle: u32,
    key_package: Vec<u8>,
) -> Result<MlsAddMemberResult, String> {
    let state = {
        let states = MLS_STATES
            .read()
            .map_err(|e| format!("MLS state lock poisoned: {}", e))?;
        states
            .get(&group_handle)
            .ok_or_else(|| format!("No MLS group with handle {}", group_handle))?
            .clone()
    };

    let result = mls::add_member(&state, &key_package).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsAddMemberResult {
        handle,
        commit: result.commit,
        welcome: result.welcome,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 14. MLS — Remove Member
// ===========================================================================

/// Result of removing a member from an MLS group (FRB-friendly).
pub struct MlsRemoveMemberResult {
    /// Handle referencing the updated group state.
    pub handle: u32,
    /// TLS-serialized commit — broadcast to remaining members.
    pub commit: Vec<u8>,
    /// New epoch after the removal.
    pub epoch: u64,
}

/// Remove a member (by leaf index) from the MLS group referenced by `group_handle`.
pub fn mls_remove_member(
    group_handle: u32,
    leaf_index: u32,
) -> Result<MlsRemoveMemberResult, String> {
    let state = {
        let states = MLS_STATES
            .read()
            .map_err(|e| format!("MLS state lock poisoned: {}", e))?;
        states
            .get(&group_handle)
            .ok_or_else(|| format!("No MLS group with handle {}", group_handle))?
            .clone()
    };

    let result = mls::remove_member(&state, leaf_index).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsRemoveMemberResult {
        handle,
        commit: result.commit,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 15. MLS — Encrypt Message
// ===========================================================================

/// Result of MLS group encryption (FRB-friendly).
pub struct MlsEncryptResult {
    /// Handle referencing the updated group state.
    pub handle: u32,
    /// TLS-serialized MLS ciphertext.
    pub mls_ciphertext: Vec<u8>,
    /// Current epoch.
    pub epoch: u64,
}

/// Encrypt a plaintext message for the MLS group referenced by `group_handle`.
pub fn mls_encrypt_message(
    group_handle: u32,
    plaintext: Vec<u8>,
) -> Result<MlsEncryptResult, String> {
    let state = {
        let states = MLS_STATES
            .read()
            .map_err(|e| format!("MLS state lock poisoned: {}", e))?;
        states
            .get(&group_handle)
            .ok_or_else(|| format!("No MLS group with handle {}", group_handle))?
            .clone()
    };

    let result = mls::encrypt_message(&state, &plaintext).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsEncryptResult {
        handle,
        mls_ciphertext: result.mls_ciphertext,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 16. MLS — Decrypt Message
// ===========================================================================

/// Result of MLS group decryption (FRB-friendly).
pub struct MlsDecryptResult {
    /// Handle referencing the updated group state.
    pub handle: u32,
    /// Decrypted plaintext bytes (empty if message was a commit/proposal).
    pub plaintext: Vec<u8>,
}

/// Decrypt a received MLS group message using the state referenced by `group_handle`.
pub fn mls_decrypt_message(
    group_handle: u32,
    mls_message: Vec<u8>,
) -> Result<MlsDecryptResult, String> {
    let state = {
        let states = MLS_STATES
            .read()
            .map_err(|e| format!("MLS state lock poisoned: {}", e))?;
        states
            .get(&group_handle)
            .ok_or_else(|| format!("No MLS group with handle {}", group_handle))?
            .clone()
    };

    let result = mls::decrypt_message(&state, &mls_message).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsDecryptResult {
        handle,
        plaintext: result.plaintext,
    })
}

// ===========================================================================
// 17. MLS — Process Welcome
// ===========================================================================

/// Result of processing an MLS welcome message (FRB-friendly).
pub struct MlsProcessWelcomeResult {
    /// Handle referencing the new group state.
    pub handle: u32,
    /// The group identifier.
    pub group_id: Vec<u8>,
    /// Current epoch.
    pub epoch: u64,
}

/// Process a welcome message to join an MLS group.
pub fn mls_process_welcome(
    welcome: Vec<u8>,
    secret_bundle: Vec<u8>,
) -> Result<MlsProcessWelcomeResult, String> {
    let result = mls::process_welcome(&welcome, &secret_bundle).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsProcessWelcomeResult {
        handle,
        group_id: result.group_id,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 18. MLS — Process Commit
// ===========================================================================

/// Result of processing an MLS commit (FRB-friendly).
pub struct MlsProcessCommitResult {
    /// Handle referencing the updated group state.
    pub handle: u32,
    /// New epoch after the commit.
    pub epoch: u64,
}

/// Process a received commit to update MLS group state.
pub fn mls_process_commit(
    group_handle: u32,
    commit: Vec<u8>,
) -> Result<MlsProcessCommitResult, String> {
    let state = {
        let states = MLS_STATES
            .read()
            .map_err(|e| format!("MLS state lock poisoned: {}", e))?;
        states
            .get(&group_handle)
            .ok_or_else(|| format!("No MLS group with handle {}", group_handle))?
            .clone()
    };

    let result = mls::process_commit(&state, &commit).map_err(map_err)?;

    let handle = NEXT_MLS_ID.fetch_add(1, Ordering::Relaxed);
    MLS_STATES
        .write()
        .map_err(|e| format!("MLS state lock poisoned: {}", e))?
        .insert(handle, result.group_state);

    Ok(MlsProcessCommitResult {
        handle,
        epoch: result.epoch,
    })
}

// ===========================================================================
// 19. MLS — Destroy Group State
// ===========================================================================

/// Remove an MLS group state from the global store.
/// Returns `true` if a state with that handle existed and was removed.
pub fn mls_destroy_state(group_handle: u32) -> bool {
    match MLS_STATES.write() {
        Ok(mut states) => states.remove(&group_handle).is_some(),
        Err(_) => false,
    }
}
