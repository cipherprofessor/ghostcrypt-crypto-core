//! WASM bindings for GhostCrypt crypto core.
//!
//! Exposes the Rust crypto API to JavaScript via wasm-bindgen.
//! Complex Rust types are stored in thread-local HashMaps and referenced
//! by opaque u32 handles. Data crosses the WASM boundary as JSON strings
//! with binary values encoded in base64.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::aead;
use crate::identity::{IdentityKeyPair, SignedPreKey, OneTimePreKey};
use crate::mls;
use crate::ratchet::{MessageHeader, Session};
use crate::x3dh::{self, PreKeyBundle};

// ---------------------------------------------------------------------------
// Thread-local stores for opaque handles
// ---------------------------------------------------------------------------

thread_local! {
    static IDENTITY_KEYS: RefCell<HashMap<u32, IdentityKeyPair>> = RefCell::new(HashMap::new());
    static SPK_KEYS: RefCell<HashMap<u32, SignedPreKey>> = RefCell::new(HashMap::new());
    static SESSIONS: RefCell<HashMap<u32, Session>> = RefCell::new(HashMap::new());
    static MLS_STATES: RefCell<HashMap<u32, Vec<u8>>> = RefCell::new(HashMap::new());
    static NEXT_ID: RefCell<u32> = RefCell::new(1);
}

/// Allocate the next unique handle ID.
fn next_id() -> u32 {
    NEXT_ID.with(|id| {
        let current = *id.borrow();
        *id.borrow_mut() = current + 1;
        current
    })
}

// ---------------------------------------------------------------------------
// 1. generate_identity_keypair
// ---------------------------------------------------------------------------

/// Generate a new identity keypair.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 1,
///   "public_key": "<base64>",
///   "signing_key_public": "<base64>"
/// }
/// ```
///
/// The private keys are retained in WASM memory, referenced by `handle`.
#[wasm_bindgen]
pub fn generate_identity_keypair() -> Result<JsValue, JsError> {
    let kp = IdentityKeyPair::generate();

    let public_key_b64 = BASE64.encode(kp.public_key().as_bytes());
    let signing_key_pub_b64 = BASE64.encode(kp.verifying_key().as_bytes());

    let handle = next_id();
    IDENTITY_KEYS.with(|store| {
        store.borrow_mut().insert(handle, kp);
    });

    let result = serde_json::json!({
        "handle": handle,
        "public_key": public_key_b64,
        "signing_key_public": signing_key_pub_b64,
    });

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 2. generate_signed_pre_key
// ---------------------------------------------------------------------------

/// Generate a signed pre-key using the identity keypair referenced by
/// `identity_handle`.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 2,
///   "public_key": "<base64>",
///   "signature": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn generate_signed_pre_key(identity_handle: u32) -> Result<JsValue, JsError> {
    let spk = IDENTITY_KEYS.with(|store| {
        let map = store.borrow();
        let identity = map.get(&identity_handle)
            .ok_or_else(|| JsError::new(&format!(
                "Identity handle {} not found", identity_handle
            )))?;
        Ok::<SignedPreKey, JsError>(SignedPreKey::generate(identity))
    })?;

    let public_key_b64 = BASE64.encode(spk.public_key().as_bytes());
    let signature_b64 = BASE64.encode(spk.signature());

    let handle = next_id();
    SPK_KEYS.with(|store| {
        store.borrow_mut().insert(handle, spk);
    });

    let result = serde_json::json!({
        "handle": handle,
        "public_key": public_key_b64,
        "signature": signature_b64,
    });

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 3. generate_one_time_pre_keys
// ---------------------------------------------------------------------------

/// Generate a batch of one-time pre-keys.
///
/// Returns a JSON array:
/// ```json
/// [
///   { "id": 0, "public_key": "<base64>" },
///   { "id": 1, "public_key": "<base64>" }
/// ]
/// ```
#[wasm_bindgen]
pub fn generate_one_time_pre_keys(count: u32) -> Result<JsValue, JsError> {
    let otpks = OneTimePreKey::generate_batch(count as usize);

    let items: Vec<serde_json::Value> = otpks
        .iter()
        .map(|otpk| {
            serde_json::json!({
                "id": otpk.id(),
                "public_key": BASE64.encode(otpk.public_key().as_bytes()),
            })
        })
        .collect();

    serde_json::to_string(&items)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 4. X3DH initiate (Alice)
// ---------------------------------------------------------------------------

/// Perform X3DH key agreement as Alice (the initiator).
///
/// * `identity_handle` — handle to Alice's `IdentityKeyPair` (from `generate_identity_keypair`).
/// * `bob_bundle_json` — JSON string containing Bob's pre-key bundle:
///   ```json
///   {
///     "identity_key": "<base64>",
///     "signed_pre_key": "<base64>",
///     "signature": "<base64>",
///     "one_time_pre_key": "<base64 or null>"
///   }
///   ```
///
/// Returns JSON:
/// ```json
/// {
///   "shared_secret": "<base64>",
///   "ephemeral_key": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn x3dh_initiate(
    identity_handle: u32,
    bob_bundle_json: &str,
) -> Result<JsValue, JsError> {
    // Parse Bob's bundle from JSON
    let bundle_value: serde_json::Value = serde_json::from_str(bob_bundle_json)
        .map_err(|e| JsError::new(&format!("Invalid bundle JSON: {}", e)))?;

    let identity_key_b64 = bundle_value["identity_key"]
        .as_str()
        .ok_or_else(|| JsError::new("bundle.identity_key missing or not a string"))?;
    let signed_pre_key_b64 = bundle_value["signed_pre_key"]
        .as_str()
        .ok_or_else(|| JsError::new("bundle.signed_pre_key missing or not a string"))?;
    let signature_b64 = bundle_value["signature"]
        .as_str()
        .ok_or_else(|| JsError::new("bundle.signature missing or not a string"))?;
    let identity_verifying_key_b64 = bundle_value["identity_verifying_key"]
        .as_str()
        .ok_or_else(|| JsError::new("bundle.identity_verifying_key missing or not a string"))?;
    let one_time_pre_key_b64 = bundle_value["one_time_pre_key"].as_str();

    // Decode base64 values
    let ik_bytes = BASE64.decode(identity_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid identity_key base64: {}", e)))?;
    let spk_bytes = BASE64.decode(signed_pre_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid signed_pre_key base64: {}", e)))?;
    let sig_bytes = BASE64.decode(signature_b64)
        .map_err(|e| JsError::new(&format!("Invalid signature base64: {}", e)))?;
    let vk_bytes = BASE64.decode(identity_verifying_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid identity_verifying_key base64: {}", e)))?;

    if ik_bytes.len() != 32 {
        return Err(JsError::new("identity_key must be 32 bytes"));
    }
    if spk_bytes.len() != 32 {
        return Err(JsError::new("signed_pre_key must be 32 bytes"));
    }
    if vk_bytes.len() != 32 {
        return Err(JsError::new("identity_verifying_key must be 32 bytes"));
    }

    let mut ik_arr = [0u8; 32];
    ik_arr.copy_from_slice(&ik_bytes);
    let mut spk_arr = [0u8; 32];
    spk_arr.copy_from_slice(&spk_bytes);
    let mut vk_arr = [0u8; 32];
    vk_arr.copy_from_slice(&vk_bytes);

    let bob_ik = x25519_dalek::PublicKey::from(ik_arr);
    let bob_spk = x25519_dalek::PublicKey::from(spk_arr);
    let bob_vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| JsError::new(&format!("Invalid identity_verifying_key: {}", e)))?;

    let bob_opk = if let Some(opk_b64) = one_time_pre_key_b64 {
        let opk_bytes = BASE64.decode(opk_b64)
            .map_err(|e| JsError::new(&format!("Invalid one_time_pre_key base64: {}", e)))?;
        if opk_bytes.len() != 32 {
            return Err(JsError::new("one_time_pre_key must be 32 bytes"));
        }
        let mut opk_arr = [0u8; 32];
        opk_arr.copy_from_slice(&opk_bytes);
        Some(x25519_dalek::PublicKey::from(opk_arr))
    } else {
        None
    };

    let bundle = PreKeyBundle {
        identity_key: bob_ik,
        identity_verifying_key: bob_vk,
        signed_pre_key: bob_spk,
        signature: sig_bytes,
        one_time_pre_key: bob_opk,
    };

    // Perform X3DH using Alice's identity from the handle store
    let x3dh_result = IDENTITY_KEYS.with(|store| {
        let map = store.borrow();
        let identity = map.get(&identity_handle)
            .ok_or_else(|| JsError::new(&format!(
                "Identity handle {} not found", identity_handle
            )))?;
        x3dh::initiate(identity, &bundle)
            .map_err(|e| JsError::new(&format!("X3DH initiate failed: {}", e)))
    })?;

    let result = serde_json::json!({
        "shared_secret": BASE64.encode(&x3dh_result.shared_secret),
        "ephemeral_key": BASE64.encode(x3dh_result.ephemeral_key.as_bytes()),
    });

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 5. X3DH respond (Bob)
// ---------------------------------------------------------------------------

/// Perform X3DH key agreement as Bob (the responder).
///
/// * `identity_handle` — handle to Bob's `IdentityKeyPair`.
/// * `spk_handle` — handle to Bob's `SignedPreKey`.
/// * `alice_identity_key_b64` — base64-encoded Alice's identity public key.
/// * `alice_ephemeral_key_b64` — base64-encoded Alice's ephemeral public key.
///
/// Returns JSON:
/// ```json
/// {
///   "shared_secret": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn x3dh_respond(
    identity_handle: u32,
    spk_handle: u32,
    alice_identity_key_b64: &str,
    alice_ephemeral_key_b64: &str,
) -> Result<JsValue, JsError> {
    let alice_ik_bytes = BASE64.decode(alice_identity_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid alice_identity_key base64: {}", e)))?;
    let alice_ek_bytes = BASE64.decode(alice_ephemeral_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid alice_ephemeral_key base64: {}", e)))?;

    if alice_ik_bytes.len() != 32 {
        return Err(JsError::new("alice_identity_key must be 32 bytes"));
    }
    if alice_ek_bytes.len() != 32 {
        return Err(JsError::new("alice_ephemeral_key must be 32 bytes"));
    }

    let mut ik_arr = [0u8; 32];
    ik_arr.copy_from_slice(&alice_ik_bytes);
    let mut ek_arr = [0u8; 32];
    ek_arr.copy_from_slice(&alice_ek_bytes);

    let alice_ik = x25519_dalek::PublicKey::from(ik_arr);
    let alice_ek = x25519_dalek::PublicKey::from(ek_arr);

    let x3dh_result = IDENTITY_KEYS.with(|store| {
        let ik_map = store.borrow();
        let identity = ik_map.get(&identity_handle)
            .ok_or_else(|| JsError::new(&format!(
                "Identity handle {} not found", identity_handle
            )))?;

        SPK_KEYS.with(|spk_store| {
            let spk_map = spk_store.borrow();
            let spk = spk_map.get(&spk_handle)
                .ok_or_else(|| JsError::new(&format!(
                    "SPK handle {} not found", spk_handle
                )))?;

            // No OPK for now (consumed on first use, not tracked in WASM)
            x3dh::respond(identity, spk, None, &alice_ik, &alice_ek)
                .map_err(|e| JsError::new(&format!("X3DH respond failed: {}", e)))
        })
    })?;

    let result = serde_json::json!({
        "shared_secret": BASE64.encode(&x3dh_result.shared_secret),
    });

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 6. create_session_alice
// ---------------------------------------------------------------------------

/// Initialize a Double Ratchet session as Alice (the initiator).
///
/// * `shared_secret_b64` — base64-encoded shared secret from X3DH (32 bytes).
/// * `bob_spk_public_b64` — base64-encoded Bob's signed pre-key public key (32 bytes).
///
/// Returns the session handle (u32).
#[wasm_bindgen]
pub fn create_session_alice(
    shared_secret_b64: &str,
    bob_spk_public_b64: &str,
) -> Result<u32, JsError> {
    let shared_secret = BASE64.decode(shared_secret_b64)
        .map_err(|e| JsError::new(&format!("Invalid shared_secret base64: {}", e)))?;

    let bob_spk_bytes = BASE64.decode(bob_spk_public_b64)
        .map_err(|e| JsError::new(&format!("Invalid bob_spk_public base64: {}", e)))?;

    if bob_spk_bytes.len() != 32 {
        return Err(JsError::new("Bob's SPK public key must be 32 bytes"));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bob_spk_bytes);
    let bob_spk_public = x25519_dalek::PublicKey::from(key_bytes);

    let session = Session::init_alice(&shared_secret, bob_spk_public);

    let handle = next_id();
    SESSIONS.with(|store| {
        store.borrow_mut().insert(handle, session);
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 7. create_session_bob
// ---------------------------------------------------------------------------

/// Initialize a Double Ratchet session as Bob (the responder).
///
/// * `shared_secret_b64` — base64-encoded shared secret from X3DH (32 bytes).
/// * `spk_handle` — handle to a previously generated `SignedPreKey`.
///
/// Returns the session handle (u32).
#[wasm_bindgen]
pub fn create_session_bob(
    shared_secret_b64: &str,
    spk_handle: u32,
) -> Result<u32, JsError> {
    let shared_secret = BASE64.decode(shared_secret_b64)
        .map_err(|e| JsError::new(&format!("Invalid shared_secret base64: {}", e)))?;

    let session = SPK_KEYS.with(|store| {
        let map = store.borrow();
        let spk = map.get(&spk_handle)
            .ok_or_else(|| JsError::new(&format!(
                "SPK handle {} not found", spk_handle
            )))?;
        Ok::<Session, JsError>(Session::init_bob(&shared_secret, spk))
    })?;

    let handle = next_id();
    SESSIONS.with(|store| {
        store.borrow_mut().insert(handle, session);
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 8. session_encrypt
// ---------------------------------------------------------------------------

/// Encrypt a message using the session referenced by `session_handle`.
///
/// * `session_handle` — handle to an active Double Ratchet session.
/// * `plaintext_b64` — base64-encoded plaintext bytes.
///
/// Returns JSON:
/// ```json
/// {
///   "header": {
///     "dh_public_key": "<base64>",
///     "message_number": 0,
///     "previous_chain_length": 0
///   },
///   "ciphertext": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn session_encrypt(
    session_handle: u32,
    plaintext_b64: &str,
) -> Result<JsValue, JsError> {
    let plaintext = BASE64.decode(plaintext_b64)
        .map_err(|e| JsError::new(&format!("Invalid plaintext base64: {}", e)))?;

    let (header, encrypted) = SESSIONS.with(|store| {
        let mut map = store.borrow_mut();
        let session = map.get_mut(&session_handle)
            .ok_or_else(|| JsError::new(&format!(
                "Session handle {} not found", session_handle
            )))?;
        session.encrypt(&plaintext)
            .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))
    })?;

    let result = serde_json::json!({
        "header": {
            "dh_public_key": BASE64.encode(&header.dh_public_key),
            "message_number": header.message_number,
            "previous_chain_length": header.previous_chain_length,
        },
        "ciphertext": BASE64.encode(&encrypted.ciphertext),
        "nonce": BASE64.encode(&encrypted.nonce),
    });

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 9. session_decrypt
// ---------------------------------------------------------------------------

/// Decrypt a message using the session referenced by `session_handle`.
///
/// * `session_handle` — handle to an active Double Ratchet session.
/// * `header_json` — JSON string with the message header (same format as
///   returned by `session_encrypt`).
/// * `ciphertext_b64` — base64-encoded ciphertext.
/// * `nonce_b64` — base64-encoded nonce (from `session_encrypt` output).
///
/// Returns base64-encoded plaintext.
#[wasm_bindgen]
pub fn session_decrypt(
    session_handle: u32,
    header_json: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
) -> Result<JsValue, JsError> {
    // Parse header from JSON
    let header_value: serde_json::Value = serde_json::from_str(header_json)
        .map_err(|e| JsError::new(&format!("Invalid header JSON: {}", e)))?;

    let dh_public_key_b64 = header_value["dh_public_key"]
        .as_str()
        .ok_or_else(|| JsError::new("header.dh_public_key missing or not a string"))?;

    let dh_public_key = BASE64.decode(dh_public_key_b64)
        .map_err(|e| JsError::new(&format!("Invalid dh_public_key base64: {}", e)))?;

    let message_number = header_value["message_number"]
        .as_u64()
        .ok_or_else(|| JsError::new("header.message_number missing or not a number"))?
        as u32;

    let previous_chain_length = header_value["previous_chain_length"]
        .as_u64()
        .ok_or_else(|| JsError::new("header.previous_chain_length missing or not a number"))?
        as u32;

    let header = MessageHeader {
        dh_public_key,
        message_number,
        previous_chain_length,
    };

    let ciphertext = BASE64.decode(ciphertext_b64)
        .map_err(|e| JsError::new(&format!("Invalid ciphertext base64: {}", e)))?;

    let nonce = BASE64.decode(nonce_b64)
        .map_err(|e| JsError::new(&format!("Invalid nonce base64: {}", e)))?;

    let encrypted = aead::Encrypted {
        nonce,
        ciphertext,
    };

    let plaintext = SESSIONS.with(|store| {
        let mut map = store.borrow_mut();
        let session = map.get_mut(&session_handle)
            .ok_or_else(|| JsError::new(&format!(
                "Session handle {} not found", session_handle
            )))?;
        session.decrypt(&header, &encrypted)
            .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))
    })?;

    Ok(JsValue::from_str(&BASE64.encode(&plaintext)))
}

// ---------------------------------------------------------------------------
// 10. MLS — Generate Key Package
// ---------------------------------------------------------------------------

/// Generate an MLS key package for the given identity.
///
/// * `identity_b64` — base64-encoded identity bytes.
///
/// Returns JSON:
/// ```json
/// {
///   "key_package": "<base64>",
///   "secret_bundle": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn mls_generate_key_package(identity_b64: &str) -> Result<JsValue, JsError> {
    let identity = BASE64.decode(identity_b64)
        .map_err(|e| JsError::new(&format!("Invalid identity base64: {}", e)))?;

    let result = mls::generate_key_package(&identity)
        .map_err(|e| JsError::new(&format!("MLS key package generation failed: {}", e)))?;

    let json = serde_json::json!({
        "key_package": BASE64.encode(&result.key_package),
        "secret_bundle": BASE64.encode(&result.secret_bundle),
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 11. MLS — Create Group
// ---------------------------------------------------------------------------

/// Create a new MLS group with the caller as sole member.
///
/// * `identity_b64` — base64-encoded identity bytes.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 1,
///   "group_id": "<base64>",
///   "epoch": 0
/// }
/// ```
#[wasm_bindgen]
pub fn mls_create_group(identity_b64: &str) -> Result<JsValue, JsError> {
    let identity = BASE64.decode(identity_b64)
        .map_err(|e| JsError::new(&format!("Invalid identity base64: {}", e)))?;

    let result = mls::create_group(&identity)
        .map_err(|e| JsError::new(&format!("MLS create group failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "group_id": BASE64.encode(&result.group_id),
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 12. MLS — Add Member
// ---------------------------------------------------------------------------

/// Add a member to an MLS group.
///
/// * `group_handle` — handle from `mls_create_group` or a previous MLS operation.
/// * `key_package_b64` — base64-encoded TLS-serialized key package of the new member.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 2,
///   "commit": "<base64>",
///   "welcome": "<base64>",
///   "epoch": 1
/// }
/// ```
#[wasm_bindgen]
pub fn mls_add_member(
    group_handle: u32,
    key_package_b64: &str,
) -> Result<JsValue, JsError> {
    let key_package = BASE64.decode(key_package_b64)
        .map_err(|e| JsError::new(&format!("Invalid key_package base64: {}", e)))?;

    let state = MLS_STATES.with(|store| {
        let map = store.borrow();
        map.get(&group_handle)
            .cloned()
            .ok_or_else(|| JsError::new(&format!(
                "MLS group handle {} not found", group_handle
            )))
    })?;

    let result = mls::add_member(&state, &key_package)
        .map_err(|e| JsError::new(&format!("MLS add member failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "commit": BASE64.encode(&result.commit),
        "welcome": BASE64.encode(&result.welcome),
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 13. MLS — Remove Member
// ---------------------------------------------------------------------------

/// Remove a member from an MLS group by leaf index.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 3,
///   "commit": "<base64>",
///   "epoch": 2
/// }
/// ```
#[wasm_bindgen]
pub fn mls_remove_member(
    group_handle: u32,
    leaf_index: u32,
) -> Result<JsValue, JsError> {
    let state = MLS_STATES.with(|store| {
        let map = store.borrow();
        map.get(&group_handle)
            .cloned()
            .ok_or_else(|| JsError::new(&format!(
                "MLS group handle {} not found", group_handle
            )))
    })?;

    let result = mls::remove_member(&state, leaf_index)
        .map_err(|e| JsError::new(&format!("MLS remove member failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "commit": BASE64.encode(&result.commit),
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 14. MLS — Encrypt Message
// ---------------------------------------------------------------------------

/// Encrypt a plaintext message for the MLS group.
///
/// * `group_handle` — handle to the group state.
/// * `plaintext_b64` — base64-encoded plaintext.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 4,
///   "mls_ciphertext": "<base64>",
///   "epoch": 1
/// }
/// ```
#[wasm_bindgen]
pub fn mls_encrypt_message(
    group_handle: u32,
    plaintext_b64: &str,
) -> Result<JsValue, JsError> {
    let plaintext = BASE64.decode(plaintext_b64)
        .map_err(|e| JsError::new(&format!("Invalid plaintext base64: {}", e)))?;

    let state = MLS_STATES.with(|store| {
        let map = store.borrow();
        map.get(&group_handle)
            .cloned()
            .ok_or_else(|| JsError::new(&format!(
                "MLS group handle {} not found", group_handle
            )))
    })?;

    let result = mls::encrypt_message(&state, &plaintext)
        .map_err(|e| JsError::new(&format!("MLS encrypt failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "mls_ciphertext": BASE64.encode(&result.mls_ciphertext),
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 15. MLS — Decrypt Message
// ---------------------------------------------------------------------------

/// Decrypt a received MLS group message.
///
/// * `group_handle` — handle to the group state.
/// * `mls_message_b64` — base64-encoded TLS-serialized MLS message.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 5,
///   "plaintext": "<base64>"
/// }
/// ```
#[wasm_bindgen]
pub fn mls_decrypt_message(
    group_handle: u32,
    mls_message_b64: &str,
) -> Result<JsValue, JsError> {
    let mls_message = BASE64.decode(mls_message_b64)
        .map_err(|e| JsError::new(&format!("Invalid mls_message base64: {}", e)))?;

    let state = MLS_STATES.with(|store| {
        let map = store.borrow();
        map.get(&group_handle)
            .cloned()
            .ok_or_else(|| JsError::new(&format!(
                "MLS group handle {} not found", group_handle
            )))
    })?;

    let result = mls::decrypt_message(&state, &mls_message)
        .map_err(|e| JsError::new(&format!("MLS decrypt failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "plaintext": BASE64.encode(&result.plaintext),
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 16. MLS — Process Welcome
// ---------------------------------------------------------------------------

/// Process a welcome message to join an MLS group.
///
/// * `welcome_b64` — base64-encoded TLS-serialized welcome message.
/// * `secret_bundle_b64` — base64-encoded secret bundle from `mls_generate_key_package`.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 6,
///   "group_id": "<base64>",
///   "epoch": 1
/// }
/// ```
#[wasm_bindgen]
pub fn mls_process_welcome(
    welcome_b64: &str,
    secret_bundle_b64: &str,
) -> Result<JsValue, JsError> {
    let welcome = BASE64.decode(welcome_b64)
        .map_err(|e| JsError::new(&format!("Invalid welcome base64: {}", e)))?;
    let secret_bundle = BASE64.decode(secret_bundle_b64)
        .map_err(|e| JsError::new(&format!("Invalid secret_bundle base64: {}", e)))?;

    let result = mls::process_welcome(&welcome, &secret_bundle)
        .map_err(|e| JsError::new(&format!("MLS process welcome failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "group_id": BASE64.encode(&result.group_id),
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 17. MLS — Process Commit
// ---------------------------------------------------------------------------

/// Process a received commit to update MLS group state.
///
/// * `group_handle` — handle to the group state.
/// * `commit_b64` — base64-encoded TLS-serialized commit message.
///
/// Returns JSON:
/// ```json
/// {
///   "handle": 7,
///   "epoch": 2
/// }
/// ```
#[wasm_bindgen]
pub fn mls_process_commit(
    group_handle: u32,
    commit_b64: &str,
) -> Result<JsValue, JsError> {
    let commit = BASE64.decode(commit_b64)
        .map_err(|e| JsError::new(&format!("Invalid commit base64: {}", e)))?;

    let state = MLS_STATES.with(|store| {
        let map = store.borrow();
        map.get(&group_handle)
            .cloned()
            .ok_or_else(|| JsError::new(&format!(
                "MLS group handle {} not found", group_handle
            )))
    })?;

    let result = mls::process_commit(&state, &commit)
        .map_err(|e| JsError::new(&format!("MLS process commit failed: {}", e)))?;

    let handle = next_id();
    MLS_STATES.with(|store| {
        store.borrow_mut().insert(handle, result.group_state);
    });

    let json = serde_json::json!({
        "handle": handle,
        "epoch": result.epoch,
    });

    serde_json::to_string(&json)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

// ---------------------------------------------------------------------------
// 18. MLS — Destroy State
// ---------------------------------------------------------------------------

/// Remove an MLS group state from the thread-local store.
/// Returns `true` if a state with that handle existed and was removed.
#[wasm_bindgen]
pub fn mls_destroy_state(group_handle: u32) -> bool {
    MLS_STATES.with(|store| {
        store.borrow_mut().remove(&group_handle).is_some()
    })
}
