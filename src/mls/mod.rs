//! MLS Group Encryption Core Module
//!
//! Stateless wrapper around openmls for MLS (Messaging Layer Security) group
//! operations. Every function takes serialized bytes in and returns serialized
//! bytes out -- clients manage state externally.
//!
//! All MLS group state is bundled into a single serialized blob (`GroupBundle`)
//! that contains the openmls provider key store, the signing key, and the
//! credential alongside the group itself.

use std::collections::HashMap;

use base64::prelude::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// X25519 + AES-128-GCM + SHA-256 + Ed25519 -- matches our existing crypto stack.
const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// ---------------------------------------------------------------------------
// Result types returned to callers
// ---------------------------------------------------------------------------

/// Result of generating an MLS key package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsKeyPackageResult {
    /// TLS-serialized `KeyPackage` bytes -- share with the server/other members.
    pub key_package: Vec<u8>,
    /// Serialized secret material (provider key store + signing key + credential).
    /// The client MUST store this privately; it is required to process a Welcome.
    pub secret_bundle: Vec<u8>,
}

/// Result of creating a new MLS group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupResult {
    /// Opaque group state blob (a serialized `GroupBundle`).
    pub group_state: Vec<u8>,
    /// The group identifier.
    pub group_id: Vec<u8>,
    /// Current epoch number.
    pub epoch: u64,
}

/// Result of adding a member to a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberResult {
    /// TLS-serialized commit message -- broadcast to existing members.
    pub commit: Vec<u8>,
    /// TLS-serialized welcome message -- send privately to the new member.
    pub welcome: Vec<u8>,
    /// Updated group state blob.
    pub group_state: Vec<u8>,
    /// New epoch after the add.
    pub epoch: u64,
}

/// Result of removing a member from a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMemberResult {
    /// TLS-serialized commit message -- broadcast to remaining members.
    pub commit: Vec<u8>,
    /// Updated group state blob.
    pub group_state: Vec<u8>,
    /// New epoch after the removal.
    pub epoch: u64,
}

/// Result of encrypting a message for the group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResult {
    /// TLS-serialized MLS ciphertext.
    pub mls_ciphertext: Vec<u8>,
    /// Updated group state blob (encryption advances the secret tree).
    pub group_state: Vec<u8>,
    /// Current epoch.
    pub epoch: u64,
}

/// Result of decrypting a received group message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResult {
    /// The decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
    /// Updated group state blob.
    pub group_state: Vec<u8>,
}

/// Result of processing a received commit (membership change).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCommitResult {
    /// Updated group state blob.
    pub group_state: Vec<u8>,
    /// New epoch after the commit.
    pub epoch: u64,
}

/// Result of processing a welcome message (joining a group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessWelcomeResult {
    /// Opaque group state blob.
    pub group_state: Vec<u8>,
    /// The group identifier.
    pub group_id: Vec<u8>,
    /// Current epoch.
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Internal: serializable bundle that captures full MLS context
// ---------------------------------------------------------------------------

/// Everything needed to reconstruct a fully-operational `MlsGroup` from
/// serialized bytes.  Stored by the client alongside each group.
#[derive(Serialize, Deserialize)]
struct GroupBundle {
    /// Base64-encoded key-value pairs from the provider's `MemoryStorage`.
    store: HashMap<String, String>,
    /// JSON-serialized `SignatureKeyPair`.
    signer: Vec<u8>,
    /// JSON-serialized `CredentialWithKey`.
    credential_with_key: Vec<u8>,
    /// JSON-serialized `GroupId`.
    group_id: Vec<u8>,
}

/// Secret material produced alongside a `KeyPackage` so the client can later
/// process a `Welcome` for that key package.
#[derive(Serialize, Deserialize)]
struct KeyPackageSecretBundle {
    /// Base64-encoded key-value pairs from the provider's `MemoryStorage`.
    store: HashMap<String, String>,
    /// JSON-serialized `SignatureKeyPair`.
    signer: Vec<u8>,
    /// JSON-serialized `CredentialWithKey`.
    credential_with_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Snapshot the provider's in-memory key store into a portable HashMap.
fn snapshot_store(provider: &OpenMlsRustCrypto) -> HashMap<String, String> {
    let storage = provider.storage();
    let values = storage.values.read().expect("storage lock poisoned");
    values
        .iter()
        .map(|(k, v)| (BASE64_STANDARD.encode(k), BASE64_STANDARD.encode(v)))
        .collect()
}

/// Restore a provider's in-memory key store from a portable HashMap.
fn restore_store(provider: &OpenMlsRustCrypto, store: &HashMap<String, String>) {
    let storage = provider.storage();
    let mut values = storage.values.write().expect("storage lock poisoned");
    for (k, v) in store {
        values.insert(
            BASE64_STANDARD.decode(k).expect("invalid base64 key"),
            BASE64_STANDARD.decode(v).expect("invalid base64 value"),
        );
    }
}

/// Create a fresh `OpenMlsRustCrypto` provider pre-loaded with key store data.
fn provider_from_store(store: &HashMap<String, String>) -> OpenMlsRustCrypto {
    let provider = OpenMlsRustCrypto::default();
    restore_store(&provider, store);
    provider
}

/// Serialize a `GroupBundle` into an opaque blob.
fn serialize_bundle(bundle: &GroupBundle) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(bundle).map_err(|e| CryptoError::Serialization(e.to_string()))
}

/// Deserialize a `GroupBundle` from an opaque blob.
fn deserialize_bundle(bytes: &[u8]) -> Result<GroupBundle, CryptoError> {
    serde_json::from_slice(bytes).map_err(|e| CryptoError::Serialization(e.to_string()))
}

/// Load an `MlsGroup` from a `GroupBundle`, returning the group alongside its
/// provider, signer and credential.
fn load_group(
    bundle: &GroupBundle,
) -> Result<(MlsGroup, OpenMlsRustCrypto, SignatureKeyPair, CredentialWithKey), CryptoError> {
    let provider = provider_from_store(&bundle.store);

    let signer: SignatureKeyPair = serde_json::from_slice(&bundle.signer)
        .map_err(|e| CryptoError::Serialization(format!("signer: {e}")))?;

    let credential_with_key: CredentialWithKey =
        serde_json::from_slice(&bundle.credential_with_key)
            .map_err(|e| CryptoError::Serialization(format!("credential: {e}")))?;

    let group_id: GroupId = serde_json::from_slice(&bundle.group_id)
        .map_err(|e| CryptoError::Serialization(format!("group_id: {e}")))?;

    let group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|e| CryptoError::Mls(format!("storage error loading group: {e}")))?
        .ok_or_else(|| {
            CryptoError::MlsGroupNotFound(format!(
                "no group found for id {:?}",
                group_id.as_slice()
            ))
        })?;

    Ok((group, provider, signer, credential_with_key))
}

/// Save an `MlsGroup` back into a serialized `GroupBundle`.
fn save_group(
    group: &MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    credential_with_key: &CredentialWithKey,
) -> Result<Vec<u8>, CryptoError> {
    let bundle = GroupBundle {
        store: snapshot_store(provider),
        signer: serde_json::to_vec(signer)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?,
        credential_with_key: serde_json::to_vec(credential_with_key)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?,
        group_id: serde_json::to_vec(group.group_id())
            .map_err(|e| CryptoError::Serialization(e.to_string()))?,
    };
    serialize_bundle(&bundle)
}

/// TLS-serialize an `MlsMessageOut`.
fn serialize_mls_message(msg: &MlsMessageOut) -> Result<Vec<u8>, CryptoError> {
    msg.tls_serialize_detached()
        .map_err(|e| CryptoError::Serialization(format!("tls_serialize: {e}")))
}

/// TLS-deserialize bytes into an `MlsMessageIn`.
fn deserialize_mls_message(bytes: &[u8]) -> Result<MlsMessageIn, CryptoError> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| CryptoError::Serialization(format!("tls_deserialize MlsMessageIn: {e}")))
}

/// Build the default `MlsGroupCreateConfig` used throughout GhostCrypt.
fn default_group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Build the default `MlsGroupJoinConfig` used when processing a welcome.
fn default_group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

// ---------------------------------------------------------------------------
// Public API -- stateless MLS operations
// ---------------------------------------------------------------------------

/// Generate an MLS key package for the given identity.
///
/// Returns an `MlsKeyPackageResult` containing:
/// - `key_package`: TLS-serialized `KeyPackage` bytes to publish/share.
/// - `secret_bundle`: opaque blob the client must store secretly -- it is
///   needed later to process a `Welcome` for this key package.
pub fn generate_key_package(identity: &[u8]) -> Result<MlsKeyPackageResult, CryptoError> {
    let provider = OpenMlsRustCrypto::default();

    // Create credential from the raw identity bytes.
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| CryptoError::KeyGeneration(format!("signature keypair: {e}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| CryptoError::KeyGeneration(format!("store signer: {e}")))?;

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    // Build the key package (stores private material in the provider).
    let key_package_bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider, &signer, credential_with_key.clone())
        .map_err(|e| CryptoError::KeyGeneration(format!("key package build: {e}")))?;

    let kp_bytes = key_package_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| CryptoError::Serialization(format!("key package tls: {e}")))?;

    // Bundle secret material so the client can process a Welcome later.
    let secret_bundle = KeyPackageSecretBundle {
        store: snapshot_store(&provider),
        signer: serde_json::to_vec(&signer)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?,
        credential_with_key: serde_json::to_vec(&credential_with_key)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?,
    };
    let secret_bytes = serde_json::to_vec(&secret_bundle)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    Ok(MlsKeyPackageResult {
        key_package: kp_bytes,
        secret_bundle: secret_bytes,
    })
}

/// Create a new MLS group with the caller as the sole member.
///
/// `identity` is the raw identity bytes for the creator's credential.
///
/// Returns a `CreateGroupResult` with:
/// - `group_state`: opaque blob the client stores for subsequent operations.
/// - `group_id`: the auto-generated group identifier.
/// - `epoch`: initial epoch (0).
pub fn create_group(identity: &[u8]) -> Result<CreateGroupResult, CryptoError> {
    let provider = OpenMlsRustCrypto::default();

    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| CryptoError::KeyGeneration(format!("signature keypair: {e}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| CryptoError::KeyGeneration(format!("store signer: {e}")))?;

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    let config = default_group_create_config();

    let group = MlsGroup::new(&provider, &signer, &config, credential_with_key.clone())
        .map_err(|e| CryptoError::Mls(format!("create group: {e}")))?;

    let group_id_bytes = group.group_id().as_slice().to_vec();
    let epoch = group.epoch().as_u64();

    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(CreateGroupResult {
        group_state: state,
        group_id: group_id_bytes,
        epoch,
    })
}

/// Add a member to the group.
///
/// - `group_state`: opaque blob from a previous operation.
/// - `key_package_bytes`: TLS-serialized `KeyPackage` of the member to add.
///
/// Returns an `AddMemberResult` with:
/// - `commit`: broadcast to existing members.
/// - `welcome`: send to the new member (they process it with `process_welcome`).
/// - `group_state`: updated state.
/// - `epoch`: new epoch.
pub fn add_member(
    group_state: &[u8],
    key_package_bytes: &[u8],
) -> Result<AddMemberResult, CryptoError> {
    let bundle = deserialize_bundle(group_state)?;
    let (mut group, provider, signer, credential_with_key) = load_group(&bundle)?;

    // Deserialize and validate the incoming key package.
    let key_package_in = KeyPackageIn::tls_deserialize_exact(key_package_bytes)
        .map_err(|e| CryptoError::Serialization(format!("key package tls deser: {e}")))?;

    let key_package: KeyPackage = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| CryptoError::Mls(format!("key package validation: {e}")))?;

    let (commit_msg, welcome_msg, _group_info) = group
        .add_members(&provider, &signer, &[key_package])
        .map_err(|e| CryptoError::Mls(format!("add_members: {e}")))?;

    group
        .merge_pending_commit(&provider)
        .map_err(|e| CryptoError::Mls(format!("merge_pending_commit: {e}")))?;

    let epoch = group.epoch().as_u64();
    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(AddMemberResult {
        commit: serialize_mls_message(&commit_msg)?,
        welcome: serialize_mls_message(&welcome_msg)?,
        group_state: state,
        epoch,
    })
}

/// Remove a member from the group by leaf index.
///
/// - `group_state`: opaque blob.
/// - `leaf_index`: the `LeafNodeIndex` of the member to remove.
///
/// Returns a `RemoveMemberResult`.
pub fn remove_member(
    group_state: &[u8],
    leaf_index: u32,
) -> Result<RemoveMemberResult, CryptoError> {
    let bundle = deserialize_bundle(group_state)?;
    let (mut group, provider, signer, credential_with_key) = load_group(&bundle)?;

    let (commit_msg, _welcome, _group_info) = group
        .remove_members(&provider, &signer, &[LeafNodeIndex::new(leaf_index)])
        .map_err(|e| CryptoError::Mls(format!("remove_members: {e}")))?;

    group
        .merge_pending_commit(&provider)
        .map_err(|e| CryptoError::Mls(format!("merge_pending_commit: {e}")))?;

    let epoch = group.epoch().as_u64();
    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(RemoveMemberResult {
        commit: serialize_mls_message(&commit_msg)?,
        group_state: state,
        epoch,
    })
}

/// Encrypt a plaintext message for the group.
///
/// - `group_state`: opaque blob.
/// - `plaintext`: raw plaintext bytes to encrypt.
///
/// Returns an `EncryptResult` with the MLS ciphertext and updated state.
pub fn encrypt_message(
    group_state: &[u8],
    plaintext: &[u8],
) -> Result<EncryptResult, CryptoError> {
    let bundle = deserialize_bundle(group_state)?;
    let (mut group, provider, signer, credential_with_key) = load_group(&bundle)?;

    let ciphertext_msg = group
        .create_message(&provider, &signer, plaintext)
        .map_err(|e| CryptoError::Encryption(format!("create_message: {e}")))?;

    let epoch = group.epoch().as_u64();
    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(EncryptResult {
        mls_ciphertext: serialize_mls_message(&ciphertext_msg)?,
        group_state: state,
        epoch,
    })
}

/// Decrypt a received MLS group message (application message).
///
/// - `group_state`: opaque blob.
/// - `mls_message_bytes`: TLS-serialized MLS message received from the group.
///
/// Returns a `DecryptResult` with the plaintext and updated state.
pub fn decrypt_message(
    group_state: &[u8],
    mls_message_bytes: &[u8],
) -> Result<DecryptResult, CryptoError> {
    let bundle = deserialize_bundle(group_state)?;
    let (mut group, provider, signer, credential_with_key) = load_group(&bundle)?;

    let mls_message_in = deserialize_mls_message(mls_message_bytes)?;
    let protocol_message = mls_message_in
        .try_into_protocol_message()
        .map_err(|e| CryptoError::Decryption(format!("not a protocol message: {e}")))?;

    let processed = group
        .process_message(&provider, protocol_message)
        .map_err(|e| CryptoError::Decryption(format!("process_message: {e}")))?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let state = save_group(&group, &provider, &signer, &credential_with_key)?;
            Ok(DecryptResult {
                plaintext: app_msg.into_bytes(),
                group_state: state,
            })
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Caller sent a commit through decrypt_message -- merge it and
            // return empty plaintext to signal "this was a commit, not app data".
            group
                .merge_staged_commit(&provider, *staged_commit)
                .map_err(|e| CryptoError::Mls(format!("merge_staged_commit: {e}")))?;
            let state = save_group(&group, &provider, &signer, &credential_with_key)?;
            Ok(DecryptResult {
                plaintext: Vec::new(),
                group_state: state,
            })
        }
        ProcessedMessageContent::ProposalMessage(proposal) => {
            group
                .store_pending_proposal(provider.storage(), *proposal)
                .map_err(|e| CryptoError::Mls(format!("store_pending_proposal: {e}")))?;
            let state = save_group(&group, &provider, &signer, &credential_with_key)?;
            Ok(DecryptResult {
                plaintext: Vec::new(),
                group_state: state,
            })
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
            group
                .store_pending_proposal(provider.storage(), *proposal)
                .map_err(|e| CryptoError::Mls(format!("store_pending_proposal: {e}")))?;
            let state = save_group(&group, &provider, &signer, &credential_with_key)?;
            Ok(DecryptResult {
                plaintext: Vec::new(),
                group_state: state,
            })
        }
    }
}

/// Process a received commit message (membership change from another member).
///
/// - `group_state`: opaque blob.
/// - `commit_bytes`: TLS-serialized commit `MlsMessageOut` from another member.
///
/// Returns a `ProcessCommitResult` with updated state and new epoch.
pub fn process_commit(
    group_state: &[u8],
    commit_bytes: &[u8],
) -> Result<ProcessCommitResult, CryptoError> {
    let bundle = deserialize_bundle(group_state)?;
    let (mut group, provider, signer, credential_with_key) = load_group(&bundle)?;

    let mls_message_in = deserialize_mls_message(commit_bytes)?;
    let protocol_message = mls_message_in
        .try_into_protocol_message()
        .map_err(|e| CryptoError::Mls(format!("not a protocol message: {e}")))?;

    let processed = group
        .process_message(&provider, protocol_message)
        .map_err(|e| CryptoError::Mls(format!("process_message: {e}")))?;

    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider, *staged_commit)
                .map_err(|e| CryptoError::Mls(format!("merge_staged_commit: {e}")))?;
        }
        other => {
            return Err(CryptoError::Mls(format!(
                "expected a commit message, got: {other:?}"
            )));
        }
    }

    let epoch = group.epoch().as_u64();
    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(ProcessCommitResult {
        group_state: state,
        epoch,
    })
}

/// Process a welcome message to join an existing group.
///
/// - `welcome_bytes`: TLS-serialized welcome `MlsMessageOut`.
/// - `secret_bundle_bytes`: the `secret_bundle` from `generate_key_package`.
///
/// Returns a `ProcessWelcomeResult` with group state, id and epoch.
pub fn process_welcome(
    welcome_bytes: &[u8],
    secret_bundle_bytes: &[u8],
) -> Result<ProcessWelcomeResult, CryptoError> {
    // Restore the secret material from the key package generation.
    let secret_bundle: KeyPackageSecretBundle =
        serde_json::from_slice(secret_bundle_bytes)
            .map_err(|e| CryptoError::Serialization(format!("secret bundle: {e}")))?;

    let provider = provider_from_store(&secret_bundle.store);

    let signer: SignatureKeyPair = serde_json::from_slice(&secret_bundle.signer)
        .map_err(|e| CryptoError::Serialization(format!("signer: {e}")))?;
    let credential_with_key: CredentialWithKey =
        serde_json::from_slice(&secret_bundle.credential_with_key)
            .map_err(|e| CryptoError::Serialization(format!("credential: {e}")))?;

    // Deserialize the welcome message.
    let mls_message_in = deserialize_mls_message(welcome_bytes)?;
    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => {
            return Err(CryptoError::Mls(
                "expected a Welcome message".to_string(),
            ));
        }
    };

    let join_config = default_group_join_config();

    let staged_welcome =
        StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|e| CryptoError::Mls(format!("staged welcome: {e}")))?;

    let group = staged_welcome
        .into_group(&provider)
        .map_err(|e| CryptoError::Mls(format!("welcome into_group: {e}")))?;

    let group_id_bytes = group.group_id().as_slice().to_vec();
    let epoch = group.epoch().as_u64();

    let state = save_group(&group, &provider, &signer, &credential_with_key)?;

    Ok(ProcessWelcomeResult {
        group_state: state,
        group_id: group_id_bytes,
        epoch,
    })
}
