pub mod bundle;

pub use bundle::{PreKeyBundle, X3DHResult};

use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::error::{CryptoError, Result};
use crate::identity::{IdentityKeyPair, SignedPreKey, OneTimePreKey};
use crate::kdf;

const X3DH_SALT: &[u8] = b"GhostCrypt_X3DH";
const X3DH_INFO: &[u8] = b"X3DH_shared_secret";
const SHARED_SECRET_LEN: usize = 32;

/// Alice initiates an X3DH key exchange with Bob using his published pre-key bundle.
///
/// Performs 3 or 4 Diffie-Hellman computations depending on whether Bob's bundle
/// includes a one-time pre-key, then derives a shared secret via HKDF-SHA256.
pub fn initiate(alice_identity: &IdentityKeyPair, bob_bundle: &PreKeyBundle) -> Result<X3DHResult> {
    // Authenticate Bob's signed pre-key before using it. This is the X3DH
    // authentication step: the signed pre-key carries a signature under Bob's
    // long-term identity key, and verifying it here prevents a malicious
    // key-distribution server from substituting a pre-key it controls.
    if !IdentityKeyPair::verify(
        &bob_bundle.identity_verifying_key,
        bob_bundle.signed_pre_key.as_bytes(),
        &bob_bundle.signature,
    ) {
        return Err(CryptoError::InvalidSignature(
            "signed pre-key signature failed verification".into(),
        ));
    }

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // DH1 = DH(alice_identity, bob_signed_pre_key)
    let dh1 = alice_identity.dh(&bob_bundle.signed_pre_key);

    // DH2 = DH(alice_ephemeral, bob_identity_key)
    let dh2 = ephemeral_secret.diffie_hellman(&bob_bundle.identity_key);

    // DH3 = DH(alice_ephemeral, bob_signed_pre_key)
    let dh3 = ephemeral_secret.diffie_hellman(&bob_bundle.signed_pre_key);

    // Concatenate DH results
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    // DH4 = DH(alice_ephemeral, bob_one_time_pre_key) if available
    if let Some(ref opk) = bob_bundle.one_time_pre_key {
        let dh4 = ephemeral_secret.diffie_hellman(opk);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret via HKDF-SHA256
    let shared_secret = kdf::derive(&dh_concat, X3DH_SALT, X3DH_INFO, SHARED_SECRET_LEN)?;

    Ok(X3DHResult {
        shared_secret,
        ephemeral_key: ephemeral_public,
    })
}

/// Bob responds to Alice's X3DH initiation, computing the same shared secret.
///
/// Mirrors Alice's DH computations using Bob's private keys and Alice's public keys.
pub fn respond(
    bob_identity: &IdentityKeyPair,
    bob_spk: &SignedPreKey,
    bob_opk: Option<&OneTimePreKey>,
    alice_identity_pub: &PublicKey,
    alice_ephemeral_pub: &PublicKey,
) -> Result<X3DHResult> {
    // DH1 = DH(bob_spk, alice_identity_key) — mirrors Alice's DH1
    let dh1 = bob_spk.dh(alice_identity_pub);

    // DH2 = DH(bob_identity, alice_ephemeral_key) — mirrors Alice's DH2
    let dh2 = bob_identity.dh(alice_ephemeral_pub);

    // DH3 = DH(bob_spk, alice_ephemeral_key) — mirrors Alice's DH3
    let dh3 = bob_spk.dh(alice_ephemeral_pub);

    // Concatenate DH results
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    // DH4 = DH(bob_opk, alice_ephemeral_key) — mirrors Alice's DH4
    if let Some(opk) = bob_opk {
        let dh4 = opk.dh(alice_ephemeral_pub);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret via HKDF-SHA256 (same salt/info as Alice)
    let shared_secret = kdf::derive(&dh_concat, X3DH_SALT, X3DH_INFO, SHARED_SECRET_LEN)?;

    Ok(X3DHResult {
        shared_secret,
        ephemeral_key: *alice_ephemeral_pub,
    })
}
