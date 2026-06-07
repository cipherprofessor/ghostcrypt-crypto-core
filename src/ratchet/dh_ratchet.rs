use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::kdf;
use crate::error::Result;

/// Perform a DH ratchet step.
/// Takes current root key + DH output, returns (new_root_key, new_chain_key).
/// Derives 64 bytes via HKDF: first 32 = new root key, last 32 = new chain key.
pub fn dh_ratchet_step(
    root_key: &[u8],
    dh_output: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let derived = kdf::derive(
        dh_output,
        root_key,
        b"GhostCrypt_Ratchet",
        64,
    )?;

    let new_root_key = derived[..32].to_vec();
    let new_chain_key = derived[32..].to_vec();

    Ok((new_root_key, new_chain_key))
}

/// Generate a new X25519 keypair for the DH ratchet.
pub fn generate_dh_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Perform X25519 Diffie-Hellman with our secret and their public key.
pub fn dh(our_secret: &StaticSecret, their_public: &PublicKey) -> Vec<u8> {
    our_secret.diffie_hellman(their_public).as_bytes().to_vec()
}
