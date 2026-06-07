use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CryptoError, Result};

/// Derive key material using HKDF-SHA256.
pub fn derive(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KeyGeneration(format!("HKDF expand failed: {}", e)))?;
    Ok(output)
}

/// Derive a new chain key and message key from a chain key.
/// Used in the Double Ratchet symmetric ratchet step.
pub fn derive_chain_and_message_key(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let new_chain_key = hmac_sha256(chain_key, &[0x01])?;
    let message_key = hmac_sha256(chain_key, &[0x02])?;
    Ok((new_chain_key, message_key))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| CryptoError::KeyGeneration(format!("HMAC key error: {}", e)))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
