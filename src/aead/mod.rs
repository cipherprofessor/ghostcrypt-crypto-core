use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<Encrypted> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Encryption(format!("Invalid key: {}", e)))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::Encryption(format!("Encryption failed: {}", e)))?;

    Ok(Encrypted {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(key: &[u8; 32], encrypted: &Encrypted, associated_data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Decryption(format!("Invalid key: {}", e)))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    let payload = aes_gcm::aead::Payload {
        msg: &encrypted.ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::Decryption(format!("Decryption failed: {}", e)))
}
