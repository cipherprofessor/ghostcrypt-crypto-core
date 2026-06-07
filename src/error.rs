use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Ratchet error: {0}")]
    Ratchet(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("MLS error: {0}")]
    Mls(String),

    #[error("MLS group not found: {0}")]
    MlsGroupNotFound(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
