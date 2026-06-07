use x25519_dalek::PublicKey;
use serde::{Serialize, Deserialize};

/// Header sent with each encrypted message.
/// Contains the sender's current DH ratchet public key and counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key (32 bytes)
    pub dh_public_key: Vec<u8>,
    /// Message number in the current sending chain
    pub message_number: u32,
    /// Length of the previous sending chain
    pub previous_chain_length: u32,
}

impl MessageHeader {
    pub fn new(dh_key: &PublicKey, msg_num: u32, prev_chain_len: u32) -> Self {
        Self {
            dh_public_key: dh_key.as_bytes().to_vec(),
            message_number: msg_num,
            previous_chain_length: prev_chain_len,
        }
    }

    /// Reconstruct the X25519 public key from the serialized bytes.
    pub fn to_public_key(&self) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.dh_public_key);
        PublicKey::from(bytes)
    }

    /// Serialize header for use as associated data in AEAD.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}
