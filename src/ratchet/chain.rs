use crate::kdf;
use crate::error::Result;

/// A symmetric ratchet chain that derives message keys.
pub struct ChainKey {
    key: Vec<u8>,
    index: u32,
}

impl ChainKey {
    pub fn new(key: Vec<u8>, index: u32) -> Self {
        Self { key, index }
    }

    /// Advance the chain: derive next chain key + message key.
    /// Returns the message key. The internal chain key and index are updated.
    pub fn advance(&mut self) -> Result<Vec<u8>> {
        let (new_chain_key, message_key) = kdf::derive_chain_and_message_key(&self.key)?;
        self.key = new_chain_key;
        self.index += 1;
        Ok(message_key)
    }

    /// Current message index (number of times advance has been called).
    pub fn index(&self) -> u32 {
        self.index
    }
}
