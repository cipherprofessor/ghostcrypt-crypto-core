use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::ratchet::chain::ChainKey;
use crate::ratchet::dh_ratchet;
use crate::ratchet::header::MessageHeader;

/// Maximum number of message keys to skip and store (prevents DoS).
const MAX_SKIP: u32 = 100;

/// A Double Ratchet session between two parties.
///
/// Manages the root key, sending/receiving symmetric chains, DH ratchet keypairs,
/// and skipped message keys for handling out-of-order delivery.
pub struct Session {
    /// Current root key
    root_key: Vec<u8>,
    /// Our current DH ratchet secret key
    dh_secret: StaticSecret,
    /// Our current DH ratchet public key
    dh_public: PublicKey,
    /// Remote party's current DH public key
    remote_dh_public: Option<PublicKey>,
    /// Sending chain (symmetric ratchet for outgoing messages)
    sending_chain: Option<ChainKey>,
    /// Receiving chain (symmetric ratchet for incoming messages)
    receiving_chain: Option<ChainKey>,
    /// Number of messages sent in previous sending chain
    previous_sending_chain_length: u32,
    /// Skipped message keys: (dh_public_bytes, message_number) -> message_key
    skipped_keys: HashMap<(Vec<u8>, u32), Vec<u8>>,
}

impl Session {
    /// Initialize session as Alice (the initiator).
    ///
    /// Alice knows Bob's signed pre-key public key and the shared secret from X3DH.
    /// She performs the first DH ratchet step to establish a sending chain.
    pub fn init_alice(shared_secret: &[u8], bob_spk_public: PublicKey) -> Self {
        let (dh_secret, dh_public) = dh_ratchet::generate_dh_keypair();

        // Perform initial DH ratchet step with Bob's SPK
        let dh_output = dh_ratchet::dh(&dh_secret, &bob_spk_public);
        let (root_key, chain_key) = dh_ratchet::dh_ratchet_step(shared_secret, &dh_output)
            .expect("Initial DH ratchet step failed");

        Session {
            root_key,
            dh_secret,
            dh_public,
            remote_dh_public: Some(bob_spk_public),
            sending_chain: Some(ChainKey::new(chain_key, 0)),
            receiving_chain: None,
            previous_sending_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize session as Bob (the responder).
    ///
    /// Bob uses his signed pre-key as his initial DH ratchet keypair and the
    /// shared secret from X3DH as the root key. He waits for Alice's first
    /// message to trigger the DH ratchet.
    pub fn init_bob(shared_secret: &[u8], our_spk: &crate::identity::SignedPreKey) -> Self {
        // Reconstruct a StaticSecret from the SPK's raw bytes
        let secret_bytes = our_spk.secret_bytes();
        let dh_secret = StaticSecret::from(secret_bytes);
        let dh_public = our_spk.public_key().clone();

        Session {
            root_key: shared_secret.to_vec(),
            dh_secret,
            dh_public,
            remote_dh_public: None,
            sending_chain: None,
            receiving_chain: None,
            previous_sending_chain_length: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the message header and the AEAD-encrypted ciphertext.
    /// The header must be sent alongside the ciphertext so the receiver can
    /// perform the corresponding DH ratchet step.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, aead::Encrypted)> {
        let sending_chain = self.sending_chain.as_mut()
            .ok_or_else(|| CryptoError::Ratchet("No sending chain established".into()))?;

        let message_key = sending_chain.advance()?;
        let msg_num = sending_chain.index() - 1;

        let header = MessageHeader::new(
            &self.dh_public,
            msg_num,
            self.previous_sending_chain_length,
        );

        let key: [u8; 32] = message_key.try_into()
            .map_err(|_| CryptoError::Ratchet("Invalid message key length".into()))?;

        let encrypted = aead::encrypt(&key, plaintext, &header.to_bytes())?;

        Ok((header, encrypted))
    }

    /// Decrypt a received message.
    ///
    /// Handles DH ratchet steps when the sender's DH key changes, and
    /// supports out-of-order message delivery via skipped message keys.
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        encrypted: &aead::Encrypted,
    ) -> Result<Vec<u8>> {
        // 1. Try skipped message keys first (out-of-order delivery)
        let header_dh_bytes = header.dh_public_key.clone();
        if let Some(mk) = self.skipped_keys.remove(&(header_dh_bytes.clone(), header.message_number)) {
            let key: [u8; 32] = mk.try_into()
                .map_err(|_| CryptoError::Ratchet("Invalid skipped key length".into()))?;
            return aead::decrypt(&key, encrypted, &header.to_bytes());
        }

        let header_dh_public = header.to_public_key();

        // 2. Check if we need to perform a DH ratchet step
        let need_ratchet = match &self.remote_dh_public {
            None => true,
            Some(remote) => remote.as_bytes() != header_dh_public.as_bytes(),
        };

        if need_ratchet {
            // Skip remaining messages in the current receiving chain
            self.skip_current_receiving_chain(header.previous_chain_length)?;

            // Perform DH ratchet: derive new receiving chain
            let dh_output = dh_ratchet::dh(&self.dh_secret, &header_dh_public);
            let (root_key, recv_chain_key) =
                dh_ratchet::dh_ratchet_step(&self.root_key, &dh_output)?;
            self.root_key = root_key;
            self.receiving_chain = Some(ChainKey::new(recv_chain_key, 0));
            self.remote_dh_public = Some(header_dh_public);

            // Save the previous sending chain length
            self.previous_sending_chain_length = self.sending_chain
                .as_ref()
                .map(|c| c.index())
                .unwrap_or(0);

            // Generate new DH keypair and derive new sending chain
            let (new_secret, new_public) = dh_ratchet::generate_dh_keypair();
            let dh_output = dh_ratchet::dh(
                &new_secret,
                self.remote_dh_public.as_ref().unwrap(),
            );
            let (root_key, send_chain_key) =
                dh_ratchet::dh_ratchet_step(&self.root_key, &dh_output)?;
            self.root_key = root_key;
            self.dh_secret = new_secret;
            self.dh_public = new_public;
            self.sending_chain = Some(ChainKey::new(send_chain_key, 0));
        }

        // 3. Skip ahead in receiving chain if message number is ahead
        let recv_chain = self.receiving_chain.as_mut()
            .ok_or_else(|| CryptoError::Ratchet("No receiving chain established".into()))?;

        while recv_chain.index() < header.message_number {
            let skipped_mk = recv_chain.advance()?;
            self.skipped_keys.insert(
                (header.dh_public_key.clone(), recv_chain.index() - 1),
                skipped_mk,
            );
            if self.skipped_keys.len() > MAX_SKIP as usize {
                return Err(CryptoError::Ratchet("Too many skipped messages".into()));
            }
        }

        // 4. Derive the message key for this message
        let message_key = recv_chain.advance()?;
        let key: [u8; 32] = message_key.try_into()
            .map_err(|_| CryptoError::Ratchet("Invalid message key length".into()))?;

        aead::decrypt(&key, encrypted, &header.to_bytes())
    }

    /// Skip remaining messages in the current receiving chain up to `until`,
    /// storing their message keys for later out-of-order delivery.
    fn skip_current_receiving_chain(&mut self, until: u32) -> Result<()> {
        if let Some(ref mut recv_chain) = self.receiving_chain {
            if let Some(ref remote) = self.remote_dh_public {
                let remote_bytes = remote.as_bytes().to_vec();
                while recv_chain.index() < until {
                    let mk = recv_chain.advance()?;
                    self.skipped_keys.insert(
                        (remote_bytes.clone(), recv_chain.index() - 1),
                        mk,
                    );
                    if self.skipped_keys.len() > MAX_SKIP as usize {
                        return Err(CryptoError::Ratchet("Too many skipped messages".into()));
                    }
                }
            }
        }
        Ok(())
    }
}
