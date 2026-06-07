use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
/// An identity keypair containing X25519 keys for Diffie-Hellman key exchange
/// and an Ed25519 signing key for digital signatures.
pub struct IdentityKeyPair {
    secret_seed: [u8; 32],
    x25519_secret: StaticSecret,
    x25519_public: PublicKey,
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity keypair.
    pub fn generate() -> Self {
        let mut secret_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut secret_seed);
        let x25519_secret = StaticSecret::from(secret_seed);
        let x25519_public = PublicKey::from(&x25519_secret);
        let signing_key = SigningKey::generate(&mut OsRng);

        Self {
            secret_seed,
            x25519_secret,
            x25519_public,
            signing_key,
        }
    }

    /// Returns the X25519 secret seed bytes (32 bytes).
    /// Used by the FFI layer to export the private key for secure storage on the client.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_seed
    }

    /// Returns the Ed25519 signing key bytes (32 bytes).
    /// Used by the FFI layer to export the signing key for secure storage on the client.
    pub fn signing_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Reconstruct an IdentityKeyPair from exported byte slices.
    ///
    /// `identity_secret` must be exactly 32 bytes (X25519 seed).
    /// `signing_secret` must be exactly 32 bytes (Ed25519 signing key).
    pub fn from_bytes(identity_secret: &[u8], signing_secret: &[u8]) -> crate::Result<Self> {
        if identity_secret.len() != 32 {
            return Err(crate::CryptoError::InvalidKey(
                format!("identity secret must be 32 bytes, got {}", identity_secret.len()),
            ));
        }
        if signing_secret.len() != 32 {
            return Err(crate::CryptoError::InvalidKey(
                format!("signing secret must be 32 bytes, got {}", signing_secret.len()),
            ));
        }

        let mut secret_seed = [0u8; 32];
        secret_seed.copy_from_slice(identity_secret);
        let x25519_secret = StaticSecret::from(secret_seed);
        let x25519_public = PublicKey::from(&x25519_secret);

        let mut signing_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(signing_secret);
        let signing_key = SigningKey::from_bytes(&signing_bytes);

        Ok(Self {
            secret_seed,
            x25519_secret,
            x25519_public,
            signing_key,
        })
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.x25519_public
    }

    /// Returns the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Perform X25519 Diffie-Hellman key exchange with another party's public key.
    pub fn dh(&self, their_public: &PublicKey) -> SharedSecret {
        self.x25519_secret.diffie_hellman(their_public)
    }

    /// Sign a message using the Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify an Ed25519 signature against a verifying key.
    pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = match Signature::from_bytes(&sig_bytes) {
            sig => sig,
        };
        verifying_key.verify(message, &sig).is_ok()
    }
}

/// A signed pre-key: an X25519 keypair whose public key is signed by the
/// identity's Ed25519 key, proving ownership.
pub struct SignedPreKey {
    secret_seed: [u8; 32],
    x25519_secret: StaticSecret,
    x25519_public: PublicKey,
    signature: Vec<u8>,
}

impl SignedPreKey {
    /// Generate a new signed pre-key, signed by the given identity keypair.
    pub fn generate(identity: &IdentityKeyPair) -> Self {
        let mut secret_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut secret_seed);
        let x25519_secret = StaticSecret::from(secret_seed);
        let x25519_public = PublicKey::from(&x25519_secret);
        let signature = identity.sign(x25519_public.as_bytes());

        Self {
            secret_seed,
            x25519_secret,
            x25519_public,
            signature,
        }
    }

    /// Reconstruct a SignedPreKey from exported byte slices.
    ///
    /// `secret` must be exactly 32 bytes (X25519 seed).
    /// `public` must be exactly 32 bytes (X25519 public key).
    /// `signature` must be exactly 64 bytes (Ed25519 signature).
    pub fn from_bytes(secret: &[u8], public: &[u8], signature: &[u8]) -> crate::Result<Self> {
        if secret.len() != 32 {
            return Err(crate::CryptoError::InvalidKey(
                format!("secret must be 32 bytes, got {}", secret.len()),
            ));
        }
        if public.len() != 32 {
            return Err(crate::CryptoError::InvalidKey(
                format!("public key must be 32 bytes, got {}", public.len()),
            ));
        }
        if signature.len() != 64 {
            return Err(crate::CryptoError::InvalidKey(
                format!("signature must be 64 bytes, got {}", signature.len()),
            ));
        }

        let mut secret_seed = [0u8; 32];
        secret_seed.copy_from_slice(secret);
        let x25519_secret = StaticSecret::from(secret_seed);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(public);
        let x25519_public = PublicKey::from(pub_bytes);

        Ok(Self {
            secret_seed,
            x25519_secret,
            x25519_public,
            signature: signature.to_vec(),
        })
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.x25519_public
    }

    /// Returns the Ed25519 signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verify this pre-key's signature against the given identity keypair.
    pub fn verify_signature(&self, identity: &IdentityKeyPair) -> bool {
        let verifying_key = identity.verifying_key();
        IdentityKeyPair::verify(&verifying_key, self.x25519_public.as_bytes(), &self.signature)
    }

    /// Perform X25519 Diffie-Hellman key exchange with another party's public key.
    pub fn dh(&self, their_public: &PublicKey) -> SharedSecret {
        self.x25519_secret.diffie_hellman(their_public)
    }

    /// Returns the raw X25519 secret seed bytes (32 bytes).
    /// Used by the Double Ratchet and FFI layer.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_seed
    }
}

/// A one-time pre-key: an ephemeral X25519 keypair with a unique identifier.
pub struct OneTimePreKey {
    id: u32,
    secret_seed: [u8; 32],
    x25519_secret: StaticSecret,
    x25519_public: PublicKey,
}

impl OneTimePreKey {
    /// Generate a batch of one-time pre-keys with sequential IDs starting from 0.
    pub fn generate_batch(count: usize) -> Vec<Self> {
        (0..count)
            .map(|i| {
                let mut secret_seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut OsRng, &mut secret_seed);
                let x25519_secret = StaticSecret::from(secret_seed);
                let x25519_public = PublicKey::from(&x25519_secret);
                Self {
                    id: i as u32,
                    secret_seed,
                    x25519_secret,
                    x25519_public,
                }
            })
            .collect()
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.x25519_public
    }

    /// Returns the unique key ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Perform X25519 Diffie-Hellman key exchange with another party's public key.
    pub fn dh(&self, their_public: &PublicKey) -> SharedSecret {
        self.x25519_secret.diffie_hellman(their_public)
    }

    /// Returns the raw X25519 secret seed bytes (32 bytes).
    /// Used by the FFI layer to export the private key for secure storage on the client.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_seed
    }
}

/// A key bundle containing only public keys, suitable for uploading to a server.
/// Other users fetch this bundle to initiate an X3DH key exchange.
#[derive(Clone)]
pub struct KeyBundle {
    identity_key: PublicKey,
    signed_pre_key: PublicKey,
    signature: Vec<u8>,
    one_time_pre_keys: Vec<PublicKey>,
}

impl KeyBundle {
    /// Create a new key bundle from public components.
    pub fn new(
        identity_key: PublicKey,
        signed_pre_key: PublicKey,
        signature: Vec<u8>,
        one_time_pre_keys: Vec<PublicKey>,
    ) -> Self {
        Self {
            identity_key,
            signed_pre_key,
            signature,
            one_time_pre_keys,
        }
    }

    /// Returns the identity public key.
    pub fn identity_key(&self) -> &PublicKey {
        &self.identity_key
    }

    /// Returns the signed pre-key public key.
    pub fn signed_pre_key(&self) -> &PublicKey {
        &self.signed_pre_key
    }

    /// Returns the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the one-time pre-key public keys.
    pub fn one_time_pre_keys(&self) -> &[PublicKey] {
        &self.one_time_pre_keys
    }
}
