//! ML-KEM-768 + X25519 Hybrid Key Encapsulation.
//!
//! Combines classical X25519 ECDH with post-quantum ML-KEM-768 (FIPS 203)
//! for a hybrid shared secret resistant to both classical and quantum attacks.
//!
//! ```text
//! Hybrid Shared Secret = HKDF(X25519_DH_Output || ML-KEM_Shared_Secret)
//! ```
//!
//! Even if quantum computers break X25519, ML-KEM protects the key exchange.
//! Even if ML-KEM has a flaw, X25519 still protects.

use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{CryptoError, Result};
use crate::kdf;

const HYBRID_SALT: &[u8] = b"GhostCrypt_Hybrid_PQ";
const HYBRID_INFO: &[u8] = b"hybrid_shared_secret";
const SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-768 public key size in bytes.
pub const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
/// ML-KEM-768 secret key size in bytes.
pub const MLKEM_SECRET_KEY_LEN: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

/// Generate an ML-KEM-768 keypair.
///
/// Returns `(public_key_bytes, secret_key_bytes)`.
pub fn generate_kem_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let (dk, ek): (DecapsulationKey<MlKem768Params>, EncapsulationKey<MlKem768Params>) =
        MlKem768::generate(&mut OsRng);
    let ek_bytes = ek.as_bytes().to_vec();
    let dk_bytes = dk.as_bytes().to_vec();
    Ok((ek_bytes, dk_bytes))
}

/// Encapsulate: given recipient's ML-KEM-768 public key, produce `(ciphertext, shared_secret)`.
pub fn encapsulate(recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let ek_encoded: &ml_kem::Encoded<EncapsulationKey<MlKem768Params>> =
        recipient_public_key.try_into().map_err(|_| {
            CryptoError::InvalidKey(format!(
                "ML-KEM public key must be {} bytes, got {}",
                MLKEM_PUBLIC_KEY_LEN,
                recipient_public_key.len()
            ))
        })?;
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(ek_encoded);
    let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|e| {
        CryptoError::KeyExchange(format!("ML-KEM encapsulation failed: {:?}", e))
    })?;
    Ok((ct.to_vec(), ss.to_vec()))
}

/// Decapsulate: given our ML-KEM-768 secret key and ciphertext, recover the shared secret.
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let dk_encoded: &ml_kem::Encoded<DecapsulationKey<MlKem768Params>> =
        secret_key.try_into().map_err(|_| {
            CryptoError::InvalidKey(format!(
                "ML-KEM secret key must be {} bytes, got {}",
                MLKEM_SECRET_KEY_LEN,
                secret_key.len()
            ))
        })?;
    let dk = DecapsulationKey::<MlKem768Params>::from_bytes(dk_encoded);
    let ct: &ml_kem::Ciphertext<MlKem768> = ciphertext.try_into().map_err(|_| {
        CryptoError::InvalidKey(format!(
            "ML-KEM ciphertext must be {} bytes, got {}",
            MLKEM_CIPHERTEXT_LEN,
            ciphertext.len()
        ))
    })?;
    let ss = dk.decapsulate(ct).map_err(|e| {
        CryptoError::KeyExchange(format!("ML-KEM decapsulation failed: {:?}", e))
    })?;
    Ok(ss.to_vec())
}

/// Combine X25519 DH output with ML-KEM shared secret via HKDF-SHA256.
///
/// This is the core "belt and suspenders" operation: even if one primitive
/// is broken, the other still provides security.
pub fn hybrid_shared_secret(
    x25519_shared: &[u8],
    mlkem_shared: &[u8],
) -> Result<Vec<u8>> {
    let combined = [x25519_shared, mlkem_shared].concat();
    kdf::derive(&combined, HYBRID_SALT, HYBRID_INFO, SHARED_SECRET_LEN)
}

/// Combined X25519 + ML-KEM-768 keypair for hybrid post-quantum key exchange.
pub struct HybridKeyPair {
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
}

/// Generate a full hybrid keypair containing both X25519 and ML-KEM-768 keys.
pub fn generate_hybrid_keypair() -> Result<HybridKeyPair> {
    // Generate X25519 keypair
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = PublicKey::from(&x25519_secret);

    // Generate ML-KEM-768 keypair
    let (mlkem_pub, mlkem_sec) = generate_kem_keypair()?;

    Ok(HybridKeyPair {
        x25519_public: x25519_public.as_bytes().to_vec(),
        x25519_secret: x25519_secret.to_bytes().to_vec(),
        mlkem_public: mlkem_pub,
        mlkem_secret: mlkem_sec,
    })
}

/// Result of a hybrid encapsulation operation.
pub struct HybridEncapsulation {
    /// The ephemeral X25519 public key used in the DH exchange.
    pub x25519_ephemeral_public: Vec<u8>,
    /// The ML-KEM-768 ciphertext to send to the recipient.
    pub mlkem_ciphertext: Vec<u8>,
    /// The derived hybrid shared secret (for local use only, never transmitted).
    pub shared_secret: Vec<u8>,
}

/// Perform hybrid encapsulation: X25519 DH + ML-KEM-768 encapsulation.
///
/// The sender performs:
/// 1. X25519 Diffie-Hellman with the recipient's X25519 public key
/// 2. ML-KEM encapsulation with the recipient's ML-KEM public key
/// 3. HKDF combination of both shared secrets
pub fn hybrid_encapsulate(
    our_x25519_secret: &[u8; 32],
    their_x25519_public: &[u8; 32],
    their_mlkem_public: &[u8],
) -> Result<HybridEncapsulation> {
    // X25519 DH
    let secret = StaticSecret::from(*our_x25519_secret);
    let their_pub = PublicKey::from(*their_x25519_public);
    let x25519_shared = secret.diffie_hellman(&their_pub);

    // ML-KEM encapsulate
    let (mlkem_ct, mlkem_shared) = encapsulate(their_mlkem_public)?;

    // Combine both shared secrets via HKDF
    let hybrid = hybrid_shared_secret(x25519_shared.as_bytes(), &mlkem_shared)?;

    let ephemeral_pub = PublicKey::from(&secret);

    Ok(HybridEncapsulation {
        x25519_ephemeral_public: ephemeral_pub.as_bytes().to_vec(),
        mlkem_ciphertext: mlkem_ct,
        shared_secret: hybrid,
    })
}

/// Perform hybrid decapsulation: X25519 DH + ML-KEM-768 decapsulation.
///
/// The recipient performs:
/// 1. X25519 Diffie-Hellman with the sender's X25519 public key
/// 2. ML-KEM decapsulation with their own ML-KEM secret key
/// 3. HKDF combination of both shared secrets
pub fn hybrid_decapsulate(
    our_x25519_secret: &[u8; 32],
    their_x25519_public: &[u8; 32],
    our_mlkem_secret: &[u8],
    mlkem_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    // X25519 DH
    let secret = StaticSecret::from(*our_x25519_secret);
    let their_pub = PublicKey::from(*their_x25519_public);
    let x25519_shared = secret.diffie_hellman(&their_pub);

    // ML-KEM decapsulate
    let mlkem_shared = decapsulate(our_mlkem_secret, mlkem_ciphertext)?;

    // Combine both shared secrets via HKDF
    hybrid_shared_secret(x25519_shared.as_bytes(), &mlkem_shared)
}
