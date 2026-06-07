use x25519_dalek::PublicKey;
use ed25519_dalek::VerifyingKey;

/// A pre-key bundle fetched from the server for initiating X3DH.
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_key: PublicKey,
    /// Ed25519 verifying key of the bundle owner's identity. Used to
    /// authenticate the signed pre-key before it is used in the key
    /// agreement, so that a malicious key-distribution server cannot
    /// substitute a pre-key it controls.
    pub identity_verifying_key: VerifyingKey,
    pub signed_pre_key: PublicKey,
    pub signature: Vec<u8>,
    pub one_time_pre_key: Option<PublicKey>,
}

/// Result of an X3DH key exchange.
pub struct X3DHResult {
    /// The derived shared secret (32 bytes).
    pub shared_secret: Vec<u8>,
    /// Alice's ephemeral public key (sent to Bob so he can compute the same secret).
    pub ephemeral_key: PublicKey,
}
