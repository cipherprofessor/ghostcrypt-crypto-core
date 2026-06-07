use ghostcrypt_crypto::identity;

#[test]
fn test_generate_identity_keypair() {
    let keypair = identity::IdentityKeyPair::generate();
    assert_eq!(keypair.public_key().as_bytes().len(), 32);
}

#[test]
fn test_two_keypairs_are_different() {
    let kp1 = identity::IdentityKeyPair::generate();
    let kp2 = identity::IdentityKeyPair::generate();
    assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
}

#[test]
fn test_generate_signed_pre_key() {
    let identity = identity::IdentityKeyPair::generate();
    let spk = identity::SignedPreKey::generate(&identity);
    assert_eq!(spk.public_key().as_bytes().len(), 32);
    assert!(spk.verify_signature(&identity), "Signature must be valid");
}

#[test]
fn test_signed_pre_key_wrong_identity_fails_verification() {
    let identity1 = identity::IdentityKeyPair::generate();
    let identity2 = identity::IdentityKeyPair::generate();
    let spk = identity::SignedPreKey::generate(&identity1);
    assert!(!spk.verify_signature(&identity2), "Wrong identity must fail verification");
}

#[test]
fn test_generate_one_time_pre_keys() {
    let keys = identity::OneTimePreKey::generate_batch(100);
    assert_eq!(keys.len(), 100);

    let unique: std::collections::HashSet<_> = keys.iter()
        .map(|k| k.public_key().as_bytes().to_vec())
        .collect();
    assert_eq!(unique.len(), 100, "All one-time pre-keys must be unique");
}

#[test]
fn test_key_bundle_creation() {
    let identity = identity::IdentityKeyPair::generate();
    let spk = identity::SignedPreKey::generate(&identity);
    let opks = identity::OneTimePreKey::generate_batch(10);

    let bundle = identity::KeyBundle::new(
        identity.public_key().clone(),
        spk.public_key().clone(),
        spk.signature().to_vec(),
        opks.iter().map(|k| k.public_key().clone()).collect(),
    );

    assert_eq!(bundle.one_time_pre_keys().len(), 10);
}

// ── FFI byte export/import roundtrip tests ──────────────────────────────

#[test]
fn test_identity_keypair_byte_roundtrip() {
    let original = identity::IdentityKeyPair::generate();
    let secret = original.secret_bytes();
    let signing = original.signing_secret_bytes();
    let original_public = *original.public_key().as_bytes();
    let original_verifying = original.verifying_key().to_bytes();

    let restored = identity::IdentityKeyPair::from_bytes(&secret, &signing).unwrap();
    assert_eq!(restored.public_key().as_bytes(), &original_public);
    assert_eq!(restored.verifying_key().to_bytes(), original_verifying);
}

#[test]
fn test_signed_pre_key_byte_roundtrip() {
    let id = identity::IdentityKeyPair::generate();
    let spk = identity::SignedPreKey::generate(&id);
    let secret = spk.secret_bytes();
    let public_bytes = spk.public_key().as_bytes().to_vec();
    let sig_bytes = spk.signature().to_vec();

    let restored = identity::SignedPreKey::from_bytes(&secret, &public_bytes, &sig_bytes).unwrap();
    assert_eq!(restored.public_key().as_bytes(), spk.public_key().as_bytes());
    assert_eq!(restored.signature(), spk.signature());
}

#[test]
fn test_identity_keypair_sign_verify_after_roundtrip() {
    let original = identity::IdentityKeyPair::generate();
    let message = b"test message for signing";
    let signature = original.sign(message);

    let restored = identity::IdentityKeyPair::from_bytes(
        &original.secret_bytes(),
        &original.signing_secret_bytes(),
    ).unwrap();

    // Verify signature still works after roundtrip
    assert!(identity::IdentityKeyPair::verify(&restored.verifying_key(), message, &signature));
}

#[test]
fn test_dh_works_after_roundtrip() {
    let alice = identity::IdentityKeyPair::generate();
    let bob = identity::IdentityKeyPair::generate();

    // DH with original
    let shared1 = alice.dh(bob.public_key());

    // Roundtrip Alice
    let alice_restored = identity::IdentityKeyPair::from_bytes(
        &alice.secret_bytes(),
        &alice.signing_secret_bytes(),
    ).unwrap();

    // DH with restored should produce same shared secret
    let shared2 = alice_restored.dh(bob.public_key());
    assert_eq!(shared1.as_bytes(), shared2.as_bytes());
}

#[test]
fn test_identity_from_bytes_rejects_wrong_length() {
    let bad_short = [0u8; 16];
    let good = [0u8; 32];

    assert!(identity::IdentityKeyPair::from_bytes(&bad_short, &good).is_err());
    assert!(identity::IdentityKeyPair::from_bytes(&good, &bad_short).is_err());
}

#[test]
fn test_signed_pre_key_from_bytes_rejects_wrong_length() {
    let good_32 = [0u8; 32];
    let good_64 = [0u8; 64];
    let bad = [0u8; 10];

    assert!(identity::SignedPreKey::from_bytes(&bad, &good_32, &good_64).is_err());
    assert!(identity::SignedPreKey::from_bytes(&good_32, &bad, &good_64).is_err());
    assert!(identity::SignedPreKey::from_bytes(&good_32, &good_32, &bad).is_err());
}

#[test]
fn test_one_time_pre_key_secret_bytes() {
    let keys = identity::OneTimePreKey::generate_batch(3);
    for key in &keys {
        let secret = key.secret_bytes();
        assert_eq!(secret.len(), 32);
    }
    // Each key should have a different secret
    assert_ne!(keys[0].secret_bytes(), keys[1].secret_bytes());
    assert_ne!(keys[1].secret_bytes(), keys[2].secret_bytes());
}
