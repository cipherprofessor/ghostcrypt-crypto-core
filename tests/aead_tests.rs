use ghostcrypt_crypto::aead;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"Hello, GhostCrypt! Speak freely.";
    let associated_data = b"message_header";

    let encrypted = aead::encrypt(&key, plaintext, associated_data).unwrap();
    assert_ne!(encrypted.ciphertext, plaintext.to_vec(), "Ciphertext must differ from plaintext");

    let decrypted = aead::decrypt(&key, &encrypted, associated_data).unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_decrypt_with_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong_key = [0x43u8; 32];
    let plaintext = b"Secret message";

    let encrypted = aead::encrypt(&key, plaintext, b"").unwrap();
    let result = aead::decrypt(&wrong_key, &encrypted, b"");
    assert!(result.is_err(), "Decryption with wrong key must fail");
}

#[test]
fn test_decrypt_with_wrong_ad_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"Secret message";

    let encrypted = aead::encrypt(&key, plaintext, b"correct_ad").unwrap();
    let result = aead::decrypt(&key, &encrypted, b"wrong_ad");
    assert!(result.is_err(), "Decryption with wrong associated data must fail");
}

#[test]
fn test_each_encryption_produces_unique_ciphertext() {
    let key = [0x42u8; 32];
    let plaintext = b"Same message twice";

    let enc1 = aead::encrypt(&key, plaintext, b"").unwrap();
    let enc2 = aead::encrypt(&key, plaintext, b"").unwrap();
    assert_ne!(enc1.nonce, enc2.nonce, "Each encryption must use a unique nonce");
    assert_ne!(enc1.ciphertext, enc2.ciphertext, "Ciphertext must differ due to unique nonce");
}

#[test]
fn test_empty_plaintext() {
    let key = [0x42u8; 32];
    let plaintext = b"";

    let encrypted = aead::encrypt(&key, plaintext, b"").unwrap();
    let decrypted = aead::decrypt(&key, &encrypted, b"").unwrap();
    assert_eq!(decrypted, plaintext.to_vec());
}
