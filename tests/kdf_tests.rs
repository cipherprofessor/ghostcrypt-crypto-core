use ghostcrypt_crypto::kdf;

#[test]
fn test_hkdf_derive_produces_correct_length() {
    let input_key_material = b"shared_secret_from_x3dh";
    let salt = b"ghostcrypt_salt";
    let info = b"ghostcrypt_ratchet";

    let output = kdf::derive(input_key_material, salt, info, 32);
    assert!(output.is_ok());
    assert_eq!(output.unwrap().len(), 32);
}

#[test]
fn test_hkdf_derive_deterministic() {
    let ikm = b"same_input";
    let salt = b"same_salt";
    let info = b"same_info";

    let out1 = kdf::derive(ikm, salt, info, 32).unwrap();
    let out2 = kdf::derive(ikm, salt, info, 32).unwrap();
    assert_eq!(out1, out2, "Same inputs must produce same output");
}

#[test]
fn test_hkdf_derive_different_info_produces_different_output() {
    let ikm = b"same_input";
    let salt = b"same_salt";

    let out1 = kdf::derive(ikm, salt, b"info_a", 32).unwrap();
    let out2 = kdf::derive(ikm, salt, b"info_b", 32).unwrap();
    assert_ne!(out1, out2, "Different info must produce different output");
}

#[test]
fn test_hkdf_derive_chain_key_and_message_key() {
    let chain_key = b"chain_key_input_32_bytes_long!!!";
    let (new_chain_key, message_key) = kdf::derive_chain_and_message_key(chain_key).unwrap();

    assert_eq!(new_chain_key.len(), 32);
    assert_eq!(message_key.len(), 32);
    assert_ne!(new_chain_key, message_key, "Chain key and message key must differ");
    assert_ne!(&new_chain_key[..], &chain_key[..], "New chain key must differ from old");
}
