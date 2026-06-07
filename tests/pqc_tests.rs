#[cfg(feature = "post-quantum")]
mod pqc_tests {
    use ghostcrypt_crypto::pqc::hybrid_kem::*;

    #[test]
    fn test_mlkem_keypair_generation() {
        let (pub_key, sec_key) = generate_kem_keypair().unwrap();
        assert_eq!(
            pub_key.len(),
            MLKEM_PUBLIC_KEY_LEN,
            "ML-KEM public key should be {} bytes",
            MLKEM_PUBLIC_KEY_LEN
        );
        assert_eq!(
            sec_key.len(),
            MLKEM_SECRET_KEY_LEN,
            "ML-KEM secret key should be {} bytes",
            MLKEM_SECRET_KEY_LEN
        );
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate() {
        let (pub_key, sec_key) = generate_kem_keypair().unwrap();
        let (ciphertext, shared1) = encapsulate(&pub_key).unwrap();
        assert_eq!(
            ciphertext.len(),
            MLKEM_CIPHERTEXT_LEN,
            "ML-KEM ciphertext should be {} bytes",
            MLKEM_CIPHERTEXT_LEN
        );
        let shared2 = decapsulate(&sec_key, &ciphertext).unwrap();
        assert_eq!(
            shared1, shared2,
            "encapsulate and decapsulate must produce the same shared secret"
        );
    }

    #[test]
    fn test_mlkem_invalid_public_key_rejected() {
        let bad_key = vec![0u8; 32]; // wrong size
        let result = encapsulate(&bad_key);
        assert!(result.is_err(), "encapsulate with wrong-size key should fail");
    }

    #[test]
    fn test_mlkem_invalid_ciphertext_rejected() {
        let (_pub_key, sec_key) = generate_kem_keypair().unwrap();
        let bad_ct = vec![0u8; 32]; // wrong size
        let result = decapsulate(&sec_key, &bad_ct);
        assert!(
            result.is_err(),
            "decapsulate with wrong-size ciphertext should fail"
        );
    }

    #[test]
    fn test_hybrid_keypair_generation() {
        let keypair = generate_hybrid_keypair().unwrap();
        assert_eq!(keypair.x25519_public.len(), 32);
        assert_eq!(keypair.x25519_secret.len(), 32);
        assert_eq!(keypair.mlkem_public.len(), MLKEM_PUBLIC_KEY_LEN);
        assert_eq!(keypair.mlkem_secret.len(), MLKEM_SECRET_KEY_LEN);
    }

    #[test]
    fn test_hybrid_shared_secret_deterministic() {
        let x25519_shared = [0xABu8; 32];
        let mlkem_shared = [0xCDu8; 32];

        let result1 = hybrid_shared_secret(&x25519_shared, &mlkem_shared).unwrap();
        let result2 = hybrid_shared_secret(&x25519_shared, &mlkem_shared).unwrap();
        assert_eq!(result1, result2, "same inputs must produce same hybrid secret");
        assert_eq!(result1.len(), 32, "hybrid shared secret should be 32 bytes");
    }

    #[test]
    fn test_hybrid_shared_secret_differs_with_different_inputs() {
        let x25519_a = [0xAAu8; 32];
        let x25519_b = [0xBBu8; 32];
        let mlkem_shared = [0xCCu8; 32];

        let result_a = hybrid_shared_secret(&x25519_a, &mlkem_shared).unwrap();
        let result_b = hybrid_shared_secret(&x25519_b, &mlkem_shared).unwrap();
        assert_ne!(
            result_a, result_b,
            "different X25519 inputs must produce different hybrid secrets"
        );
    }

    #[test]
    fn test_hybrid_encapsulate_decapsulate() {
        // Alice generates hybrid keypair
        let alice = generate_hybrid_keypair().unwrap();
        // Bob generates hybrid keypair
        let bob = generate_hybrid_keypair().unwrap();

        // Alice encapsulates to Bob
        let encap = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        assert_eq!(encap.x25519_ephemeral_public.len(), 32);
        assert_eq!(encap.mlkem_ciphertext.len(), MLKEM_CIPHERTEXT_LEN);
        assert_eq!(encap.shared_secret.len(), 32);

        // Bob decapsulates using Alice's ephemeral X25519 public key
        let shared = hybrid_decapsulate(
            bob.x25519_secret.as_slice().try_into().unwrap(),
            encap.x25519_ephemeral_public.as_slice().try_into().unwrap(),
            &bob.mlkem_secret,
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        assert_eq!(
            encap.shared_secret, shared,
            "hybrid shared secrets must match between encapsulate and decapsulate"
        );
    }

    #[test]
    fn test_hybrid_wrong_x25519_key_produces_different_secret() {
        let alice = generate_hybrid_keypair().unwrap();
        let bob = generate_hybrid_keypair().unwrap();
        let eve = generate_hybrid_keypair().unwrap();

        let encap = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        // Eve uses her own X25519 key but Bob's ML-KEM key (she shouldn't have it,
        // but even if she did, the X25519 DH mismatch causes a different secret)
        let eve_shared = hybrid_decapsulate(
            eve.x25519_secret.as_slice().try_into().unwrap(),
            encap.x25519_ephemeral_public.as_slice().try_into().unwrap(),
            &bob.mlkem_secret,
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        assert_ne!(
            eve_shared, encap.shared_secret,
            "wrong X25519 key should produce a different hybrid shared secret"
        );
    }

    #[test]
    fn test_hybrid_wrong_mlkem_key_produces_different_secret() {
        let alice = generate_hybrid_keypair().unwrap();
        let bob = generate_hybrid_keypair().unwrap();
        let eve = generate_hybrid_keypair().unwrap();

        let encap = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        // Eve uses Bob's X25519 key but her own ML-KEM key
        let eve_shared = hybrid_decapsulate(
            bob.x25519_secret.as_slice().try_into().unwrap(),
            encap.x25519_ephemeral_public.as_slice().try_into().unwrap(),
            &eve.mlkem_secret,
            &encap.mlkem_ciphertext,
        );

        // Either decapsulation fails or produces a different shared secret
        match eve_shared {
            Ok(s) => assert_ne!(
                s, encap.shared_secret,
                "wrong ML-KEM key should produce a different hybrid shared secret"
            ),
            Err(_) => {} // decapsulation error is also acceptable
        }
    }

    #[test]
    fn test_hybrid_wrong_both_keys_fails() {
        let alice = generate_hybrid_keypair().unwrap();
        let bob = generate_hybrid_keypair().unwrap();
        let eve = generate_hybrid_keypair().unwrap();

        let encap = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        // Eve tries with all her own keys
        let eve_shared = hybrid_decapsulate(
            eve.x25519_secret.as_slice().try_into().unwrap(),
            encap.x25519_ephemeral_public.as_slice().try_into().unwrap(),
            &eve.mlkem_secret,
            &encap.mlkem_ciphertext,
        );

        match eve_shared {
            Ok(s) => assert_ne!(
                s, encap.shared_secret,
                "Eve should not derive the same shared secret"
            ),
            Err(_) => {} // error is also acceptable
        }
    }

    #[test]
    fn test_multiple_encapsulations_produce_different_secrets() {
        let alice = generate_hybrid_keypair().unwrap();
        let bob = generate_hybrid_keypair().unwrap();

        let encap1 = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        let encap2 = hybrid_encapsulate(
            alice.x25519_secret.as_slice().try_into().unwrap(),
            bob.x25519_public.as_slice().try_into().unwrap(),
            &bob.mlkem_public,
        )
        .unwrap();

        // ML-KEM encapsulation is randomized, so each call should produce
        // a different ciphertext and shared secret even with the same keys.
        // However, since X25519 DH is deterministic with the same static keys,
        // only the ML-KEM component varies. The hybrid secrets should differ.
        assert_ne!(
            encap1.mlkem_ciphertext, encap2.mlkem_ciphertext,
            "ML-KEM encapsulations should be randomized"
        );
        assert_ne!(
            encap1.shared_secret, encap2.shared_secret,
            "different ML-KEM randomness should produce different hybrid secrets"
        );
    }
}
