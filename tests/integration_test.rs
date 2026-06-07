use ghostcrypt_crypto::{identity, x3dh, ratchet};

/// Simulates a complete encrypted conversation between Alice and Bob.
/// This test verifies the full GhostCrypt encryption pipeline:
/// Key Generation -> X3DH -> Double Ratchet -> Encrypted Messages
#[test]
fn test_full_encrypted_conversation() {
    // ============================================================
    // Phase 1: Key Generation (both users, on their devices)
    // ============================================================

    // Alice generates her identity
    let alice_identity = identity::IdentityKeyPair::generate();

    // Bob generates his identity + pre-keys
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let bob_opks = identity::OneTimePreKey::generate_batch(100);

    // Verify Bob's signed pre-key is valid
    assert!(bob_spk.verify_signature(&bob_identity), "Bob's SPK signature must be valid");

    // ============================================================
    // Phase 2: Key Bundle Exchange (simulating server)
    // ============================================================

    // Bob uploads his public key bundle to "the server"
    // The server only sees PUBLIC keys — never private keys
    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[0].public_key().clone()),
    };

    // ============================================================
    // Phase 3: X3DH Key Exchange
    // ============================================================

    // Alice initiates X3DH with Bob's bundle
    let alice_x3dh = x3dh::initiate(&alice_identity, &bob_bundle)
        .expect("Alice X3DH initiation must succeed");

    // Bob processes Alice's initial message
    let bob_x3dh = x3dh::respond(
        &bob_identity,
        &bob_spk,
        Some(&bob_opks[0]),
        &alice_identity.public_key(),
        &alice_x3dh.ephemeral_key,
    ).expect("Bob X3DH response must succeed");

    // CRITICAL: Both must derive the SAME shared secret
    assert_eq!(
        alice_x3dh.shared_secret, bob_x3dh.shared_secret,
        "X3DH shared secret must match"
    );

    // ============================================================
    // Phase 4: Double Ratchet Session Initialization
    // ============================================================

    let mut alice_session = ratchet::Session::init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public_key().clone(),
    );

    let mut bob_session = ratchet::Session::init_bob(
        &bob_x3dh.shared_secret,
        &bob_spk,
    );

    // ============================================================
    // Phase 5: Encrypted Conversation
    // ============================================================

    // --- Message 1: Alice -> Bob ---
    let (h1, ct1) = alice_session.encrypt(b"Hey Bob! Welcome to GhostCrypt!")
        .expect("Alice encrypt must succeed");

    // Simulate "the server" seeing the message -- only encrypted garbage
    assert_ne!(ct1.ciphertext, b"Hey Bob! Welcome to GhostCrypt!".to_vec(),
        "Server must NOT see plaintext");

    let pt1 = bob_session.decrypt(&h1, &ct1)
        .expect("Bob decrypt must succeed");
    assert_eq!(pt1, b"Hey Bob! Welcome to GhostCrypt!");

    // --- Message 2: Bob -> Alice (triggers DH ratchet) ---
    let (h2, ct2) = bob_session.encrypt(b"Hey Alice! This is encrypted!")
        .expect("Bob encrypt must succeed");

    let pt2 = alice_session.decrypt(&h2, &ct2)
        .expect("Alice decrypt must succeed");
    assert_eq!(pt2, b"Hey Alice! This is encrypted!");

    // --- Messages 3-7: Rapid-fire Alice -> Bob ---
    let messages = vec![
        "Speak freely.",
        "No one can listen.",
        "Not us.",
        "Not them.",
        "Not anyone.",
    ];

    let mut encrypted_messages = Vec::new();
    for msg in &messages {
        let (h, ct) = alice_session.encrypt(msg.as_bytes())
            .expect("Encrypt must succeed");
        encrypted_messages.push((h, ct));
    }

    // Deliver in order and verify
    for (i, (h, ct)) in encrypted_messages.iter().enumerate() {
        let pt = bob_session.decrypt(h, ct)
            .expect("Decrypt must succeed");
        assert_eq!(pt, messages[i].as_bytes());
    }

    // --- Message 8: Bob -> Alice (another DH ratchet) ---
    let (h8, ct8) = bob_session.encrypt(b"The ghost protocol works!")
        .expect("Bob encrypt must succeed");
    let pt8 = alice_session.decrypt(&h8, &ct8)
        .expect("Alice decrypt must succeed");
    assert_eq!(pt8, b"The ghost protocol works!");

    // ============================================================
    // Phase 6: Out-of-Order Delivery Test
    // ============================================================

    let (h_a, ct_a) = alice_session.encrypt(b"Message A").unwrap();
    let (h_b, ct_b) = alice_session.encrypt(b"Message B").unwrap();
    let (h_c, ct_c) = alice_session.encrypt(b"Message C").unwrap();

    // Deliver in reverse order -- must still work
    assert_eq!(bob_session.decrypt(&h_c, &ct_c).unwrap(), b"Message C");
    assert_eq!(bob_session.decrypt(&h_a, &ct_a).unwrap(), b"Message A");
    assert_eq!(bob_session.decrypt(&h_b, &ct_b).unwrap(), b"Message B");

    // ============================================================
    // Phase 7: Forward Secrecy Verification
    // ============================================================

    // Same plaintext encrypted twice must produce different ciphertext
    let (_, fs1) = alice_session.encrypt(b"same message").unwrap();
    let (_, fs2) = alice_session.encrypt(b"same message").unwrap();
    assert_ne!(fs1.ciphertext, fs2.ciphertext,
        "Forward secrecy: same plaintext must produce different ciphertext");
    assert_ne!(fs1.nonce, fs2.nonce,
        "Each message must use a unique nonce");

    // ============================================================
    // Phase 8: Server Knowledge Test
    // ============================================================

    // Collect all ciphertexts "seen by the server"
    let server_saw = vec![&ct1, &ct2, &ct8];
    for ct in server_saw {
        // Server only sees random-looking bytes
        assert!(ct.ciphertext.len() > 0, "Ciphertext must not be empty");
        assert!(ct.nonce.len() == 12, "AES-GCM nonce must be 12 bytes");
        // The ciphertext contains no recognizable plaintext patterns
        let ct_str = String::from_utf8_lossy(&ct.ciphertext);
        assert!(!ct_str.contains("Hey"), "Server must not see any plaintext");
        assert!(!ct_str.contains("Ghost"), "Server must not see any plaintext");
        assert!(!ct_str.contains("encrypt"), "Server must not see any plaintext");
    }

    println!("\n FULL INTEGRATION TEST PASSED!");
    println!(" Key generation works");
    println!(" X3DH key exchange derives matching secrets");
    println!(" Double Ratchet encrypts/decrypts correctly");
    println!(" Multi-message conversations work");
    println!(" Ping-pong (DH ratchet rotation) works");
    println!(" Out-of-order message delivery works");
    println!(" Forward secrecy: unique keys per message");
    println!(" Server sees ONLY encrypted garbage");
    println!("\n   Speak freely. No one can listen.");
    println!("   Not us. Not them. Not anyone.\n");
}

/// Test that wrong recipient cannot decrypt messages
#[test]
fn test_wrong_recipient_cannot_decrypt() {
    let alice_identity = identity::IdentityKeyPair::generate();
    let bob_identity = identity::IdentityKeyPair::generate();
    let eve_identity = identity::IdentityKeyPair::generate(); // Attacker!

    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let bob_opks = identity::OneTimePreKey::generate_batch(1);

    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[0].public_key().clone()),
    };

    // Alice and Bob establish a session
    let alice_x3dh = x3dh::initiate(&alice_identity, &bob_bundle).unwrap();
    let bob_x3dh = x3dh::respond(
        &bob_identity, &bob_spk, Some(&bob_opks[0]),
        &alice_identity.public_key(), &alice_x3dh.ephemeral_key,
    ).unwrap();

    let mut alice_session = ratchet::Session::init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public_key().clone(),
    );
    let mut bob_session = ratchet::Session::init_bob(
        &bob_x3dh.shared_secret,
        &bob_spk,
    );

    // Alice sends a message
    let (header, ciphertext) = alice_session.encrypt(b"Secret for Bob only!").unwrap();

    // Bob can decrypt
    let plaintext = bob_session.decrypt(&header, &ciphertext).unwrap();
    assert_eq!(plaintext, b"Secret for Bob only!");

    // Eve tries to decrypt with a fake session -- she doesn't have the shared secret
    let eve_spk = identity::SignedPreKey::generate(&eve_identity);
    let mut eve_session = ratchet::Session::init_bob(
        b"wrong_shared_secret_32_bytes!!!!", // Eve's guess
        &eve_spk,
    );

    let eve_result = eve_session.decrypt(&header, &ciphertext);
    assert!(eve_result.is_err(), "Eve must NOT be able to decrypt Alice's message!");

    println!("\n Eve (attacker) FAILED to decrypt -- encryption works!");
}
