use ghostcrypt_crypto::{identity, x3dh, ratchet};

fn setup_alice_and_bob() -> (ratchet::Session, ratchet::Session) {
    // Bob publishes keys
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let bob_opks = identity::OneTimePreKey::generate_batch(1);

    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[0].public_key().clone()),
    };

    // Alice performs X3DH
    let alice_identity = identity::IdentityKeyPair::generate();
    let alice_x3dh = x3dh::initiate(&alice_identity, &bob_bundle).unwrap();

    // Bob performs X3DH
    let bob_x3dh = x3dh::respond(
        &bob_identity,
        &bob_spk,
        Some(&bob_opks[0]),
        &alice_identity.public_key(),
        &alice_x3dh.ephemeral_key,
    ).unwrap();

    // Initialize Double Ratchet sessions
    let alice_session = ratchet::Session::init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public_key().clone(),
    );
    let bob_session = ratchet::Session::init_bob(
        &bob_x3dh.shared_secret,
        &bob_spk,
    );

    (alice_session, bob_session)
}

#[test]
fn test_alice_sends_bob_receives() {
    let (mut alice, mut bob) = setup_alice_and_bob();

    let (header, ciphertext) = alice.encrypt(b"Hello Bob!").unwrap();
    let plaintext = bob.decrypt(&header, &ciphertext).unwrap();

    assert_eq!(plaintext, b"Hello Bob!");
}

#[test]
fn test_multiple_messages_one_direction() {
    let (mut alice, mut bob) = setup_alice_and_bob();

    for i in 0..10 {
        let msg = format!("Message {}", i);
        let (header, ct) = alice.encrypt(msg.as_bytes()).unwrap();
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }
}

#[test]
fn test_ping_pong_conversation() {
    let (mut alice, mut bob) = setup_alice_and_bob();

    let (h, ct) = alice.encrypt(b"Hey Bob!").unwrap();
    assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"Hey Bob!");

    let (h, ct) = bob.encrypt(b"Hey Alice!").unwrap();
    assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"Hey Alice!");

    let (h, ct) = alice.encrypt(b"How are you?").unwrap();
    assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"How are you?");

    let (h, ct) = bob.encrypt(b"Great, you?").unwrap();
    assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"Great, you?");
}

#[test]
fn test_out_of_order_messages() {
    let (mut alice, mut bob) = setup_alice_and_bob();

    let (h1, ct1) = alice.encrypt(b"First").unwrap();
    let (h2, ct2) = alice.encrypt(b"Second").unwrap();
    let (h3, ct3) = alice.encrypt(b"Third").unwrap();

    // Deliver out of order
    assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"Second");
    assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"Third");
    assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"First");
}

#[test]
fn test_forward_secrecy_unique_keys() {
    let (mut alice, mut bob) = setup_alice_and_bob();

    let (_, ct1) = alice.encrypt(b"Same message").unwrap();
    let (_, ct2) = alice.encrypt(b"Same message").unwrap();

    assert_ne!(ct1.ciphertext, ct2.ciphertext, "Same plaintext must produce different ciphertext");
}
