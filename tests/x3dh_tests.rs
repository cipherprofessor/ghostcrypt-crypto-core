use ghostcrypt_crypto::{identity, x3dh};

#[test]
fn test_x3dh_alice_and_bob_derive_same_shared_secret() {
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let bob_opks = identity::OneTimePreKey::generate_batch(10);

    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[0].public_key().clone()),
    };

    let alice_identity = identity::IdentityKeyPair::generate();
    let alice_result = x3dh::initiate(&alice_identity, &bob_bundle).unwrap();

    let bob_result = x3dh::respond(
        &bob_identity,
        &bob_spk,
        Some(&bob_opks[0]),
        &alice_identity.public_key(),
        &alice_result.ephemeral_key,
    ).unwrap();

    assert_eq!(
        alice_result.shared_secret, bob_result.shared_secret,
        "Alice and Bob must derive the same shared secret"
    );
    assert_eq!(alice_result.shared_secret.len(), 32);
}

#[test]
fn test_x3dh_without_one_time_pre_key() {
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);

    let bob_bundle = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: None,
    };

    let alice_identity = identity::IdentityKeyPair::generate();
    let alice_result = x3dh::initiate(&alice_identity, &bob_bundle).unwrap();

    let bob_result = x3dh::respond(
        &bob_identity,
        &bob_spk,
        None,
        &alice_identity.public_key(),
        &alice_result.ephemeral_key,
    ).unwrap();

    assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
}

#[test]
fn test_x3dh_different_sessions_produce_different_secrets() {
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let bob_opks = identity::OneTimePreKey::generate_batch(2);

    let bundle1 = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[0].public_key().clone()),
    };

    let bundle2 = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: bob_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: Some(bob_opks[1].public_key().clone()),
    };

    let alice = identity::IdentityKeyPair::generate();
    let result1 = x3dh::initiate(&alice, &bundle1).unwrap();
    let result2 = x3dh::initiate(&alice, &bundle2).unwrap();

    assert_ne!(result1.shared_secret, result2.shared_secret);
}

#[test]
fn test_x3dh_rejects_unauthentic_signed_prekey() {
    let bob_identity = identity::IdentityKeyPair::generate();
    let bob_spk = identity::SignedPreKey::generate(&bob_identity);
    let eve_identity = identity::IdentityKeyPair::generate();

    // The bundle carries Eve's verifying key instead of Bob's, so the signed
    // pre-key signature must fail verification and initiate() must refuse.
    let forged = x3dh::PreKeyBundle {
        identity_key: bob_identity.public_key().clone(),
        identity_verifying_key: eve_identity.verifying_key(),
        signed_pre_key: bob_spk.public_key().clone(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: None,
    };

    let alice = identity::IdentityKeyPair::generate();
    assert!(
        x3dh::initiate(&alice, &forged).is_err(),
        "X3DH must reject a signed pre-key whose signature does not verify"
    );
}
