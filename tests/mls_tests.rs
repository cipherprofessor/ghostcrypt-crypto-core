use ghostcrypt_crypto::mls;

// ---------------------------------------------------------------------------
// Key package generation
// ---------------------------------------------------------------------------

#[test]
fn test_key_package_generation() {
    let identity = b"user-alice";
    let result = mls::generate_key_package(identity).unwrap();
    assert!(!result.key_package.is_empty(), "key_package must not be empty");
    assert!(
        !result.secret_bundle.is_empty(),
        "secret_bundle must not be empty"
    );
}

#[test]
fn test_key_package_different_identities_produce_different_packages() {
    let alice = mls::generate_key_package(b"alice").unwrap();
    let bob = mls::generate_key_package(b"bob").unwrap();
    assert_ne!(
        alice.key_package, bob.key_package,
        "different identities must produce different key packages"
    );
}

// ---------------------------------------------------------------------------
// Group creation
// ---------------------------------------------------------------------------

#[test]
fn test_create_group() {
    let identity = b"user-alice";
    let result = mls::create_group(identity).unwrap();
    assert!(
        !result.group_state.is_empty(),
        "group_state must not be empty"
    );
    assert!(!result.group_id.is_empty(), "group_id must not be empty");
    assert_eq!(result.epoch, 0, "initial epoch must be 0");
}

// ---------------------------------------------------------------------------
// Add member + encrypt/decrypt round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_add_member_and_encrypt_decrypt() {
    // Alice creates group
    let alice_group = mls::create_group(b"alice").unwrap();

    // Bob generates key package
    let bob_kp = mls::generate_key_package(b"bob").unwrap();

    // Alice adds Bob
    let add_result =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();
    assert!(!add_result.commit.is_empty(), "commit must not be empty");
    assert!(!add_result.welcome.is_empty(), "welcome must not be empty");
    assert_eq!(add_result.epoch, 1, "epoch must advance to 1 after add");

    // Bob joins via welcome
    let bob_group =
        mls::process_welcome(&add_result.welcome, &bob_kp.secret_bundle).unwrap();
    assert!(
        !bob_group.group_state.is_empty(),
        "bob's group_state must not be empty"
    );

    // Alice encrypts
    let encrypt_result =
        mls::encrypt_message(&add_result.group_state, b"Hello Bob!").unwrap();
    assert!(
        !encrypt_result.mls_ciphertext.is_empty(),
        "ciphertext must not be empty"
    );

    // Bob decrypts
    let decrypt_result = mls::decrypt_message(
        &bob_group.group_state,
        &encrypt_result.mls_ciphertext,
    )
    .unwrap();
    assert_eq!(
        &decrypt_result.plaintext, b"Hello Bob!",
        "decrypted plaintext must match"
    );
}

// ---------------------------------------------------------------------------
// Three member group
// ---------------------------------------------------------------------------

#[test]
fn test_three_member_group() {
    // Alice creates group
    let alice_group = mls::create_group(b"alice").unwrap();

    // Bob generates key package and Alice adds him
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_bob =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();
    let bob_group =
        mls::process_welcome(&add_bob.welcome, &bob_kp.secret_bundle).unwrap();

    // Charlie generates key package and Alice adds him
    let charlie_kp = mls::generate_key_package(b"charlie").unwrap();
    let add_charlie =
        mls::add_member(&add_bob.group_state, &charlie_kp.key_package).unwrap();
    assert_eq!(
        add_charlie.epoch, 2,
        "epoch must advance to 2 after second add"
    );

    // Bob must process the commit that added Charlie so his group state advances
    let bob_after_commit =
        mls::process_commit(&bob_group.group_state, &add_charlie.commit).unwrap();

    // Charlie joins via welcome
    let charlie_group = mls::process_welcome(
        &add_charlie.welcome,
        &charlie_kp.secret_bundle,
    )
    .unwrap();

    // Alice encrypts a message for the group
    let encrypted =
        mls::encrypt_message(&add_charlie.group_state, b"Hello team!").unwrap();

    // Bob decrypts (using his state after processing Charlie's add commit)
    let bob_decrypted = mls::decrypt_message(
        &bob_after_commit.group_state,
        &encrypted.mls_ciphertext,
    )
    .unwrap();
    assert_eq!(&bob_decrypted.plaintext, b"Hello team!");

    // Charlie decrypts
    let charlie_decrypted = mls::decrypt_message(
        &charlie_group.group_state,
        &encrypted.mls_ciphertext,
    )
    .unwrap();
    assert_eq!(&charlie_decrypted.plaintext, b"Hello team!");
}

// ---------------------------------------------------------------------------
// Remove member
// ---------------------------------------------------------------------------

#[test]
fn test_remove_member() {
    // Alice creates group and adds Bob
    let alice_group = mls::create_group(b"alice").unwrap();
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_result =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();
    let _bob_group =
        mls::process_welcome(&add_result.welcome, &bob_kp.secret_bundle).unwrap();

    // Alice removes Bob (leaf index 1 — Bob is the second member)
    let remove_result = mls::remove_member(&add_result.group_state, 1).unwrap();
    assert!(!remove_result.commit.is_empty(), "remove commit must not be empty");
    assert_eq!(
        remove_result.epoch, 2,
        "epoch must advance to 2 after remove"
    );

    // Alice can still encrypt after removing Bob
    let encrypted =
        mls::encrypt_message(&remove_result.group_state, b"Solo again").unwrap();
    assert!(!encrypted.mls_ciphertext.is_empty());
}

// ---------------------------------------------------------------------------
// Epoch advances
// ---------------------------------------------------------------------------

#[test]
fn test_epoch_advances() {
    let group = mls::create_group(b"alice").unwrap();
    assert_eq!(group.epoch, 0, "initial epoch must be 0");

    // Add first member -> epoch 1
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_bob = mls::add_member(&group.group_state, &bob_kp.key_package).unwrap();
    assert_eq!(add_bob.epoch, 1, "epoch must be 1 after first add");

    // Add second member -> epoch 2
    let charlie_kp = mls::generate_key_package(b"charlie").unwrap();
    let add_charlie =
        mls::add_member(&add_bob.group_state, &charlie_kp.key_package).unwrap();
    assert_eq!(add_charlie.epoch, 2, "epoch must be 2 after second add");

    // Remove a member -> epoch 3
    let remove_result = mls::remove_member(&add_charlie.group_state, 1).unwrap();
    assert_eq!(remove_result.epoch, 3, "epoch must be 3 after remove");
}

// ---------------------------------------------------------------------------
// Process welcome result fields
// ---------------------------------------------------------------------------

#[test]
fn test_process_welcome_fields() {
    let alice_group = mls::create_group(b"alice").unwrap();
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_result =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();

    let welcome_result =
        mls::process_welcome(&add_result.welcome, &bob_kp.secret_bundle).unwrap();

    assert!(
        !welcome_result.group_state.is_empty(),
        "group_state must be populated"
    );
    assert!(
        !welcome_result.group_id.is_empty(),
        "group_id must be populated"
    );
    // After welcome, Bob is at the same epoch as Alice post-add
    assert_eq!(
        welcome_result.epoch, 1,
        "epoch after welcome should match add epoch"
    );
}

// ---------------------------------------------------------------------------
// Encrypt updates group state
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_updates_state() {
    let alice_group = mls::create_group(b"alice").unwrap();
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_result =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();

    let first = mls::encrypt_message(&add_result.group_state, b"msg1").unwrap();
    let second = mls::encrypt_message(&first.group_state, b"msg2").unwrap();

    // Each encryption produces a different ciphertext (different secret tree state)
    assert_ne!(
        first.mls_ciphertext, second.mls_ciphertext,
        "sequential encryptions must produce different ciphertext"
    );
}

// ---------------------------------------------------------------------------
// Decrypt commit via decrypt_message (graceful handling)
// ---------------------------------------------------------------------------

#[test]
fn test_decrypt_message_handles_commit() {
    // When a commit arrives through decrypt_message, it should merge the
    // staged commit and return empty plaintext (not an error).
    let alice_group = mls::create_group(b"alice").unwrap();
    let bob_kp = mls::generate_key_package(b"bob").unwrap();
    let add_result =
        mls::add_member(&alice_group.group_state, &bob_kp.key_package).unwrap();

    // Bob joins
    let bob_group =
        mls::process_welcome(&add_result.welcome, &bob_kp.secret_bundle).unwrap();

    // Add charlie from Alice's side — the commit is sent to Bob
    let charlie_kp = mls::generate_key_package(b"charlie").unwrap();
    let add_charlie =
        mls::add_member(&add_result.group_state, &charlie_kp.key_package).unwrap();

    // Bob receives the commit through decrypt_message
    let result =
        mls::decrypt_message(&bob_group.group_state, &add_charlie.commit).unwrap();
    assert!(
        result.plaintext.is_empty(),
        "commit processed via decrypt_message should return empty plaintext"
    );
}
