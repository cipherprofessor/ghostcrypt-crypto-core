//! Criterion micro-benchmarks for the GhostCrypt crypto core.
//!
//! Run with:  cargo bench --bench crypto_bench
//! Optionally enable the post-quantum path:  cargo bench --bench crypto_bench --features post-quantum
//!
//! Results are written to target/criterion/. A concise summary prints to stdout.
//! These numbers populate the "Evaluation" table of the GhostCrypt paper.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use ghostcrypt_crypto::aead;
use ghostcrypt_crypto::identity::{IdentityKeyPair, OneTimePreKey, SignedPreKey};
use ghostcrypt_crypto::kdf;
use ghostcrypt_crypto::mls;
use ghostcrypt_crypto::ratchet::state::Session;
use ghostcrypt_crypto::x3dh::{self, PreKeyBundle};

const MSG_1K: &[u8] = &[0x61u8; 1024];

// ---------------- primitives ----------------
fn bench_primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitives");

    // AES-256-GCM AEAD over a 1 KiB message
    let key = [7u8; 32];
    let ct = aead::encrypt(&key, MSG_1K, b"aad").unwrap();
    g.throughput(Throughput::Bytes(MSG_1K.len() as u64));
    g.bench_function("aead_encrypt_1KiB", |b| {
        b.iter(|| aead::encrypt(black_box(&key), black_box(MSG_1K), b"aad").unwrap())
    });
    g.bench_function("aead_decrypt_1KiB", |b| {
        b.iter(|| aead::decrypt(black_box(&key), black_box(&ct), b"aad").unwrap())
    });

    // HKDF-SHA256
    g.bench_function("hkdf_derive_32B", |b| {
        b.iter(|| kdf::derive(black_box(&[1u8; 32]), b"salt", b"info", 32).unwrap())
    });

    g.finish();
}

// ---------------- key generation ----------------
fn bench_keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("keygen");
    g.bench_function("identity_keypair", |b| b.iter(IdentityKeyPair::generate));

    let id = IdentityKeyPair::generate();
    g.bench_function("signed_prekey", |b| {
        b.iter(|| SignedPreKey::generate(black_box(&id)))
    });
    g.bench_function("one_time_prekeys_x100", |b| {
        b.iter(|| OneTimePreKey::generate_batch(black_box(100)))
    });
    g.finish();
}

// ---------------- X3DH ----------------
fn make_bundle(bob_id: &IdentityKeyPair, bob_spk: &SignedPreKey) -> PreKeyBundle {
    PreKeyBundle {
        identity_key: *bob_id.public_key(),
        signed_pre_key: *bob_spk.public_key(),
        signature: bob_spk.signature().to_vec(),
        one_time_pre_key: None,
    }
}

fn bench_x3dh(c: &mut Criterion) {
    let mut g = c.benchmark_group("x3dh");
    let bob_id = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(&bob_id);
    let bundle = make_bundle(&bob_id, &bob_spk);
    let alice = IdentityKeyPair::generate();

    g.bench_function("initiate", |b| {
        b.iter(|| x3dh::initiate(black_box(&alice), black_box(&bundle)).unwrap())
    });

    let res = x3dh::initiate(&alice, &bundle).unwrap();
    g.bench_function("respond", |b| {
        b.iter(|| {
            x3dh::respond(
                black_box(&bob_id),
                black_box(&bob_spk),
                None,
                alice.public_key(),
                black_box(&res.ephemeral_key),
            )
            .unwrap()
        })
    });
    g.finish();
}

// ---------------- Double Ratchet ----------------
fn fresh_pair() -> (Session, Session) {
    let bob_id = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(&bob_id);
    let bundle = make_bundle(&bob_id, &bob_spk);
    let alice = IdentityKeyPair::generate();
    let res = x3dh::initiate(&alice, &bundle).unwrap();
    let alice_sess = Session::init_alice(&res.shared_secret, *bob_spk.public_key());
    let bob_sess = Session::init_bob(&res.shared_secret, &bob_spk);
    (alice_sess, bob_sess)
}

fn bench_ratchet(c: &mut Criterion) {
    let mut g = c.benchmark_group("double_ratchet");

    // Encrypt: one long-lived sending session, chain advances each iteration.
    let (mut alice, _bob) = fresh_pair();
    g.throughput(Throughput::Bytes(MSG_1K.len() as u64));
    g.bench_function("encrypt_1KiB", |b| {
        b.iter(|| alice.encrypt(black_box(MSG_1K)).unwrap())
    });

    // Decrypt: fresh prepared message per iteration (setup excluded from timing).
    g.bench_function("decrypt_1KiB", |b| {
        b.iter_batched(
            || {
                let (mut a, b2) = fresh_pair();
                let (hdr, ct) = a.encrypt(MSG_1K).unwrap();
                (b2, hdr, ct)
            },
            |(mut bob, hdr, ct)| bob.decrypt(black_box(&hdr), black_box(&ct)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

// ---------------- MLS (OpenMLS) ----------------
fn bench_mls(c: &mut Criterion) {
    let mut g = c.benchmark_group("mls");
    let id = b"alice@ghostcrypt".as_slice();

    g.bench_function("generate_key_package", |b| {
        b.iter(|| mls::generate_key_package(black_box(id)).unwrap())
    });
    g.bench_function("create_group", |b| {
        b.iter(|| mls::create_group(black_box(id)).unwrap())
    });

    // App-message encrypt on a single-member group.
    let grp = mls::create_group(id).unwrap();
    g.throughput(Throughput::Bytes(MSG_1K.len() as u64));
    g.bench_function("encrypt_message_1KiB", |b| {
        b.iter_batched(
            || grp.group_state.clone(),
            |state| mls::encrypt_message(black_box(&state), black_box(MSG_1K)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

criterion_group!(benches, bench_primitives, bench_keygen, bench_x3dh, bench_ratchet, bench_mls);
criterion_main!(benches);
