# ghostcrypt-crypto-core

The cryptographic core of **GhostCrypt**, a research end-to-end encrypted messaging
system. It is a single memory-safe Rust crate that implements the full client-side
cryptography once and compiles to every client surface — to **WebAssembly** for the
browser and to **native libraries via a foreign-function interface** for mobile and
desktop — so that every platform runs the same audited code.

This repository contains **only the cryptographic core**. The GhostCrypt application,
servers, and infrastructure are not part of this repository.

## What it implements

- **X3DH** key agreement (with signed-prekey signature verification on the live path)
- **Double Ratchet** message encryption (forward secrecy + post-compromise security)
- **MLS** group messaging via [OpenMLS](https://openmls.tech/)
- **AEAD** (AES-256-GCM) and **HKDF-SHA-256** key derivation
- Optional **hybrid post-quantum KEM** (ML-KEM-768 + X25519), behind a feature flag
- Bindings: WebAssembly (`wasm-bindgen`) and FFI (`flutter_rust_bridge`)

## Status

This is a **research reference implementation**, not a production library. It has **not
been independently audited**. Do not use it to protect real user data. It accompanies a
research paper on single-core, multi-surface E2E messaging architecture.

## Build and test

```bash
# Build
cargo build

# Run the test suite (X3DH, Double Ratchet, MLS, AEAD, KDF, identity, PQC, end-to-end)
cargo test

# Optional: include the post-quantum hybrid KEM
cargo test --features post-quantum
```

## Benchmarks

Reproducible micro-benchmarks (Criterion) for the operations on the critical path:

```bash
./run-benchmarks.sh          # core paths
./run-benchmarks.sh --pq     # also benchmark the post-quantum hybrid KEM
```

Results are written to `bench-summary.txt`, and a full HTML report to
`target/criterion/report/index.html`. On an Apple M-series core, all per-message
operations complete in tens of microseconds and the heaviest MLS operation in under
0.2 ms.

## Security note

The crate uses audited primitive libraries (`x25519-dalek`, `ed25519-dalek`,
RustCrypto `aes-gcm` / `hkdf` / `hmac`, OpenMLS). The X3DH path verifies the signed
prekey's signature before use. Testing is currently example-based; known-answer and
property-based tests are planned. Treat this as a learning and research artifact.

## License

MIT. See [LICENSE](LICENSE).
