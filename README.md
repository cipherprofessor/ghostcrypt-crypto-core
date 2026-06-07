<div align="center">

# 👻 ghostcrypt-crypto-core

### One memory-safe cryptographic core. Every platform.

The client-side cryptography of **GhostCrypt**, written once in Rust and compiled to
**WebAssembly** for the browser and to **native libraries** for mobile and desktop — so
every surface runs the same audited code instead of a separate re-implementation.

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-7B2FF7.svg?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.94%2B-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/WASM-ready-654FF0?style=flat-square&logo=webassembly&logoColor=white)](https://webassembly.org/)
[![Tests](https://img.shields.io/badge/tests-43%20passing-2F9E44?style=flat-square)](#-testing)
[![Status](https://img.shields.io/badge/status-research%20%C2%B7%20not%20audited-E8590C?style=flat-square)](#-security)

</div>

---

## ✨ What it is

A single Rust crate that implements the full end-to-end-encryption stack a messenger
needs, behind one clean interface. The same compiled core powers the web client (via
WebAssembly) and the mobile and desktop clients (via a foreign-function interface), which
collapses the audit surface from *one per platform* to *one*.

> **This repository contains only the cryptographic core.** GhostCrypt's application,
> servers, and infrastructure are not part of it.

```
                 ┌─────────────────────────────────────────────┐
   Browser  ◀────┤                                             │
   Android  ◀────┤   ghostcrypt-crypto-core  (one Rust crate)  │
   iOS      ◀────┤   X3DH · Double Ratchet · MLS · AEAD · PQC  │
   Desktop  ◀────┤                                             │
                 └─────────────────────────────────────────────┘
                   WebAssembly  +  native FFI, from one source
```

## 🔐 Features

| Capability | Detail |
| --- | --- |
| **X3DH key agreement** | Authenticated session setup — the signed-prekey signature is verified on the live path |
| **Double Ratchet** | Per-message keys, forward secrecy, and post-compromise security |
| **MLS group messaging** | Tree-based group key agreement via [OpenMLS](https://openmls.tech/) |
| **AEAD + KDF** | AES-256-GCM with HKDF-SHA-256; HMAC-SHA-256 symmetric ratchet |
| **Post-quantum (optional)** | Hybrid ML-KEM-768 + X25519, behind the `post-quantum` feature flag |
| **Multi-surface bindings** | WebAssembly (`wasm-bindgen`) and FFI (`flutter_rust_bridge`) |
| **Memory-safe** | Built on audited crates: `x25519-dalek`, `ed25519-dalek`, RustCrypto, OpenMLS |

## 🚀 Quick start

```bash
# Build
cargo build

# Run the full test suite (43 tests)
cargo test

# Include the post-quantum hybrid KEM
cargo test --features post-quantum
```

## ⚡ Benchmarks

Reproducible Criterion micro-benchmarks for the operations on the critical path. Run them
yourself with `./run-benchmarks.sh`. Medians below are from an Apple M-series core
(release build):

| Operation | Median |
| --- | ---: |
| AES-256-GCM encrypt (1 KiB) | **9.9 µs** |
| AES-256-GCM decrypt (1 KiB) | 8.3 µs |
| HKDF-SHA-256 | 2.5 µs |
| Identity keypair generate | 23.0 µs |
| Double Ratchet encrypt (1 KiB) | **12.9 µs** |
| Double Ratchet decrypt (1 KiB) | 83.3 µs |
| X3DH initiate (incl. signature verify) / respond | 115 / 85 µs |
| MLS key package generate | 118 µs |
| MLS create group | 155 µs |
| MLS encrypt message (1 KiB) | 190 µs |

Every per-message operation finishes in tens of microseconds, and even the heaviest group
operation in under 0.2 ms — orders of magnitude below network latency.

## 🧪 Testing

```text
aead · identity · kdf · x3dh · ratchet · mls · pqc · end-to-end
43 tests, 0 failures
```

The suite includes a negative test (`test_x3dh_rejects_unauthentic_signed_prekey`) that
confirms a forged prekey signature is rejected.

## 📂 Project structure

```
src/
├── lib.rs          crate root
├── aead/           AES-256-GCM authenticated encryption
├── kdf/            HKDF-SHA-256 key derivation
├── identity/       identity keys, signed prekeys, one-time prekeys
├── x3dh/           X3DH key agreement (+ prekey-signature verification)
├── ratchet/        Double Ratchet session state machine
├── mls/            MLS group messaging (OpenMLS wrapper)
├── pqc/            hybrid post-quantum KEM (feature-gated)
├── api.rs          FFI surface (flutter_rust_bridge)
└── wasm.rs         WebAssembly surface (wasm-bindgen)
benches/            Criterion benchmarks
tests/              integration tests
```

## 🛡️ Security

This is a **research reference implementation**, and it has **not been independently
audited**. Please do not use it to protect real user data. Primitives come from
well-regarded audited crates, the X3DH path authenticates the signed prekey before use,
and testing is currently example-based (known-answer and property-based tests are
planned). Treat it as a learning and research artifact.

## 📄 Paper

This crate is the reference implementation accompanying a research paper on single-core,
multi-surface architecture for end-to-end encrypted messaging. *(Citation to be added.)*

## ⚖️ License

Released under the [MIT License](LICENSE) © 2026 Mohsin Manzoor Bhat.

<div align="center">
<sub>Built with Rust 🦀 — speak freely.</sub>
</div>
