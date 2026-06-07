//! Post-Quantum Cryptography module.
//!
//! Provides ML-KEM-768 hybrid key encapsulation combined with X25519
//! for quantum-resistant key exchange. Feature-gated behind `post-quantum`.

pub mod hybrid_kem;
