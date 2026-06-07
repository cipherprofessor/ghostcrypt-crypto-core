pub mod error;
pub mod kdf;
pub mod aead;
pub mod identity;
pub mod x3dh;
pub mod ratchet;
pub mod mls;

#[cfg(feature = "post-quantum")]
pub mod pqc;

pub use error::{CryptoError, Result};

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub mod api;
