//! Crypto primitives for DCX.
//!
//! - [`aead`] — ChaCha20-Poly1305 seal/open
//! - [`kdf`] — HKDF-Expand for directional keys
//! - [`nonce`] — counter-based nonce derivation

pub mod aead;
pub mod kdf;
pub mod nonce;

pub use aead::{aead_open, aead_seal, AeadError};
pub use kdf::{derive_directional_keys, DirectionalKeys};
pub use nonce::{nonce_for_msg_id, NONCE_LEN};
