//! # DIDComm v1 Implementation
//!
//! This crate provides DIDComm v1 (JWE-based) encryption and decryption support
//!
//! ## Features
//!
//! - **Authcrypt**: Authenticated encryption with sender verification
//! - **Anoncrypt**: Anonymous encryption without sender information
//!
//! ## Architecture
//!
//! - Uses Aries Askar for ECDH and X Salsa20-Poly1305 key wrapping
//! - Uses RustCrypto's ChaCha20-Poly1305 for content encryption
//! - Compatible with DIDComm v2 (via `didcomm_core`) for dual support

mod crypto;
mod error;
pub mod pack;
mod types;
pub mod unpack;

pub use crypto::*;
pub use error::{DIDCommV1Error, Result};
pub use pack::*;
pub use types::*;
pub use unpack::*;
