//! # mDoc (Mobile Document) Implementation for Rust
//!
//! This crate provides ISO/IEC 18013-5 compliant mobile document (mDoc) functionality.
//! It implements the mDL (mobile Driver's License) standard and related protocols.
//!
//! ## Architecture
//!
//! This implementation is based on the [@animo-id/mdoc](https://github.com/animo/mdoc) TypeScript library
//! and follows their pluggable architecture pattern.
//!
//! ### Core Components:
//!
//! - **CBOR**: Using `ciborium` for CBOR encoding/decoding
//! - **COSE**: Using `coset` for COSE Sign1/Mac0 operations
//! - **Context**: Pluggable crypto via `MdocContext` trait (similar to animo's context pattern)
//!
//! ### Main Modules:
//!
//! - `issuer`: Issue mDocs with COSE_Sign1 issuer authentication
//! - `holder`: Create device responses with selective disclosure
//! - `verifier`: Verify mDocs and device responses
//!
//! ## Example: Issuing an mDL
//!
//! ```rust,ignore
//! use mdoc::{Document, issuer::DocumentBuilder};
//!
//! let document = DocumentBuilder::new("org.iso.18013.5.1.mDL")
//!     .add_issuer_namespace("org.iso.18013.5.1", elements)
//!     .use_digest_algorithm(DigestAlgorithm::Sha256)
//!     .add_validity_info(validity_info)
//!     .add_device_key_info(device_key_info)
//!     .sign(context, issuer_key_id, "ES256")
//!     .await?;
//! ```

pub mod callbacks;
pub mod cbor;
pub mod cbor_tag24;
pub mod context;
pub mod cose;
pub mod device_auth;
pub mod error;
pub mod holder;
pub mod issuer;
pub mod proximity;
pub mod reader;
pub mod session;
pub mod types;
pub mod utils;
pub mod verifier;
pub mod x509;

// Re-export main types
pub use context::MdocContext;
pub use error::MdocError;
pub use holder::DeviceResponseBuilder;
pub use issuer::DocumentBuilder;
pub use types::*;
pub use verifier::Verifier;

// Constants from ISO 18013-5
pub const DOCTYPE_MDL: &str = "org.iso.18013.5.1.mDL";
pub const NAMESPACE_MDL: &str = "org.iso.18013.5.1";
pub const MDOC_VERSION: &str = "1.0";
