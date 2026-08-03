//! DID Core - Core DID types and traits
//!
//! This crate provides the foundational types and traits for working with DIDs
//! (Decentralized Identifiers) in accordance with the W3C DID Core specification.
//!
//!
//! # Architecture
//!
//! - **Pure types**: This crate contains NO implementations of resolvers or storage.
//! - **Trait-based**: Defines traits for DID resolution and creation.
//!
//! # Examples
//!
//! ## Parsing a DID
//!
//! ```
//! use did::core::DID;
//!
//! let did = DID::parse("did:peer:2.Ez6LSms...Vf4D")?;
//! assert_eq!(did.method(), "peer");
//! assert_eq!(did.method_specific_id(), "2.Ez6LSms...Vf4D");
//! # Ok::<(), did::core::DidError>(())
//! ```
//!
//! ## Creating a DID Record
//!
//! ```
//! use did::core::record::{DidRecord, DidRole, DidDocumentKey};
//!
//! let record = DidRecord::builder(
//!     "uuid-123".to_string(),
//!     "did:peer:2.Ez6LSms".to_string(),
//!     DidRole::Created,
//! )
//! .add_key(DidDocumentKey::new(
//!     "key-uuid-1".to_string(),
//!     "#key-1".to_string(),
//! ))
//! .build();
//! ```

pub mod did;
pub mod did_repository;
pub mod document;
pub mod record;
pub mod resolver;

// Re-exports for convenience
pub use did::{DidError, DID};
pub use did_repository::{DidRepository, PersistSender};
pub use document::{DidDocument, Service, VerificationMethod, VerificationRelationship};
pub use record::{DidDocumentKey, DidRecord, DidRole};
pub use resolver::{
    CreateDidOptions, CreateDidResult, DidCreator, DidResolver, ResolutionError, ResolutionResult,
};
