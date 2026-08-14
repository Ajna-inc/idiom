//! DID Methods - Implementations of various DID methods
//!
//! This crate provides implementations of DID methods:
//! - did:key - Native implementation using Askar cryptography
//! - did:peer - TODO: Using Affinidi's did-peer crate
//! - did:jwk - TODO: Using SpruceID's ssi-dids crate
//! - did:web - TODO: Custom HTTP implementation
//!
//! # Architecture
//!
//! Each DID method has two components:
//! - Resolver: Resolves DIDs to DID Documents
//! - Creator: Creates new DIDs and stores keys in wallet
//!
//! # Examples
//!
//! ```no_run
//! use did::methods::key::KeyDidResolver;
//! use did::core::{DidResolver, DID};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = KeyDidResolver::new();
//! let did = DID::parse("did:key:z6MkpTHR8...")?;
//! let document = resolver.resolve(&did).await?;
//! # Ok(())
//! # }
//! ```

pub mod cheqd;
pub mod indy;
pub mod jwk;
pub mod key;
pub mod peer;
pub mod web;
pub mod x25519;

// Re-exports
pub use cheqd::CheqdDidResolver;
pub use indy::{IndyDidResolver, IndyLedgerClient};
pub use jwk::JwkDidResolver;
pub use key::{KeyDidCreator, KeyDidResolver};
pub use peer::{encode_did_peer4, PeerDidCreator, PeerDidResolver};
pub use web::WebDidResolver;
pub use x25519::{
    ed25519_private_to_x25519, ed25519_pubkey_from_did_key, ed25519_public_to_x25519,
    ensure_did_key_form, verkey_aliases_for_did_key, DidKeyAliases,
};
