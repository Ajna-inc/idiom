/// AnonCreds core library for idiom
///
/// Provides Issuer, Holder, and Verifier services wrapping the anoncreds 0.2 crate,
/// with an abstract registry trait for schema and credential definition storage.
pub mod error;
pub mod holder;
pub mod issuer;
pub mod registry;
pub mod registry_memory;
pub mod registry_storage;
pub mod revocation;
pub mod store;
pub mod store_storage;
pub mod types;
pub mod verifier;

pub use error::{AnonCredsError, Result};
pub use holder::AnonCredsHolderService;
pub use issuer::AnonCredsIssuerService;
pub use registry::AnonCredsRegistry;
pub use registry_memory::InMemoryRegistry;
pub use registry_storage::StorageBackedRegistry;
pub use store::{AnonCredsStore, StoredCredentialRecord};
pub use store_storage::StorageBackedAnonCredsStore;
pub use verifier::AnonCredsVerifierService;
