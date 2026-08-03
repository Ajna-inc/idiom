//! Cryptographic services for DIDComm message encryption/decryption
//!
//! This module provides adapters that bridge our agent's components
//! (DID Registry, Wallet) to the SICPA didcomm crate's resolver interfaces.

pub mod did_resolver;
pub mod keys;
pub mod secrets_resolver;

pub use did_resolver::AgentDIDResolver;
pub use keys::KeyExtractor;
pub use secrets_resolver::AgentSecretsResolver;
