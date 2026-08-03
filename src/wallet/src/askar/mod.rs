//! # Askar Wallet Provider
//!
//! Production-ready wallet implementation using Aries Askar for encrypted key storage.
//!
//! This crate provides a secure wallet implementation that integrates with the Aries Askar
//! library for encrypted key storage and cryptographic operations.
//!
//! ## Features
//!
//! - Encrypted key storage at rest
//! - Classical key types (Ed25519, X25519) via Askar's `LocalKey`
//! - Quantum-resistant key types (SLH-DSA, ML-DSA-65) stored as raw bytes
//! - Signing and verification operations
//! - AEAD encryption/decryption
//! - Key agreement (ECDH)
//! - Key management (create, list, delete)
//!
//! ## Example
//!
//! ```rust,no_run
//! use wallet::askar::AskarWalletProvider;
//! use agent_core::traits::{WalletProvider, KeyType, KeyPurpose};
//! use aries_askar::{Store, StoreKeyMethod, PassKey};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create or open an Askar store
//! let store = Store::provision(
//!     "sqlite://:memory:",
//!     StoreKeyMethod::RawKey,
//!     PassKey::from("test-key"),
//!     None,
//!     false,
//! ).await?;
//!
//! // Create wallet provider
//! let wallet = AskarWalletProvider::new(std::sync::Arc::new(store));
//!
//! // Create a key
//! let key = wallet.create_key(KeyType::Ed25519, KeyPurpose::General).await?;
//!
//! // Sign data
//! let data = b"hello world";
//! let signature = wallet.sign(&key.id, data).await?;
//!
//! // Verify signature
//! let valid = wallet.verify(&key.id, data, &signature.bytes).await?;
//! assert!(valid);
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod key_types;
pub mod provider;

// Re-exports
pub use error::{AskarWalletError, Result};
pub use provider::AskarWalletProvider;
