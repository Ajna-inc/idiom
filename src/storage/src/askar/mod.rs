//! # Askar Storage Provider
//!
//! Storage implementation using Aries Askar for encrypted, production-ready storage.
//!
//! This crate provides a thin wrapper around the native `aries-askar` crate,
//! implementing the `StorageProvider` trait from `agent_core`.
//!
//! ## Features
//!
//! - Encrypted storage at rest
//! - Multiple backends (SQLite, PostgreSQL)
//! - Tag-based queries
//! - Transaction support
//! - Profile management (multi-tenancy)
//!
//! ## Example
//!
//! ```rust,no_run
//! use storage::askar::{AskarConfig, AskarStorageProvider};
//! use agent_core::traits::StorageProvider;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AskarConfig::builder()
//!         .in_memory()
//!         .pass_key("test-key")
//!         .build()?;
//!
//!     let provider = AskarStorageProvider::new(config).await?;
//!
//!     // Use the storage provider
//!     // provider.save(&record).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod error;
pub mod provider;
pub mod query_converter;

// Re-exports
pub use config::{AskarConfig, AskarConfigBuilder, KeyDerivationMethod};
pub use error::{AskarError, Result};
pub use provider::AskarStorageProvider;
