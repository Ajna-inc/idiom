//! # Storage
//!
//! Record-persistence backends implementing the `StorageProvider` trait from
//! `agent_core`.
//!
//! This crate merges two storage backends into a single crate:
//!
//! - [`askar`] — encrypted, production-ready storage backed by Aries Askar
//!   (SQLite / PostgreSQL) with tag-based queries and multi-tenancy profiles.
//! - [`memory`] — a pure-Rust, WASM-compatible in-memory storage provider
//!   suitable for browsers, testing, and host-injected storage adapters.
//!
//! Each backend lives in its own module and can be used independently.

pub mod askar;
pub mod backend;
#[cfg(feature = "kanon")]
pub mod kanon;
pub mod memory;

// Re-exports
pub use askar::AskarStorageProvider;
pub use backend::StorageBackend;
#[cfg(feature = "kanon")]
pub use kanon::{KanonStorageProvider, KanonWalletProvider};
pub use memory::MemoryStorage;
