//! DID Registry - Method Registry and Resolution with Caching
//!
//! This crate provides a registry for DID methods with resolution caching.
//!
//! # Features
//! - Method registry with pluggable resolvers
//! - LRU memory cache (5-minute TTL) for remote DIDs
//! - Storage integration for DidRecord persistence
//!
//! # Example
//!
//! ```no_run
//! use did::registry::DidRegistry;
//! use did::methods::KeyDidResolver;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut registry = DidRegistry::new();
//!
//! // Register did:key resolver
//! registry.register_resolver(Arc::new(KeyDidResolver::new()));
//!
//! // Resolve a DID
//! let did = did::core::DID::parse("did:key:z6Mkp...")?;
//! let document = registry.resolve(&did).await?;
//! # Ok(())
//! # }
//! ```

pub mod cache;
pub mod registry;

pub use cache::DidCache;
pub use registry::DidRegistry;
