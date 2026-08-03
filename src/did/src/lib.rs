//! DID - Unified Decentralized Identifier crate
//!
//! This crate merges the previously separate DID crates into a single crate
//! with one module per former crate:
//!
//! - [`core`] — core DID types and traits (`did_core`). `did_core::Item` → `did::core::Item`.
//! - [`methods`] — DID method implementations (`did_methods`). `did_methods::Item` → `did::methods::Item`.
//! - [`registry`] — method registry and resolution caching (`did_registry`). `did_registry::Item` → `did::registry::Item`.
//! - [`ajna`] — the CRDT-based `did:ajna` method (`did_ajna`). `did_ajna::Item` → `did::ajna::Item`.
//!
//! Each module preserves the public API of its originating crate.

pub mod ajna;
pub mod core;
pub mod methods;
pub mod registry;
