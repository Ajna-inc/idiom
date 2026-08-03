//! # DIDComm
//!
//! Unified DIDComm crate merging the previously separate `didcomm_core`,
//! `didcomm_v1`, `didcomm_transports`, and `didcomm_messaging` crates into a
//! single crate with the following module layout:
//!
//! - [`core`]: Core DIDComm v2 messaging (message types, envelope services, DID resolution).
//! - [`v1`]: DIDComm v1 (JWE-based) authcrypt/anoncrypt pack/unpack.
//! - [`transports`]: Transport layer (HTTP, WebSocket) for sending/receiving messages.
//! - [`messaging`]: Message routing, handler registry, and dispatching.
//!
//! Public API is preserved: `didcomm_core::Item` is now `didcomm::core::Item`,
//! `didcomm_v1::Item` is now `didcomm::v1::Item`, and so on.
//!
//! Note: the external SICPA `didcomm-rust` git dependency is renamed to
//! `sicpa_didcomm` within this crate to avoid a name clash with this crate.

pub mod core;
pub mod dcx;
pub mod messaging;
pub mod transports;
pub mod v1;
