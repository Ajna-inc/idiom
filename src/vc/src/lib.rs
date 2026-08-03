//! # vc
//!
//! Unified Verifiable Credentials crate, merging the previously separate
//! `vc_core`, `vc_formats`, `vc_storage`, and `vc_service` crates into a
//! single crate with one module per former crate.
//!
//! - [`core`]    — core VC models, traits, and error types (was `vc_core`).
//! - [`formats`] — credential format services: JWT-VC, JSON-LD, SD-JWT,
//!   mDoc, and (optional) AnonCreds (was `vc_formats`).
//! - [`storage`] — credential/presentation records and repositories
//!   (was `vc_storage`).
//! - [`service`] — the unified W3C credential service (was `vc_service`).
//!
//! Public paths are preserved: e.g. `vc_core::W3cCredential` is now
//! `vc::core::W3cCredential`.

pub mod core;
pub mod formats;
pub mod service;
pub mod storage;
