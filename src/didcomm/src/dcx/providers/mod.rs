//! Built-in [`SessionKeyProvider`](crate::dcx::session::SessionKeyProvider) implementations.
//!
//! [`classical::ClassicalX25519Provider`] is shipped here.
//! The PQ-secure `pq_bridge::PqBridgeDcxProvider` lives in the
//! separate `pq_bridge` crate.

pub mod classical;

pub use classical::{ClassicalKeyMaterial, ClassicalX25519Provider};

// Re-export the concrete X25519 types callers need to build a
// `ClassicalKeyMaterial`, so consumers depend on `dcx` alone rather
// than pinning their own `x25519-dalek` version. Kept off the crate
// root — reach in via `dcx::providers::{PublicKey, StaticSecret}`.
pub use x25519_dalek::{PublicKey, StaticSecret};
