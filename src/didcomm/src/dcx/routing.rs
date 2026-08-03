//! Routing-prefix helpers.
//!
//! The mediator's routing table is keyed by
//! `routing_prefix = SHA-256(recipient_kid)[0..16]`.

use sha2::{Digest, Sha256};

/// Length of the routing prefix on the wire.
pub const ROUTING_PREFIX_LEN: usize = 16;

/// Derive the routing prefix for a recipient's DID-relative kid.
///
/// The mediator uses this for O(1) routing without decrypting the
/// frame body.
#[inline]
pub fn derive_routing_prefix(recipient_kid: &str) -> [u8; ROUTING_PREFIX_LEN] {
    let hash = Sha256::digest(recipient_kid.as_bytes());
    let mut prefix = [0u8; ROUTING_PREFIX_LEN];
    prefix.copy_from_slice(&hash[..ROUTING_PREFIX_LEN]);
    prefix
}

/// Channel-id derivation.
///
/// ```text
/// channel_id = SHA-256(
///   "dcx/1.0/channel_id" ||
///   provider_id          ||
///   connection_id        ||
///   generation_be(4)
/// )[0..16]
/// ```
pub fn derive_channel_id(provider_id: &str, connection_id: &str, generation: u32) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"dcx/1.0/channel_id");
    hasher.update(provider_id.as_bytes());
    hasher.update(connection_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_prefix_is_deterministic() {
        let a = derive_routing_prefix("did:peer:foo#key-1");
        let b = derive_routing_prefix("did:peer:foo#key-1");
        assert_eq!(a, b);
    }

    #[test]
    fn routing_prefix_differs_per_kid() {
        let a = derive_routing_prefix("did:peer:foo#key-1");
        let b = derive_routing_prefix("did:peer:bar#key-2");
        assert_ne!(a, b);
    }

    #[test]
    fn channel_id_includes_provider_in_derivation() {
        let a = derive_channel_id("classical-x25519/1.0", "conn-1", 0);
        let b = derive_channel_id("pq-bridge/1.0", "conn-1", 0);
        // Different providers MUST yield different channel_ids even
        // with identical connection_id + generation.
        assert_ne!(a, b);
    }

    #[test]
    fn channel_id_rotates_with_generation() {
        let a = derive_channel_id("classical-x25519/1.0", "conn-1", 0);
        let b = derive_channel_id("classical-x25519/1.0", "conn-1", 1);
        assert_ne!(a, b);
    }
}
