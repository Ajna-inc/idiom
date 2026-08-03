//! SessionKeyProvider trait — the injection point for hybrid PQ or classical
//! session key derivation.

use crate::dcx::errors::ProviderError;
use async_trait::async_trait;
use tokio::sync::broadcast;
use zeroize::ZeroizeOnDrop;

/// What a provider delivers to DCX per peer-pair channel.
///
/// Every field is required by the DCX wire protocol; providers MUST
/// populate all of them when calling [`SessionKeyProvider::establish`]
/// or [`SessionKeyProvider::get_keys`].
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// 32-byte symmetric secret. DCX derives directional keys
    /// (`K_send`, `K_recv`) from this via HKDF.
    pub kek: [u8; 32],

    /// 32-byte HMAC key for CHANNEL_CONFIRM downgrade defense.
    pub auth_key: [u8; 32],

    /// Monotonic counter incremented per provider rotation.
    #[zeroize(skip)]
    pub generation: u32,

    /// DID-relative kid of the peer's recipient key. Used to derive
    /// `routing_prefix = SHA-256(peer_kid)[0..16]`.
    #[zeroize(skip)]
    pub peer_kid: String,

    /// Stable identifier for this peer-pair connection.
    #[zeroize(skip)]
    pub connection_id: String,

    /// Deterministic per-pair initiator role for directional key
    /// derivation. Decided by the provider (e.g. `our_did < peer_did`)
    /// so both ends independently pick opposite roles — their `K_send`
    /// equals our `K_recv`. Not part of the wire; local only.
    #[zeroize(skip)]
    pub is_initiator: bool,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the raw keys.
        f.debug_struct("SessionKeys")
            .field("kek", &"<redacted 32B>")
            .field("auth_key", &"<redacted 32B>")
            .field("generation", &self.generation)
            .field("peer_kid", &self.peer_kid)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

/// Events emitted by a provider over its broadcast channel.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// New session established.
    Established {
        /// Peer's long-lived DID.
        peer_did: String,
        /// First generation number.
        generation: u32,
        /// The provider that established it.
        provider_id: &'static str,
    },
    /// Existing session rotated to a new generation.
    Rotated {
        /// Peer's long-lived DID.
        peer_did: String,
        /// Generation we just rotated away from.
        old_gen: u32,
        /// Generation we rotated to.
        new_gen: u32,
    },
    /// Session closed; keys zeroized.
    Closed {
        /// Peer's long-lived DID.
        peer_did: String,
        /// Reason ("user-requested", "idle-timeout", "rotation-failed", …).
        reason: String,
    },
}

/// Implemented by every Session Key Provider DCX can use.
#[async_trait]
pub trait SessionKeyProvider: Send + Sync {
    /// Discover-Features identifier (e.g., `"classical-x25519/1.0"` or
    /// `"pq-bridge/1.0"`).
    fn provider_id(&self) -> &'static str;

    /// Strength rank. Higher = stronger. DCX picks the strongest
    /// mutually-supported provider. Assigned ranks:
    /// - classical-x25519/1.0 → 10
    /// - pq-bridge/1.0 → 100
    fn strength(&self) -> u32;

    /// Get keys for an existing session with this peer.
    /// Returns `None` if no session exists.
    async fn get_keys(&self, peer_did: &str) -> Option<SessionKeys>;

    /// Run the provider's handshake to establish a fresh session.
    /// Returns once keys are derived and ready.
    async fn establish(&self, peer_did: &str) -> Result<SessionKeys, ProviderError>;

    /// Trigger an in-provider rotation. Returns the new generation's keys.
    /// Old keys remain valid for the provider's overlap window.
    async fn rotate(&self, peer_did: &str) -> Result<SessionKeys, ProviderError>;

    /// Close the session and zeroize all keys for this peer.
    async fn close(&self, peer_did: &str) -> Result<(), ProviderError>;

    /// Subscribe to key-change events.
    fn subscribe(&self) -> broadcast::Receiver<SessionEvent>;
}
