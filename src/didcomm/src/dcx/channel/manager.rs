//! Channel lookup tables.
//!
//! Three concurrent lookup paths (by channel_id, by peer_did, by
//! routing_prefix) are kept in sync atomically. All operations are
//! async-safe via `RwLock`s.

use crate::dcx::channel::state::Channel;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Per-agent collection of active DCX channels.
///
/// Each channel is wrapped in `Arc<Mutex<Channel>>` so two callers can
/// concurrently look up the channel but only one at a time can mutate
/// its `msg_id_send` counter (which is essential for nonce uniqueness).
pub struct ChannelManager {
    by_channel_id: RwLock<HashMap<[u8; 16], Arc<Mutex<Channel>>>>,
    by_peer_did: RwLock<HashMap<String, [u8; 16]>>,
    by_routing_prefix: RwLock<HashMap<[u8; 16], [u8; 16]>>,
}

impl ChannelManager {
    /// Build an empty manager.
    pub fn new() -> Self {
        Self {
            by_channel_id: RwLock::new(HashMap::new()),
            by_peer_did: RwLock::new(HashMap::new()),
            by_routing_prefix: RwLock::new(HashMap::new()),
        }
    }

    /// Register a channel for lookup. Replaces any prior channel with
    /// the same `channel_id`.
    pub async fn insert(&self, channel: Channel) {
        let channel_id = channel.channel_id;
        let peer_did = channel.peer_did.clone();
        let routing_prefix = channel.peer_routing_prefix;
        let arc = Arc::new(Mutex::new(channel));
        self.by_channel_id.write().await.insert(channel_id, arc);
        self.by_peer_did.write().await.insert(peer_did, channel_id);
        self.by_routing_prefix
            .write()
            .await
            .insert(routing_prefix, channel_id);
    }

    /// Look up by channel_id (mediator path: route by prefix → channel_id).
    pub async fn get_by_channel_id(&self, channel_id: &[u8; 16]) -> Option<Arc<Mutex<Channel>>> {
        self.by_channel_id.read().await.get(channel_id).cloned()
    }

    /// Look up by peer DID (application path: send a message to a peer).
    pub async fn get_by_peer_did(&self, peer_did: &str) -> Option<Arc<Mutex<Channel>>> {
        let id = *self.by_peer_did.read().await.get(peer_did)?;
        self.by_channel_id.read().await.get(&id).cloned()
    }

    /// Look up by routing prefix (mediator path: O(1) routing).
    pub async fn get_by_routing_prefix(
        &self,
        routing_prefix: &[u8; 16],
    ) -> Option<Arc<Mutex<Channel>>> {
        let id = *self.by_routing_prefix.read().await.get(routing_prefix)?;
        self.by_channel_id.read().await.get(&id).cloned()
    }

    /// Remove a channel. Zeroizing of keys happens via `Channel`'s
    /// `ZeroizeOnDrop` impl when the last Arc reference is released.
    pub async fn remove(&self, channel_id: &[u8; 16]) {
        let Some(channel) = self.by_channel_id.write().await.remove(channel_id) else {
            return;
        };
        let ch = channel.lock().await;
        self.by_peer_did.write().await.remove(&ch.peer_did);
        self.by_routing_prefix
            .write()
            .await
            .remove(&ch.peer_routing_prefix);
    }

    /// Number of active channels (for telemetry).
    pub async fn len(&self) -> usize {
        self.by_channel_id.read().await.len()
    }

    /// Whether the manager has any channels.
    pub async fn is_empty(&self) -> bool {
        self.by_channel_id.read().await.is_empty()
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcx::session::SessionKeys;

    fn sample_session() -> SessionKeys {
        SessionKeys {
            kek: [3u8; 32],
            auth_key: [4u8; 32],
            generation: 0,
            peer_kid: "did:peer:bob#key-1".into(),
            connection_id: "conn-1".into(),
            is_initiator: true,
        }
    }

    #[tokio::test]
    async fn insert_and_lookup_three_ways() {
        let mgr = ChannelManager::new();
        let ch = Channel::from_session_keys(
            &sample_session(),
            "did:bob".into(),
            "classical-x25519/1.0".into(),
            true,
        );
        let channel_id = ch.channel_id;
        let routing_prefix = ch.peer_routing_prefix;

        mgr.insert(ch).await;

        assert!(mgr.get_by_channel_id(&channel_id).await.is_some());
        assert!(mgr.get_by_peer_did("did:bob").await.is_some());
        assert!(mgr.get_by_routing_prefix(&routing_prefix).await.is_some());
        assert_eq!(mgr.len().await, 1);
    }

    #[tokio::test]
    async fn remove_clears_all_indexes() {
        let mgr = ChannelManager::new();
        let ch = Channel::from_session_keys(
            &sample_session(),
            "did:bob".into(),
            "classical-x25519/1.0".into(),
            true,
        );
        let channel_id = ch.channel_id;
        let routing_prefix = ch.peer_routing_prefix;

        mgr.insert(ch).await;
        mgr.remove(&channel_id).await;

        assert!(mgr.get_by_channel_id(&channel_id).await.is_none());
        assert!(mgr.get_by_peer_did("did:bob").await.is_none());
        assert!(mgr.get_by_routing_prefix(&routing_prefix).await.is_none());
        assert!(mgr.is_empty().await);
    }
}
