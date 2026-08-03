//! Peer Discovery System
//!
//! Enables agents to automatically discover nearby did:ajna agents using:
//! - mDNS local network discovery (✅ requires `discovery` feature)
//! - BLE proximity discovery (✅ requires `discovery` feature)

// Hardware-based discovery requires native dependencies (not WASM compatible)
#[cfg(feature = "discovery")]
pub mod ble;
#[cfg(feature = "discovery")]
pub mod mdns;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Information about a discovered peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's DID
    pub did: String,

    /// Endpoint (HTTP, WebSocket, BLE, etc.)
    pub endpoint: String,

    /// Capabilities supported by peer
    pub capabilities: Vec<String>,

    /// When discovered
    pub discovered_at: DateTime<Utc>,

    /// Discovery method
    pub discovery_method: DiscoveryMethod,

    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
}

/// Method used to discover a peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiscoveryMethod {
    /// Discovered via mDNS (local network)
    Mdns,
    /// Discovered via Bluetooth Low Energy
    Ble,
    /// Manually added by user
    Manual,
}

/// Storage for discovered peers
#[derive(Clone)]
pub struct DiscoveredPeers {
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
}

impl DiscoveredPeers {
    /// Create new empty peer storage
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add or update a discovered peer
    pub async fn add_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.write().await;
        peers.insert(peer.did.clone(), peer);
    }

    /// Get information about a specific peer
    pub async fn get_peer(&self, did: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(did).cloned()
    }

    /// Get all discovered peers
    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Update last seen timestamp for a peer
    pub async fn update_last_seen(&self, did: &str) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(did) {
            peer.last_seen = Utc::now();
        }
    }

    /// Remove a peer
    pub async fn remove_peer(&self, did: &str) -> Option<PeerInfo> {
        let mut peers = self.peers.write().await;
        peers.remove(did)
    }

    /// Get number of discovered peers
    pub async fn count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Remove peers not seen since given timestamp
    pub async fn prune_stale_peers(&self, older_than: DateTime<Utc>) -> usize {
        let mut peers = self.peers.write().await;
        let before_count = peers.len();

        peers.retain(|_, peer| peer.last_seen > older_than);

        before_count - peers.len()
    }
}

impl Default for DiscoveredPeers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_peer() {
        let discovered = DiscoveredPeers::new();

        let peer = PeerInfo {
            did: "did:ajna:test123".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            capabilities: vec!["did_sync".to_string()],
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now(),
        };

        discovered.add_peer(peer.clone()).await;

        let retrieved = discovered.get_peer("did:ajna:test123").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().did, "did:ajna:test123");
    }

    #[tokio::test]
    async fn test_all_peers() {
        let discovered = DiscoveredPeers::new();

        let peer1 = PeerInfo {
            did: "did:ajna:peer1".to_string(),
            endpoint: "http://localhost:3001".to_string(),
            capabilities: vec![],
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now(),
        };

        let peer2 = PeerInfo {
            did: "did:ajna:peer2".to_string(),
            endpoint: "http://localhost:3002".to_string(),
            capabilities: vec![],
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now(),
        };

        discovered.add_peer(peer1).await;
        discovered.add_peer(peer2).await;

        let all = discovered.all_peers().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_update_last_seen() {
        let discovered = DiscoveredPeers::new();

        let peer = PeerInfo {
            did: "did:ajna:test".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            capabilities: vec![],
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now() - chrono::Duration::hours(1),
        };

        discovered.add_peer(peer.clone()).await;

        let before = discovered.get_peer("did:ajna:test").await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        discovered.update_last_seen("did:ajna:test").await;

        let after = discovered.get_peer("did:ajna:test").await.unwrap();

        assert!(after.last_seen > before.last_seen);
    }

    #[tokio::test]
    async fn test_prune_stale_peers() {
        let discovered = DiscoveredPeers::new();

        let old_peer = PeerInfo {
            did: "did:ajna:old".to_string(),
            endpoint: "http://localhost:3000".to_string(),
            capabilities: vec![],
            discovered_at: Utc::now() - chrono::Duration::hours(2),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now() - chrono::Duration::hours(2),
        };

        let fresh_peer = PeerInfo {
            did: "did:ajna:fresh".to_string(),
            endpoint: "http://localhost:3001".to_string(),
            capabilities: vec![],
            discovered_at: Utc::now(),
            discovery_method: DiscoveryMethod::Manual,
            last_seen: Utc::now(),
        };

        discovered.add_peer(old_peer).await;
        discovered.add_peer(fresh_peer).await;

        let pruned = discovered
            .prune_stale_peers(Utc::now() - chrono::Duration::hours(1))
            .await;

        assert_eq!(pruned, 1);
        assert_eq!(discovered.count().await, 1);
        assert!(discovered.get_peer("did:ajna:fresh").await.is_some());
        assert!(discovered.get_peer("did:ajna:old").await.is_none());
    }
}
