//! DHT Provider implementations for DID resolution
//!
//! This module provides concrete implementations of the DhtProvider trait
//! for use with the ResolutionService.

use crate::ajna::resolver::DhtProvider;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// Re-export the DHT from kademlia crate
// Note: Cargo normalizes ajna-kademlia to ajna_kademlia for Rust imports
pub use ajna_kademlia::dht::KademliaDHT;

/// Wrapper around KademliaDHT that implements the DhtProvider trait
///
/// This provides a clean abstraction layer between the idiom resolver
/// and the Kademlia DHT implementation.
pub struct KademliaDhtProvider {
    dht: Arc<KademliaDHT>,
}

impl KademliaDhtProvider {
    /// Create a new KademliaDhtProvider wrapping an existing DHT instance
    ///
    /// The DHT uses internal locking so no external RwLock is needed.
    pub fn new(dht: Arc<KademliaDHT>) -> Self {
        Self { dht }
    }

    /// Create from a raw DHT (wraps in Arc)
    pub fn from_dht(dht: KademliaDHT) -> Self {
        Self { dht: Arc::new(dht) }
    }

    /// Get a reference to the underlying DHT
    pub fn dht(&self) -> &Arc<KademliaDHT> {
        &self.dht
    }
}

impl DhtProvider for KademliaDhtProvider {
    fn get_value(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + '_>> {
        let did = did.to_string();
        Box::pin(async move { self.dht.get_value(&did).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajna_kademlia::config::KademliaConfig;

    #[tokio::test]
    async fn test_kademlia_dht_provider() {
        // Create a test DHT
        let config = KademliaConfig::default();
        let dht = KademliaDHT::new("did:ajna:test_node".to_string(), config);

        // Wrap in provider
        let provider = KademliaDhtProvider::from_dht(dht);

        // Query non-existent DID (should return None since no storage)
        let result = provider.get_value("did:ajna:nonexistent").await;
        assert!(result.is_none());
    }
}
