//! Blockchain Anchoring for did:ajna
//!
//! This module provides blockchain anchoring functionality to achieve finality
//! and tamper-proof consensus for DID documents.
//!
//! ## Architecture
//!
//! ```text
//! Local CRDT State (offline, eventually consistent)
//!          ↓
//!     Merkle Root
//!          ↓
//!   Anchor to Blockchain (periodic, provides finality)
//!          ↓
//!   BlockchainAnchor (tx_hash, block_number, timestamp)
//! ```
//!
//! ## Finality Model
//!
//! - **Local updates:** Immediate, offline, CRDT-based
//! - **Gossip sync:** Fast, eventual consistency within seconds
//! - **Blockchain anchor:** Periodic (e.g., hourly), provides global finality
//!
//! ## Conflict Resolution
//!
//! 1. If no blockchain anchor exists: Use CRDT merge
//! 2. If blockchain anchor exists: Anchor wins (provides finality)
//! 3. Local changes after anchor: CRDT merge on top of anchored state

use crate::ajna::{merkle_dag::Hash, AjnaError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Blockchain anchor record
///
/// This represents a DID document state that has been anchored to the blockchain
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// DID identifier
    pub did: String,

    /// Merkle root of the DID's operation history
    pub merkle_root: Hash,

    /// Blockchain transaction hash
    pub tx_hash: String,

    /// Block number where anchor was included
    pub block_number: u64,

    /// Timestamp when anchor was created
    pub timestamp: DateTime<Utc>,

    /// Network name (e.g., "ajna-mainnet", "ajna-testnet")
    pub network: String,

    /// Optional: Number of operations at time of anchor
    pub operation_count: Option<usize>,

    /// Optional: Signature from anchoring authority
    pub signature: Option<String>,
}

impl AnchorRecord {
    /// Create a new anchor record
    pub fn new(
        did: String,
        merkle_root: Hash,
        tx_hash: String,
        block_number: u64,
        network: String,
    ) -> Self {
        Self {
            did,
            merkle_root,
            tx_hash,
            block_number,
            timestamp: Utc::now(),
            network,
            operation_count: None,
            signature: None,
        }
    }

    /// Create with operation count
    pub fn with_operation_count(mut self, count: usize) -> Self {
        self.operation_count = Some(count);
        self
    }

    /// Create with signature
    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }
}

/// Blockchain anchoring service
///
/// Manages the anchoring of DID document states to the blockchain
#[derive(Clone)]
pub struct AnchoringService {
    /// Map of DID to latest anchor
    anchors: Arc<RwLock<HashMap<String, AnchorRecord>>>,

    /// Map of DID to all historical anchors
    history: Arc<RwLock<HashMap<String, Vec<AnchorRecord>>>>,

    /// Network name
    network: String,

    /// Minimum interval between anchors (in seconds)
    min_anchor_interval: u64,
}

impl AnchoringService {
    /// Create a new anchoring service
    ///
    /// # Arguments
    /// * `network` - Blockchain network name
    /// * `min_anchor_interval` - Minimum seconds between anchors (default: 3600 = 1 hour)
    pub fn new(network: String, min_anchor_interval: u64) -> Self {
        Self {
            anchors: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            network,
            min_anchor_interval,
        }
    }

    /// Check if a DID should be anchored
    ///
    /// Returns true if:
    /// - DID has never been anchored, OR
    /// - Sufficient time has passed since last anchor
    pub async fn should_anchor(&self, did: &str) -> bool {
        let anchors = self.anchors.read().await;

        match anchors.get(did) {
            None => true, // Never anchored
            Some(last_anchor) => {
                let elapsed = Utc::now()
                    .signed_duration_since(last_anchor.timestamp)
                    .num_seconds();
                elapsed >= self.min_anchor_interval as i64
            }
        }
    }

    /// Submit an anchor to the blockchain
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `merkle_root` - Merkle root of operation history
    /// * `operation_count` - Number of operations in history
    ///
    /// # Returns
    /// The created anchor record
    ///
    /// Note: This is a mock implementation. In production, this would:
    /// 1. Create a blockchain transaction
    /// 2. Submit to the network
    /// 3. Wait for confirmation
    /// 4. Return the anchor with real tx_hash and block_number
    pub async fn submit_anchor(
        &self,
        did: String,
        merkle_root: Hash,
        operation_count: usize,
    ) -> Result<AnchorRecord> {
        // Check if we should anchor
        if !self.should_anchor(&did).await {
            return Err(AjnaError::InvalidOperation(format!(
                "Too soon to anchor {}. Min interval: {} seconds",
                did, self.min_anchor_interval
            )));
        }

        // In production, this would submit to blockchain
        // For now, we'll simulate with a hash-based tx_hash
        let tx_hash = self.create_mock_tx_hash(&did, &merkle_root);
        let block_number = self.get_mock_block_number().await;

        let anchor = AnchorRecord::new(
            did.clone(),
            merkle_root,
            tx_hash,
            block_number,
            self.network.clone(),
        )
        .with_operation_count(operation_count);

        // Store anchor
        {
            let mut anchors = self.anchors.write().await;
            anchors.insert(did.clone(), anchor.clone());
        }

        // Add to history
        {
            let mut history = self.history.write().await;
            history
                .entry(did.clone())
                .or_insert_with(Vec::new)
                .push(anchor.clone());
        }

        tracing::info!(
            "⚓ Anchored {} at block {} (tx: {})",
            did,
            block_number,
            anchor.tx_hash
        );

        Ok(anchor)
    }

    /// Get the latest anchor for a DID
    pub async fn get_anchor(&self, did: &str) -> Option<AnchorRecord> {
        let anchors = self.anchors.read().await;
        anchors.get(did).cloned()
    }

    /// Get all anchors for a DID
    pub async fn get_anchor_history(&self, did: &str) -> Vec<AnchorRecord> {
        let history = self.history.read().await;
        history.get(did).cloned().unwrap_or_default()
    }

    /// Verify a Merkle root against the blockchain
    ///
    /// # Arguments
    /// * `did` - DID identifier
    /// * `merkle_root` - Merkle root to verify
    ///
    /// # Returns
    /// - `Some(true)` if merkle_root matches anchored state
    /// - `Some(false)` if merkle_root does NOT match anchored state
    /// - `None` if DID has never been anchored
    pub async fn verify_anchor(&self, did: &str, merkle_root: &Hash) -> Option<bool> {
        let anchors = self.anchors.read().await;
        anchors
            .get(did)
            .map(|anchor| &anchor.merkle_root == merkle_root)
    }

    /// Check if a DID has been anchored
    pub async fn is_anchored(&self, did: &str) -> bool {
        let anchors = self.anchors.read().await;
        anchors.contains_key(did)
    }

    /// Get statistics about anchored DIDs
    pub async fn stats(&self) -> AnchorStats {
        let anchors = self.anchors.read().await;
        let history = self.history.read().await;

        let total_anchors: usize = history.values().map(|v| v.len()).sum();

        AnchorStats {
            total_dids_anchored: anchors.len(),
            total_anchors,
            network: self.network.clone(),
        }
    }

    /// Remove all anchors (for testing)
    #[cfg(test)]
    pub async fn clear(&self) {
        let mut anchors = self.anchors.write().await;
        anchors.clear();
        let mut history = self.history.write().await;
        history.clear();
    }

    // Mock blockchain interaction methods
    // In production, these would interact with actual blockchain

    /// Create a mock transaction hash using Blake3
    fn create_mock_tx_hash(&self, did: &str, merkle_root: &Hash) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AJNA/MOCK_TX/V1"); // DST for mock transactions
        hasher.update(did.as_bytes());
        hasher.update(merkle_root.as_bytes());
        hasher.update(Utc::now().to_rfc3339().as_bytes());
        let result = hasher.finalize();
        hex::encode(result.as_bytes())
    }

    /// Get mock block number (incrementing counter)
    async fn get_mock_block_number(&self) -> u64 {
        // In production, this would query the blockchain
        // For now, use history size as a simple incrementing counter
        let history = self.history.read().await;
        let total_anchors: usize = history.values().map(|v| v.len()).sum();
        1000000 + total_anchors as u64
    }
}

/// Statistics about blockchain anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorStats {
    /// Number of unique DIDs that have been anchored
    pub total_dids_anchored: usize,

    /// Total number of anchors across all DIDs
    pub total_anchors: usize,

    /// Blockchain network name
    pub network: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_anchoring_service() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);
        assert_eq!(service.network, "ajna-testnet");
        assert_eq!(service.min_anchor_interval, 3600);
    }

    #[tokio::test]
    async fn test_should_anchor_never_anchored() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);
        assert!(service.should_anchor("did:ajna:test").await);
    }

    #[tokio::test]
    async fn test_submit_anchor() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        let did = "did:ajna:test".to_string();
        let merkle_root = "abc123".to_string();

        let anchor = service
            .submit_anchor(did.clone(), merkle_root.clone(), 5)
            .await
            .expect("Failed to submit anchor");

        assert_eq!(anchor.did, did);
        assert_eq!(anchor.merkle_root, merkle_root);
        assert_eq!(anchor.network, "ajna-testnet");
        assert_eq!(anchor.operation_count, Some(5));
        assert!(!anchor.tx_hash.is_empty());
        assert!(anchor.block_number >= 1000000);
    }

    #[tokio::test]
    async fn test_get_anchor() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        let did = "did:ajna:test".to_string();
        let merkle_root = "abc123".to_string();

        // No anchor yet
        assert!(service.get_anchor(&did).await.is_none());

        // Submit anchor
        service
            .submit_anchor(did.clone(), merkle_root.clone(), 5)
            .await
            .unwrap();

        // Get anchor
        let anchor = service.get_anchor(&did).await.expect("Anchor not found");
        assert_eq!(anchor.did, did);
        assert_eq!(anchor.merkle_root, merkle_root);
    }

    #[tokio::test]
    async fn test_verify_anchor() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        let did = "did:ajna:test".to_string();
        let merkle_root = "abc123".to_string();

        // No anchor yet
        assert!(service.verify_anchor(&did, &merkle_root).await.is_none());

        // Submit anchor
        service
            .submit_anchor(did.clone(), merkle_root.clone(), 5)
            .await
            .unwrap();

        // Verify correct root
        assert_eq!(service.verify_anchor(&did, &merkle_root).await, Some(true));

        // Verify incorrect root
        assert_eq!(
            service.verify_anchor(&did, &"wrong_root".to_string()).await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn test_anchor_history() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 0); // No interval for testing

        let did = "did:ajna:test".to_string();

        // Submit multiple anchors
        service
            .submit_anchor(did.clone(), "root1".to_string(), 1)
            .await
            .unwrap();
        service
            .submit_anchor(did.clone(), "root2".to_string(), 2)
            .await
            .unwrap();
        service
            .submit_anchor(did.clone(), "root3".to_string(), 3)
            .await
            .unwrap();

        // Get history
        let history = service.get_anchor_history(&did).await;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].merkle_root, "root1");
        assert_eq!(history[1].merkle_root, "root2");
        assert_eq!(history[2].merkle_root, "root3");
    }

    #[tokio::test]
    async fn test_min_anchor_interval() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        let did = "did:ajna:test".to_string();

        // First anchor should succeed
        service
            .submit_anchor(did.clone(), "root1".to_string(), 1)
            .await
            .expect("First anchor should succeed");

        // Second anchor immediately should fail
        let result = service
            .submit_anchor(did.clone(), "root2".to_string(), 2)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_anchored() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        let did = "did:ajna:test".to_string();

        // Not anchored yet
        assert!(!service.is_anchored(&did).await);

        // Submit anchor
        service
            .submit_anchor(did.clone(), "root1".to_string(), 1)
            .await
            .unwrap();

        // Now anchored
        assert!(service.is_anchored(&did).await);
    }

    #[tokio::test]
    async fn test_anchor_stats() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 0);

        // Submit anchors for multiple DIDs
        service
            .submit_anchor("did:ajna:test1".to_string(), "root1".to_string(), 1)
            .await
            .unwrap();
        service
            .submit_anchor("did:ajna:test2".to_string(), "root2".to_string(), 2)
            .await
            .unwrap();
        service
            .submit_anchor("did:ajna:test1".to_string(), "root3".to_string(), 3)
            .await
            .unwrap();

        let stats = service.stats().await;
        assert_eq!(stats.total_dids_anchored, 2);
        assert_eq!(stats.total_anchors, 3);
        assert_eq!(stats.network, "ajna-testnet");
    }

    #[tokio::test]
    async fn test_multiple_dids() {
        let service = AnchoringService::new("ajna-testnet".to_string(), 3600);

        // Anchor multiple DIDs
        service
            .submit_anchor("did:ajna:alice".to_string(), "root_alice".to_string(), 5)
            .await
            .unwrap();
        service
            .submit_anchor("did:ajna:bob".to_string(), "root_bob".to_string(), 3)
            .await
            .unwrap();

        // Verify both anchors exist independently
        let alice_anchor = service.get_anchor("did:ajna:alice").await.unwrap();
        let bob_anchor = service.get_anchor("did:ajna:bob").await.unwrap();

        assert_eq!(alice_anchor.merkle_root, "root_alice");
        assert_eq!(alice_anchor.operation_count, Some(5));

        assert_eq!(bob_anchor.merkle_root, "root_bob");
        assert_eq!(bob_anchor.operation_count, Some(3));
    }
}
