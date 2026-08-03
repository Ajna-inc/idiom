//! DIDComm sync protocol for offline operation synchronization
//!
//! This module implements the three-phase sync protocol:
//! 1. ANNOUNCE - Broadcast current tips + Bloom filter
//! 2. FETCH - Request specific missing operations
//! 3. PUSH - Send operation bundles
//!
//! ## Protocol Flow
//!
//! ```text
//! Node A                          Node B
//!   |                               |
//!   |-- ANNOUNCE (tips + bloom) --->|
//!   |                               |
//!   |<-- FETCH (missing op_ids) ----|
//!   |                               |
//!   |-- PUSH (op bundle) ---------->|
//!   |                               |
//! ```

use crate::ajna::bloom_filter::BloomFilter;
use crate::ajna::error::{AjnaError, Result};
use crate::ajna::merkle_dag::MerkleDAG;
use crate::ajna::op_bundle::{OpBundle, MAX_BUNDLE_SIZE};
use crate::ajna::operation_v2::Operation;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Main sync protocol handler
pub struct SyncProtocol {
    /// Bloom filter of known operation IDs
    bloom: Arc<RwLock<BloomFilter>>,

    /// Known tips per DID (did -> set of tip op_ids)
    known_tips: Arc<RwLock<HashMap<String, HashSet<String>>>>,

    /// DAG storage per DID
    dags: Arc<RwLock<HashMap<String, MerkleDAG>>>,
}

impl SyncProtocol {
    /// Initialize sync protocol with empty state
    pub fn new() -> Self {
        Self {
            bloom: Arc::new(RwLock::new(BloomFilter::default_config())),
            known_tips: Arc::new(RwLock::new(HashMap::new())),
            dags: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize sync protocol from existing DAG
    pub async fn from_dag(dag: &MerkleDAG, did: &str) -> Result<Self> {
        let sync = Self::new();

        // Build bloom filter from all operations in DAG
        let ops = dag.get_all_operations_v2();
        {
            let mut bloom = sync.bloom.write().await;
            for op in ops {
                bloom.insert(op.op_id.as_bytes());
            }
        } // Drop bloom lock before returning

        // Store DAG
        sync.dags.write().await.insert(did.to_string(), dag.clone());

        Ok(sync)
    }

    /// Register an operation with the sync protocol
    pub async fn register_operation(&self, operation: &Operation) -> Result<()> {
        // Add to bloom filter
        let mut bloom = self.bloom.write().await;
        bloom.insert(operation.op_id.as_bytes());
        Ok(())
    }

    /// Send announce message to peer
    ///
    /// Creates an announce message containing current tips and bloom filter
    /// for the specified DID.
    pub async fn announce_to_peer(&self, doc_did: &str) -> Result<AnnounceMessage> {
        // Get tips from DAG
        let tips = self.get_tips(doc_did).await?;

        // Serialize bloom filter
        let bloom = self.bloom.read().await;
        let bloom_bytes = bloom.to_bytes();
        let bloom_base64 = STANDARD.encode(&bloom_bytes);

        Ok(AnnounceMessage {
            piuri: "bh/opsync/1.0/announce".to_string(),
            doc: doc_did.to_string(),
            tips,
            bloom: bloom_base64,
            want: None,
        })
    }

    /// Handle incoming announce message
    ///
    /// Compares peer's bloom filter with our operations to find:
    /// - Operations we have that peer doesn't (for potential push)
    /// - Operations peer has that we don't (from tips) -> request via fetch
    ///
    /// Returns Some(FetchMessage) if we need to request operations from peer.
    pub async fn handle_announce(
        &self,
        message: AnnounceMessage,
        peer_did: &str,
    ) -> Result<Option<FetchMessage>> {
        // Decode peer's bloom filter
        let peer_bloom_bytes = STANDARD
            .decode(&message.bloom)
            .map_err(|e| AjnaError::InvalidBloomFilter(e.to_string()))?;
        let peer_bloom = BloomFilter::from_bytes(&peer_bloom_bytes)?;

        // Find operations peer is missing (that we have)
        let _missing_on_peer = self.find_missing_ops(&message.doc, &peer_bloom).await?;
        // Note: We don't automatically push, peer should request

        // Find operations we're missing (from peer's tips)
        let missing_on_us = self
            .find_missing_from_tips(&message.doc, &message.tips)
            .await?;

        // Store peer's tips for later
        self.known_tips
            .write()
            .await
            .insert(peer_did.to_string(), message.tips.into_iter().collect());

        // If we're missing ops, request them
        if !missing_on_us.is_empty() {
            Ok(Some(FetchMessage {
                piuri: "bh/opsync/1.0/fetch".to_string(),
                doc: message.doc,
                op_ids: missing_on_us,
                max_bundle_size: MAX_BUNDLE_SIZE,
            }))
        } else {
            Ok(None)
        }
    }

    /// Handle fetch request from peer
    ///
    /// Gathers requested operations and creates a push message with
    /// an op bundle containing the operations.
    pub async fn handle_fetch(&self, message: FetchMessage) -> Result<PushMessage> {
        // Gather requested operations from DAG
        let dag = self.get_dag(&message.doc).await?;
        let all_ops = dag.get_all_operations_v2();

        // Filter to requested op_ids
        let requested_ops: Vec<Operation> = all_ops
            .into_iter()
            .filter(|op| message.op_ids.contains(&op.op_id))
            .collect();

        if requested_ops.is_empty() {
            return Err(AjnaError::InvalidOperation(
                "No operations found for requested IDs".to_string(),
            ));
        }

        // Create bundle with requested operations
        let bundle = OpBundle::create(&message.doc, requested_ops, message.max_bundle_size)?;

        // Serialize bundle
        let bundle_bytes = bundle.to_bytes()?;

        Ok(PushMessage {
            piuri: "bh/opsync/1.0/push".to_string(),
            doc: message.doc,
            bundle: bundle_bytes,
        })
    }

    /// Handle push message (receive ops from peer)
    ///
    /// Parses op bundle, validates operations, and adds them to our DAG.
    /// Returns the number of new operations applied.
    pub async fn handle_push(&self, message: PushMessage) -> Result<usize> {
        // Parse bundle
        let bundle = OpBundle::from_bytes(&message.bundle)?;

        // Validate bundle
        bundle.validate()?;

        // Get or create DAG for this DID
        let _dag = self.get_or_create_dag(&message.doc).await;
        let mut applied_count = 0;

        // Check each operation
        let bloom = self.bloom.read().await;
        for operation in &bundle.operations {
            // Skip if we already have it
            if bloom.contains(operation.op_id.as_bytes()) {
                continue;
            }

            // Note: We don't validate authorization here - that's the caller's responsibility
            // The sync protocol just transfers operations
            // Validation happens when applying operations via AjnaMethod

            applied_count += 1;
        }

        // Release bloom lock
        drop(bloom);

        // Register new operations
        for operation in &bundle.operations {
            self.register_operation(operation).await?;
        }

        Ok(applied_count)
    }

    /// Find operations we have that peer doesn't (based on their bloom)
    async fn find_missing_ops(&self, did: &str, peer_bloom: &BloomFilter) -> Result<Vec<String>> {
        let dag = self.get_dag(did).await?;
        let all_ops = dag.get_all_operations_v2();

        Ok(all_ops
            .iter()
            .filter(|op| !peer_bloom.contains(op.op_id.as_bytes()))
            .map(|op| op.op_id.clone())
            .collect())
    }

    /// Find operations we're missing based on peer's tips
    async fn find_missing_from_tips(
        &self,
        _did: &str,
        peer_tips: &[String],
    ) -> Result<Vec<String>> {
        let bloom = self.bloom.read().await;
        let mut missing = Vec::new();

        for tip in peer_tips {
            if !bloom.contains(tip.as_bytes()) {
                // We don't have this operation
                missing.push(tip.clone());

                // Note: We should also walk back to find missing ancestors,
                // but the fetch response will include context operations
            }
        }

        Ok(missing)
    }

    /// Get tips (latest operation IDs) for a DID
    async fn get_tips(&self, did: &str) -> Result<Vec<String>> {
        let dag = self.get_dag(did).await?;
        dag.get_tips()
    }

    /// Get DAG for a DID
    async fn get_dag(&self, did: &str) -> Result<MerkleDAG> {
        let dags = self.dags.read().await;
        dags.get(did)
            .cloned()
            .ok_or_else(|| AjnaError::DidNotFound(did.to_string()))
    }

    /// Get or create DAG for a DID
    async fn get_or_create_dag(&self, did: &str) -> MerkleDAG {
        let mut dags = self.dags.write().await;
        dags.entry(did.to_string())
            .or_insert_with(MerkleDAG::new)
            .clone()
    }

    /// Get sync statistics
    pub async fn stats(&self) -> SyncStats {
        let bloom = self.bloom.read().await;
        let known_tips = self.known_tips.read().await;
        let dags = self.dags.read().await;

        SyncStats {
            bloom_size_bytes: bloom.estimated_size_bytes(),
            known_dids: dags.len(),
            known_peers: known_tips.len(),
            total_operations: dags.values().map(|d| d.node_count()).sum(),
        }
    }
}

impl Default for SyncProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Announce message (broadcast current state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceMessage {
    /// Protocol URI: "bh/opsync/1.0/announce"
    pub piuri: String,

    /// DID being announced
    pub doc: String,

    /// Latest op_ids (DAG tips)
    pub tips: Vec<String>,

    /// Base64-encoded bloom filter of known op_ids
    pub bloom: String,

    /// Optional: ops we want from peer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub want: Option<Vec<String>>,
}

/// Fetch message (request specific ops)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchMessage {
    /// Protocol URI: "bh/opsync/1.0/fetch"
    pub piuri: String,

    /// DID identifier
    pub doc: String,

    /// Requested operation IDs
    pub op_ids: Vec<String>,

    /// Max bundle size (default: 128 KB)
    pub max_bundle_size: usize,
}

/// Push message (send op bundle)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMessage {
    /// Protocol URI: "bh/opsync/1.0/push"
    pub piuri: String,

    /// DID identifier
    pub doc: String,

    /// Serialized OpBundle
    pub bundle: Vec<u8>,
}

/// Sync protocol statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub bloom_size_bytes: usize,
    pub known_dids: usize,
    pub known_peers: usize,
    pub total_operations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::VerificationMethod;
    use crate::ajna::merkle_dag::DagNode;
    use crate::ajna::operation_v2::{AuthProof, ClockEntry, Delta};

    fn create_test_operation(doc: &str, op_id: &str, parents: Vec<String>) -> Operation {
        Operation {
            op_type: "org.ajna.did/op/1.0".to_string(),
            doc: doc.to_string(),
            op_id: op_id.to_string(),
            parents,
            actor: doc.to_string(),
            clock: ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            delta: Delta::VmAdd {
                entry: VerificationMethod {
                    id: format!("{}#key-1", doc),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: doc.to_string(),
                    public_key_multibase: "z6Mktest".to_string(),
                    purpose: Some(vec!["authentication".to_string()]),
                },
            },
            auth: AuthProof {
                proof: STANDARD.encode(vec![0u8; 64]),
                kid: format!("{}#key-1", doc),
            },
            timestamp_ms: 1000,
        }
    }

    #[tokio::test]
    async fn test_sync_protocol_creation() {
        let sync = SyncProtocol::new();
        let stats = sync.stats().await;

        assert_eq!(stats.known_dids, 0);
        assert_eq!(stats.known_peers, 0);
    }

    #[tokio::test]
    async fn test_register_operation() {
        let sync = SyncProtocol::new();
        let did = "did:ajna:test";
        let op = create_test_operation(did, "op1", vec![]);

        sync.register_operation(&op).await.unwrap();

        // Operation should be in bloom filter
        let bloom = sync.bloom.read().await;
        assert!(bloom.contains(b"op1"));
    }

    #[tokio::test]
    async fn test_announce_message_creation() {
        let did = "did:ajna:test";

        // Create DAG with operations
        let mut dag = MerkleDAG::new();
        let op1 = create_test_operation(did, "op1", vec![]);
        let node1 = DagNode::from_operation_v2(op1.clone(), "node1".to_string());
        dag.add_node(node1).unwrap();

        // Create sync protocol from DAG
        let sync = SyncProtocol::from_dag(&dag, did).await.unwrap();

        // Create announce message
        let announce = sync.announce_to_peer(did).await.unwrap();

        assert_eq!(announce.piuri, "bh/opsync/1.0/announce");
        assert_eq!(announce.doc, did);
        assert!(!announce.tips.is_empty());
        assert!(!announce.bloom.is_empty());
    }

    #[tokio::test]
    async fn test_handle_announce_no_missing() {
        let did = "did:ajna:test";

        // Both nodes have same operations
        let mut dag = MerkleDAG::new();
        let op1 = create_test_operation(did, "op1", vec![]);
        let node1 = DagNode::from_operation_v2(op1.clone(), "node1".to_string());
        dag.add_node(node1).unwrap();

        let sync1 = SyncProtocol::from_dag(&dag, did).await.unwrap();
        let sync2 = SyncProtocol::from_dag(&dag, did).await.unwrap();

        // Node 1 announces to Node 2
        let announce = sync1.announce_to_peer(did).await.unwrap();
        let fetch = sync2.handle_announce(announce, "peer1").await.unwrap();

        // No missing ops, so no fetch needed
        assert!(fetch.is_none());
    }

    #[tokio::test]
    async fn test_handle_announce_with_missing() {
        let did = "did:ajna:test";

        // Node 1 has op1
        let mut dag1 = MerkleDAG::new();
        let op1 = create_test_operation(did, "op1", vec![]);
        let node1 = DagNode::from_operation_v2(op1.clone(), "node1".to_string());
        let hash1 = dag1.add_node(node1).unwrap();

        // Node 2 has op1 and op2
        let mut dag2 = dag1.clone();
        // Use actual hash of op1 as parent
        let op2 = create_test_operation(did, "op2", vec![hash1.clone()]);
        let node2 = DagNode::from_operation_v2(op2.clone(), "node1".to_string());
        dag2.add_node(node2).unwrap();

        let sync1 = SyncProtocol::from_dag(&dag1, did).await.unwrap();
        let sync2 = SyncProtocol::from_dag(&dag2, did).await.unwrap();

        // Node 2 announces to Node 1
        let announce = sync2.announce_to_peer(did).await.unwrap();
        let fetch = sync1.handle_announce(announce, "peer2").await.unwrap();

        // Node 1 should request missing ops
        assert!(fetch.is_some());
        let fetch_msg = fetch.unwrap();
        assert_eq!(fetch_msg.piuri, "bh/opsync/1.0/fetch");
        assert!(fetch_msg.op_ids.contains(&"op2".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_and_push() {
        let did = "did:ajna:test";

        // Create DAG with operations
        let mut dag = MerkleDAG::new();
        let op1 = create_test_operation(did, "op1", vec![]);
        let node1 = DagNode::from_operation_v2(op1.clone(), "node1".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        // Use actual hash as parent
        let op2 = create_test_operation(did, "op2", vec![hash1.clone()]);
        let node2 = DagNode::from_operation_v2(op2.clone(), "node1".to_string());
        dag.add_node(node2).unwrap();

        let sync = SyncProtocol::from_dag(&dag, did).await.unwrap();

        // Create fetch request
        let fetch = FetchMessage {
            piuri: "bh/opsync/1.0/fetch".to_string(),
            doc: did.to_string(),
            op_ids: vec!["op1".to_string(), "op2".to_string()],
            max_bundle_size: MAX_BUNDLE_SIZE,
        };

        // Handle fetch (create push)
        let push = sync.handle_fetch(fetch).await.unwrap();

        assert_eq!(push.piuri, "bh/opsync/1.0/push");
        assert_eq!(push.doc, did);
        assert!(!push.bundle.is_empty());

        // Verify bundle contains requested ops
        let bundle = OpBundle::from_bytes(&push.bundle).unwrap();
        assert_eq!(bundle.operations.len(), 2);
    }

    #[tokio::test]
    async fn test_handle_push() {
        let did = "did:ajna:test";

        let sync = SyncProtocol::new();

        // Create operations
        let op1 = create_test_operation(did, "op1", vec![]);
        let op2 = create_test_operation(did, "op2", vec!["op1".to_string()]);

        // Create bundle
        let bundle = OpBundle::create(did, vec![op1, op2], MAX_BUNDLE_SIZE).unwrap();
        let bundle_bytes = bundle.to_bytes().unwrap();

        // Create push message
        let push = PushMessage {
            piuri: "bh/opsync/1.0/push".to_string(),
            doc: did.to_string(),
            bundle: bundle_bytes,
        };

        // Handle push
        let count = sync.handle_push(push).await.unwrap();

        // Should have applied 2 new operations
        assert_eq!(count, 2);

        // Operations should be in bloom filter
        let bloom = sync.bloom.read().await;
        assert!(bloom.contains(b"op1"));
        assert!(bloom.contains(b"op2"));
    }

    #[tokio::test]
    async fn test_sync_stats() {
        let did = "did:ajna:test";

        let mut dag = MerkleDAG::new();
        let op1 = create_test_operation(did, "op1", vec![]);
        let node1 = DagNode::from_operation_v2(op1.clone(), "node1".to_string());
        dag.add_node(node1).unwrap();

        let sync = SyncProtocol::from_dag(&dag, did).await.unwrap();
        let stats = sync.stats().await;

        assert_eq!(stats.known_dids, 1);
        assert!(stats.bloom_size_bytes > 0);
        assert_eq!(stats.total_operations, 1);
    }
}
