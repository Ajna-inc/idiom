//! Merkle-DAG for tracking DID operation history
//!
//! This module implements a Merkle Directed Acyclic Graph (DAG) for
//! storing and verifying the history of CRDT operations on a DID document.
//!
//! Uses Blake3 with domain separation

use crate::ajna::{crypto, operation_v2, operations::CRDTOperation, AjnaError, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Hash type for Merkle-DAG nodes (base64url-encoded Blake3 hash)
pub type Hash = String;

/// Operation storage - supports both legacy and v2 operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationStorage {
    /// Legacy CRDT operations (for backward compatibility)
    Legacy(Vec<CRDTOperation>),

    /// operation_v2 (single operation per node).
    /// Boxed because `Operation` is far larger than the `Legacy` variant.
    V2(Box<operation_v2::Operation>),
}

/// Node in the Merkle-DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Operations in this node
    pub operations: OperationStorage,

    /// Timestamp when this node was created
    pub timestamp: DateTime<Utc>,

    /// Parent node hashes (for merge commits, can have multiple parents)
    pub parents: Vec<Hash>,

    /// Hash of this node
    pub hash: Hash,

    /// Node ID that created this node
    pub node_id: String,
}

impl DagNode {
    /// Create a new DAG node (legacy - for backward compatibility)
    pub fn new(operations: Vec<CRDTOperation>, parents: Vec<Hash>, node_id: String) -> Self {
        let timestamp = Utc::now();
        let ops_storage = OperationStorage::Legacy(operations);
        let hash = Self::compute_hash(&ops_storage, &parents, &timestamp, &node_id);

        Self {
            operations: ops_storage,
            timestamp,
            parents,
            hash,
            node_id,
        }
    }

    /// Create a new DAG node from operation_v2
    ///
    /// One operation per node
    pub fn from_operation_v2(operation: operation_v2::Operation, node_id: String) -> Self {
        // Use operation's own timestamp
        let timestamp = chrono::Utc
            .timestamp_millis_opt(operation.timestamp_ms)
            .unwrap();

        // Use operation's parents
        let parents = operation.parents.clone();

        let ops_storage = OperationStorage::V2(Box::new(operation));
        let hash = Self::compute_hash(&ops_storage, &parents, &timestamp, &node_id);

        Self {
            operations: ops_storage,
            timestamp,
            parents,
            hash,
            node_id,
        }
    }

    /// Compute the hash of a DAG node using Blake3 with domain separation
    ///
    /// Uses DST_AJNA_ROOT
    fn compute_hash(
        operations: &OperationStorage,
        parents: &[Hash],
        timestamp: &DateTime<Utc>,
        node_id: &str,
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();

        // Add domain separation tag
        hasher.update(crypto::DST_AJNA_ROOT);

        // Hash operations (canonical JSON)
        match operations {
            OperationStorage::Legacy(ops) => {
                for op in ops {
                    if let Ok(op_json) = serde_json::to_string(op) {
                        hasher.update(op_json.as_bytes());
                    }
                }
            }
            OperationStorage::V2(op) => {
                // For v2, use the op_id which is already a canonical hash
                hasher.update(op.op_id.as_bytes());
            }
        }

        // Hash parents
        for parent in parents {
            hasher.update(parent.as_bytes());
        }

        // Hash timestamp
        hasher.update(timestamp.to_rfc3339().as_bytes());

        // Hash node ID
        hasher.update(node_id.as_bytes());

        // Return base64url-encoded hash
        let hash_bytes = hasher.finalize();
        crypto::hash_to_base64url(hash_bytes.as_bytes())
    }

    /// Verify the hash of this node
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            &self.operations,
            &self.parents,
            &self.timestamp,
            &self.node_id,
        );
        computed == self.hash
    }

    /// Get all operations from this node (helper for legacy code)
    pub fn get_operations(&self) -> Vec<CRDTOperation> {
        match &self.operations {
            OperationStorage::Legacy(ops) => ops.clone(),
            OperationStorage::V2(_) => vec![], // V2 ops don't map to legacy
        }
    }

    /// Get operation_v2 if this is a V2 node
    pub fn get_operation_v2(&self) -> Option<&operation_v2::Operation> {
        match &self.operations {
            OperationStorage::V2(op) => Some(op.as_ref()),
            OperationStorage::Legacy(_) => None,
        }
    }
}

/// Merkle-DAG for tracking operation history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleDAG {
    /// All nodes in the DAG (hash -> node)
    nodes: HashMap<Hash, DagNode>,

    /// Current head nodes (tips of the DAG)
    heads: HashSet<Hash>,

    /// Genesis node hash (root of the DAG)
    genesis: Option<Hash>,
}

impl MerkleDAG {
    /// Create a new empty Merkle-DAG
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            heads: HashSet::new(),
            genesis: None,
        }
    }

    /// Add a node to the DAG
    pub fn add_node(&mut self, node: DagNode) -> Result<Hash> {
        // Verify hash
        if !node.verify_hash() {
            return Err(AjnaError::MerkleDag("Invalid node hash".to_string()));
        }

        // Verify parents exist (except for genesis)
        if !node.parents.is_empty() {
            for parent in &node.parents {
                if !self.nodes.contains_key(parent) {
                    return Err(AjnaError::MerkleDag(format!(
                        "Parent node not found: {}",
                        parent
                    )));
                }
            }
        }

        let hash = node.hash.clone();

        // If this is the first node, it's the genesis
        if self.nodes.is_empty() {
            self.genesis = Some(hash.clone());
        }

        // Remove parents from heads (they're no longer tips)
        for parent in &node.parents {
            self.heads.remove(parent);
        }

        // Add this node as a new head
        self.heads.insert(hash.clone());

        // Store the node
        self.nodes.insert(hash.clone(), node);

        Ok(hash)
    }

    /// Get a node by hash
    pub fn get_node(&self, hash: &Hash) -> Option<&DagNode> {
        self.nodes.get(hash)
    }

    /// Get all head nodes (current tips)
    pub fn get_heads(&self) -> Vec<&DagNode> {
        self.heads
            .iter()
            .filter_map(|hash| self.nodes.get(hash))
            .collect()
    }

    /// Get the genesis node
    pub fn get_genesis(&self) -> Option<&DagNode> {
        self.genesis.as_ref().and_then(|hash| self.nodes.get(hash))
    }

    /// Get all nodes in topological order (parents before children)
    pub fn topological_sort(&self) -> Vec<&DagNode> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_mark = HashSet::new();

        // Start from genesis if it exists
        if let Some(genesis_hash) = &self.genesis {
            self.visit_node(genesis_hash, &mut visited, &mut temp_mark, &mut result);
        }

        // Reverse to get parents before children (DFS gives us post-order)
        result.reverse();
        result
    }

    /// DFS visit for topological sort
    fn visit_node<'a>(
        &'a self,
        hash: &Hash,
        visited: &mut HashSet<Hash>,
        temp_mark: &mut HashSet<Hash>,
        result: &mut Vec<&'a DagNode>,
    ) {
        if visited.contains(hash) {
            return;
        }

        if temp_mark.contains(hash) {
            // Cycle detected (shouldn't happen in a DAG)
            return;
        }

        temp_mark.insert(hash.clone());

        // Visit children first (find all nodes that have this as parent)
        for (child_hash, child_node) in &self.nodes {
            if child_node.parents.contains(hash) {
                self.visit_node(child_hash, visited, temp_mark, result);
            }
        }

        temp_mark.remove(hash);
        visited.insert(hash.clone());

        if let Some(node) = self.nodes.get(hash) {
            result.push(node);
        }
    }

    /// Compute the Merkle root (hash of all head nodes combined)
    ///
    /// Uses Blake3 with DST_AJNA_ROOT
    pub fn compute_root(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        // Add domain separation tag
        hasher.update(crypto::DST_AJNA_ROOT);

        // Sort heads for deterministic ordering
        let mut heads: Vec<_> = self.heads.iter().collect();
        heads.sort();

        for head in heads {
            hasher.update(head.as_bytes());
        }

        // Return base64url-encoded hash
        let hash_bytes = hasher.finalize();
        crypto::hash_to_base64url(hash_bytes.as_bytes())
    }

    /// Get all operations in chronological order (legacy only)
    pub fn get_all_operations(&self) -> Vec<CRDTOperation> {
        let sorted_nodes = self.topological_sort();
        sorted_nodes
            .into_iter()
            .flat_map(|node| node.get_operations())
            .collect()
    }

    /// Get all operation_v2 operations in chronological order
    pub fn get_all_operations_v2(&self) -> Vec<operation_v2::Operation> {
        let sorted_nodes = self.topological_sort();
        sorted_nodes
            .into_iter()
            .filter_map(|node| node.get_operation_v2().cloned())
            .collect()
    }

    /// Get tips (latest operation IDs) from head nodes
    ///
    /// Returns operation IDs from all head nodes (current tips of the DAG).
    /// This is used for sync protocol to announce current state.
    pub fn get_tips(&self) -> Result<Vec<String>> {
        let heads = self.get_heads();
        let tips: Vec<String> = heads
            .into_iter()
            .map(|node| match &node.operations {
                OperationStorage::V2(op) => op.op_id.clone(),
                // For legacy nodes, use the node hash as tip
                OperationStorage::Legacy(_) => node.hash.clone(),
            })
            .collect();

        Ok(tips)
    }

    /// Merge another DAG into this one
    pub fn merge(&mut self, other: &MerkleDAG) -> Result<()> {
        // Add all nodes from other DAG
        // Sort by timestamp to add in order
        let mut other_nodes: Vec<_> = other.nodes.values().collect();
        other_nodes.sort_by_key(|n| n.timestamp);

        for node in other_nodes {
            // Check if we already have this node
            if self.nodes.contains_key(&node.hash) {
                continue;
            }

            // Verify all parents exist or will be added
            let mut missing_parents = false;
            for parent in &node.parents {
                if !self.nodes.contains_key(parent) && !other.nodes.contains_key(parent) {
                    missing_parents = true;
                    break;
                }
            }

            if missing_parents {
                continue; // Skip nodes with missing parents for now
            }

            self.add_node(node.clone())?;
        }

        Ok(())
    }

    /// Get the number of nodes in the DAG
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the DAG is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get the number of nodes (alias for len())
    pub fn node_count(&self) -> usize {
        self.len()
    }

    /// Get all node hashes
    pub fn get_all_hashes(&self) -> Vec<Hash> {
        self.nodes.keys().cloned().collect()
    }

    /// Check if a node exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.nodes.contains_key(hash)
    }
}

impl Default for MerkleDAG {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::VerificationMethod;

    fn create_test_operation() -> CRDTOperation {
        create_test_operation_with_id("key-1")
    }

    fn create_test_operation_with_id(key_id: &str) -> CRDTOperation {
        let method = VerificationMethod {
            id: format!("did:ajna:test#{}", key_id),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: "did:ajna:test".to_string(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: Some(vec!["authentication".to_string()]),
        };
        // Use a fixed timestamp for deterministic hashing in tests
        use chrono::TimeZone;
        let fixed_timestamp = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        CRDTOperation::AddVerificationMethod {
            method,
            timestamp: fixed_timestamp,
            node_id: "node_a".to_string(),
        }
    }

    #[test]
    fn test_create_dag() {
        let dag = MerkleDAG::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
    }

    #[test]
    fn test_add_genesis_node() {
        let mut dag = MerkleDAG::new();

        let op = create_test_operation();
        let node = DagNode::new(vec![op], vec![], "node_a".to_string());

        let hash = dag.add_node(node.clone()).unwrap();

        assert_eq!(dag.len(), 1);
        assert_eq!(dag.get_genesis().unwrap().hash, hash);
        assert_eq!(dag.get_heads().len(), 1);
    }

    #[test]
    fn test_add_child_node() {
        let mut dag = MerkleDAG::new();

        // Add genesis
        let op1 = create_test_operation();
        let node1 = DagNode::new(vec![op1], vec![], "node_a".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        // Add child
        let op2 = create_test_operation();
        let node2 = DagNode::new(vec![op2], vec![hash1.clone()], "node_a".to_string());
        let hash2 = dag.add_node(node2).unwrap();

        assert_eq!(dag.len(), 2);

        // Genesis should still be genesis
        assert_eq!(dag.get_genesis().unwrap().hash, hash1);

        // Only node2 should be a head
        assert_eq!(dag.get_heads().len(), 1);
        assert_eq!(dag.get_heads()[0].hash, hash2);
    }

    #[test]
    fn test_dag_with_multiple_heads() {
        let mut dag = MerkleDAG::new();

        // Add genesis
        let op1 = create_test_operation();
        let node1 = DagNode::new(vec![op1], vec![], "node_a".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        // Add two children (creates two heads)
        let op2 = create_test_operation();
        let node2 = DagNode::new(vec![op2], vec![hash1.clone()], "node_a".to_string());
        let _hash2 = dag.add_node(node2).unwrap();

        let op3 = create_test_operation();
        let node3 = DagNode::new(vec![op3], vec![hash1.clone()], "node_b".to_string());
        let _hash3 = dag.add_node(node3).unwrap();

        // Should have 2 heads now
        assert_eq!(dag.get_heads().len(), 2);
    }

    #[test]
    fn test_merge_node() {
        let mut dag = MerkleDAG::new();

        // Create a fork
        let op1 = create_test_operation();
        let node1 = DagNode::new(vec![op1], vec![], "node_a".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        let op2 = create_test_operation();
        let node2 = DagNode::new(vec![op2], vec![hash1.clone()], "node_a".to_string());
        let hash2 = dag.add_node(node2).unwrap();

        let op3 = create_test_operation();
        let node3 = DagNode::new(vec![op3], vec![hash1.clone()], "node_b".to_string());
        let hash3 = dag.add_node(node3).unwrap();

        // Merge the fork
        let op4 = create_test_operation();
        let merge_node = DagNode::new(
            vec![op4],
            vec![hash2.clone(), hash3.clone()],
            "node_a".to_string(),
        );
        dag.add_node(merge_node).unwrap();

        // Should have 1 head after merge
        assert_eq!(dag.get_heads().len(), 1);
    }

    #[test]
    fn test_compute_root() {
        let mut dag = MerkleDAG::new();

        let op = create_test_operation();
        let node = DagNode::new(vec![op], vec![], "node_a".to_string());
        dag.add_node(node).unwrap();

        let root = dag.compute_root();
        assert!(!root.is_empty());
    }

    #[test]
    fn test_topological_sort() {
        let mut dag = MerkleDAG::new();

        // Add nodes in order
        let op1 = create_test_operation_with_id("key-1");
        let node1 = DagNode::new(vec![op1], vec![], "node_a".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        let op2 = create_test_operation_with_id("key-2");
        let node2 = DagNode::new(vec![op2], vec![hash1.clone()], "node_a".to_string());
        let hash2 = dag.add_node(node2).unwrap();

        let sorted = dag.topological_sort();
        assert_eq!(sorted.len(), 2);

        // Verify genesis comes first (has no parents)
        assert!(sorted[0].parents.is_empty());

        // Verify child comes second (has genesis as parent)
        assert_eq!(sorted[1].parents.len(), 1);
        assert_eq!(sorted[1].parents[0], hash1);

        // Verify the child's hash matches what we stored
        assert_eq!(sorted[1].hash, hash2);
    }

    #[test]
    fn test_verify_hash() {
        let op = create_test_operation();
        let node = DagNode::new(vec![op], vec![], "node_a".to_string());

        assert!(node.verify_hash());
    }

    #[test]
    fn test_merge_dags() {
        let mut dag1 = MerkleDAG::new();
        let mut dag2 = MerkleDAG::new();

        // dag1 has genesis
        let op1 = create_test_operation();
        let node1 = DagNode::new(vec![op1], vec![], "node_a".to_string());
        let hash1 = dag1.add_node(node1.clone()).unwrap();

        // dag2 has same genesis
        dag2.add_node(node1).unwrap();

        // dag2 adds a child
        let op2 = create_test_operation();
        let node2 = DagNode::new(vec![op2], vec![hash1], "node_b".to_string());
        dag2.add_node(node2).unwrap();

        // Merge dag2 into dag1
        dag1.merge(&dag2).unwrap();

        assert_eq!(dag1.len(), 2);
    }

    #[test]
    fn test_get_all_operations() {
        let mut dag = MerkleDAG::new();

        let op1 = create_test_operation();
        let node1 = DagNode::new(vec![op1.clone()], vec![], "node_a".to_string());
        let hash1 = dag.add_node(node1).unwrap();

        let op2 = create_test_operation();
        let node2 = DagNode::new(vec![op2.clone()], vec![hash1], "node_a".to_string());
        dag.add_node(node2).unwrap();

        let all_ops = dag.get_all_operations();
        assert_eq!(all_ops.len(), 2);
    }
}
