//! did:ajna Method Implementation
//!
//! This module implements the DID method interface for did:ajna,
//! providing create, resolve, update, and deactivate operations.

use crate::ajna::{
    anchoring::{AnchorRecord, AnchoringService},
    document::AjnaDocument,
    merkle_dag::{DagNode, MerkleDAG},
    operations::{CRDTOperation, DIDUpdate},
    AjnaError, Result,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// DID Method for did:ajna
///
/// Manages a registry of DID documents with CRDT-based updates
#[derive(Clone)]
pub struct AjnaMethod {
    /// DID registry (did -> document)
    registry: Arc<RwLock<HashMap<String, AjnaDocument>>>,

    /// Operation history (did -> Merkle-DAG)
    history: Arc<RwLock<HashMap<String, MerkleDAG>>>,

    /// Blockchain anchoring service (optional)
    anchoring: Option<Arc<AnchoringService>>,

    /// Node ID for this instance
    node_id: String,
}

impl AjnaMethod {
    /// Create a new AjnaMethod instance
    pub fn new(node_id: String) -> Self {
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            anchoring: None,
            node_id,
        }
    }

    /// Create with blockchain anchoring enabled
    ///
    /// # Arguments
    /// * `node_id` - Node identifier
    /// * `network` - Blockchain network name (e.g., "ajna-mainnet")
    /// * `min_anchor_interval` - Minimum seconds between anchors (e.g., 3600 = 1 hour)
    pub fn with_anchoring(node_id: String, network: String, min_anchor_interval: u64) -> Self {
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            anchoring: Some(Arc::new(AnchoringService::new(
                network,
                min_anchor_interval,
            ))),
            node_id,
        }
    }

    /// Set the anchoring service
    pub fn set_anchoring(&mut self, service: Arc<AnchoringService>) {
        self.anchoring = Some(service);
    }

    /// Create a new DID document
    ///
    /// # Arguments
    /// * `did` - The DID identifier (e.g., "did:ajna:12345")
    ///
    /// # Returns
    /// The newly created AjnaDocument
    pub async fn create(&self, did: String) -> Result<AjnaDocument> {
        // Check if DID already exists
        {
            let registry = self.registry.read().await;
            if registry.contains_key(&did) {
                return Err(AjnaError::InvalidOperation(format!(
                    "DID already exists: {}",
                    did
                )));
            }
        }

        // Create new document
        let document = AjnaDocument::new(did.clone(), self.node_id.clone());

        // Store in registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.clone(), document.clone());
        }

        // Initialize empty history
        {
            let mut history = self.history.write().await;
            history.insert(did.clone(), MerkleDAG::new());
        }

        Ok(document)
    }

    /// Create a new DID document with genesis operation
    ///
    /// This creates a DID with initial controllers and policy settings
    ///
    /// # Arguments
    /// * `did` - The DID identifier (e.g., "did:ajna:12345")
    /// * `initial_controllers` - Initial controller DIDs (empty for self-controlled)
    /// * `initial_policy` - Initial policy settings (e.g., auth quorum)
    ///
    /// # Returns
    /// The newly created AjnaDocument
    pub async fn create_with_genesis(
        &self,
        did: String,
        initial_controllers: Vec<String>,
        initial_policy: Vec<(String, serde_json::Value)>,
    ) -> Result<AjnaDocument> {
        // Check if DID already exists
        {
            let registry = self.registry.read().await;
            if registry.contains_key(&did) {
                return Err(AjnaError::InvalidOperation(format!(
                    "DID already exists: {}",
                    did
                )));
            }
        }

        // Create new document with genesis
        let document = AjnaDocument::new_with_genesis(
            did.clone(),
            self.node_id.clone(),
            initial_controllers,
            initial_policy,
        );

        // Store in registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.clone(), document.clone());
        }

        // Initialize empty history
        {
            let mut history = self.history.write().await;
            history.insert(did.clone(), MerkleDAG::new());
        }

        Ok(document)
    }

    /// Resolve a DID to its document
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    /// The AjnaDocument if found
    pub async fn resolve(&self, did: &str) -> Result<AjnaDocument> {
        let registry = self.registry.read().await;
        registry
            .get(did)
            .cloned()
            .ok_or_else(|| AjnaError::DidNotFound(did.to_string()))
    }

    /// Deactivate a DID
    ///
    /// This permanently deactivates a DID document
    ///
    /// # Arguments
    /// * `did` - The DID to deactivate
    /// * `reason` - Optional reason for deactivation
    ///
    /// # Returns
    /// The deactivated document
    pub async fn deactivate(&self, did: &str, reason: Option<String>) -> Result<AjnaDocument> {
        // Get document
        let mut document = self.resolve(did).await?;

        // Check if already deactivated
        if document.is_deactivated() {
            return Err(AjnaError::InvalidOperation(format!(
                "DID already deactivated: {}",
                did
            )));
        }

        // Apply deactivation delta
        use crate::ajna::operation_v2::Delta;
        let delta = Delta::Deactivate { reason };
        document.apply_delta_v2(&delta)?;

        // Update registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.to_string(), document.clone());
        }

        Ok(document)
    }

    /// Apply an operation_v2::Operation
    ///
    /// This applies operations with full authorization and signature verification
    ///
    /// # Arguments
    /// * `operation` - The operation_v2::Operation to apply
    ///
    /// # Returns
    /// The updated document
    ///
    /// # Note
    /// This method skips signature verification as it requires resolving the actor's
    /// DID to get their public key. Callers should verify signatures before calling.
    pub async fn apply_operation_v2(
        &self,
        operation: &crate::ajna::operation_v2::Operation,
    ) -> Result<AjnaDocument> {
        // Get document
        let mut document = self.resolve(&operation.doc).await?;

        // Authorize operation
        let auth_result =
            crate::ajna::authorization::AuthorizationEngine::can_apply(operation, &document)?;

        if !auth_result.is_allowed() {
            return Err(AjnaError::InvalidOperation(format!(
                "Operation not authorized: {:?}",
                auth_result
            )));
        }

        // Apply delta
        document.apply_delta_v2(&operation.delta)?;

        // Update vector clock
        document.vector_clock.increment(&operation.actor);

        // Update registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(operation.doc.clone(), document.clone());
        }

        // Add operation to Merkle-DAG history
        {
            let mut history = self.history.write().await;
            let dag = history
                .entry(operation.doc.clone())
                .or_insert_with(MerkleDAG::new);

            // Create DAG node from operation
            let node = DagNode::from_operation_v2(operation.clone(), self.node_id.clone());

            // Add to DAG (parents are already in operation.parents)
            dag.add_node(node)?;
        }

        Ok(document)
    }

    /// Apply an operation to a DID document
    ///
    /// # Arguments
    /// * `did` - The DID to update
    /// * `operation` - The CRDT operation to apply
    ///
    /// # Returns
    /// The updated document
    pub async fn apply_operation(
        &self,
        did: &str,
        operation: CRDTOperation,
    ) -> Result<AjnaDocument> {
        // Get or create document
        let mut document = match self.resolve(did).await {
            Ok(doc) => doc,
            Err(_) => {
                // Create new document if it doesn't exist
                self.create(did.to_string()).await?
            }
        };

        // Apply operation
        operation.apply(&mut document)?;

        // Update registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.to_string(), document.clone());
        }

        // Add to history
        {
            let mut history = self.history.write().await;
            let dag = history
                .entry(did.to_string())
                .or_insert_with(MerkleDAG::new);

            // Get current heads as parents
            let parents: Vec<_> = dag.get_heads().iter().map(|n| n.hash.clone()).collect();

            // Create new DAG node
            let node = DagNode::new(vec![operation], parents, self.node_id.clone());

            dag.add_node(node)?;
        }

        Ok(document)
    }

    /// Apply a batch of operations to a DID document
    ///
    /// # Arguments
    /// * `did` - The DID to update
    /// * `operations` - The operations to apply
    ///
    /// # Returns
    /// The updated document
    pub async fn apply_operations(
        &self,
        did: &str,
        operations: Vec<CRDTOperation>,
    ) -> Result<AjnaDocument> {
        let mut document = self.resolve(did).await?;

        // Apply all operations
        for op in &operations {
            op.apply(&mut document)?;
        }

        // Update registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.to_string(), document.clone());
        }

        // Add to history
        {
            let mut history = self.history.write().await;
            let dag = history
                .entry(did.to_string())
                .or_insert_with(MerkleDAG::new);

            // Get current heads as parents
            let parents: Vec<_> = dag.get_heads().iter().map(|n| n.hash.clone()).collect();

            // Create new DAG node with all operations
            let node = DagNode::new(operations, parents, self.node_id.clone());

            dag.add_node(node)?;
        }

        Ok(document)
    }

    /// Merge a DID update from another node
    ///
    /// # Arguments
    /// * `update` - The DID update to merge
    ///
    /// # Returns
    /// The merged document
    pub async fn merge_update(&self, update: DIDUpdate) -> Result<AjnaDocument> {
        let did = &update.did;

        // Get or create document
        let mut document = match self.resolve(did).await {
            Ok(doc) => doc,
            Err(_) => {
                // Create new document if it doesn't exist
                self.create(did.clone()).await?
            }
        };

        // Apply all operations from the update
        for op in &update.operations {
            op.apply(&mut document)?;
        }

        // Merge vector clock
        for (node_id, timestamp) in &update.clock {
            for _ in 0..*timestamp {
                document.vector_clock.increment(node_id);
            }
        }

        // Update registry
        {
            let mut registry = self.registry.write().await;
            registry.insert(did.clone(), document.clone());
        }

        // Add to history
        {
            let mut history = self.history.write().await;
            let dag = history.entry(did.clone()).or_insert_with(MerkleDAG::new);

            // Get current heads as parents
            let parents: Vec<_> = dag.get_heads().iter().map(|n| n.hash.clone()).collect();

            // Create new DAG node with operations
            let node = DagNode::new(update.operations, parents, update.origin_node);

            dag.add_node(node)?;
        }

        Ok(document)
    }

    /// Get the operation history for a DID
    ///
    /// # Arguments
    /// * `did` - The DID to get history for
    ///
    /// # Returns
    /// Vector of operations in chronological order
    pub async fn get_history(&self, did: &str) -> Result<Vec<CRDTOperation>> {
        let history = self.history.read().await;
        let dag = history
            .get(did)
            .ok_or_else(|| AjnaError::DidNotFound(did.to_string()))?;

        Ok(dag.get_all_operations())
    }

    /// Get the Merkle root for a DID's operation history
    ///
    /// # Arguments
    /// * `did` - The DID to get Merkle root for
    ///
    /// # Returns
    /// The Merkle root hash
    pub async fn get_merkle_root(&self, did: &str) -> Result<String> {
        let history = self.history.read().await;
        let dag = history
            .get(did)
            .ok_or_else(|| AjnaError::DidNotFound(did.to_string()))?;

        Ok(dag.compute_root())
    }

    /// List all DIDs in the registry
    pub async fn list_dids(&self) -> Vec<String> {
        let registry = self.registry.read().await;
        registry.keys().cloned().collect()
    }

    /// Get the number of DIDs in the registry
    pub async fn count(&self) -> usize {
        let registry = self.registry.read().await;
        registry.len()
    }

    /// Check if a DID exists
    pub async fn exists(&self, did: &str) -> bool {
        let registry = self.registry.read().await;
        registry.contains_key(did)
    }

    /// Export a DID update for gossip synchronization
    ///
    /// # Arguments
    /// * `did` - The DID to export
    ///
    /// # Returns
    /// DIDUpdate message for gossip
    pub async fn export_update(&self, did: &str) -> Result<DIDUpdate> {
        let document = self.resolve(did).await?;
        let operations = self.get_history(did).await?;

        // Convert vector clock to serializable format
        let clock: Vec<(String, u64)> = document
            .vector_clock
            .node_ids()
            .into_iter()
            .map(|node_id| {
                let count = document.vector_clock.get(&node_id);
                (node_id, count)
            })
            .collect();

        Ok(DIDUpdate {
            did: did.to_string(),
            operations,
            clock,
            timestamp: Utc::now(),
            origin_node: self.node_id.clone(),
            signature: None, // TODO: Add signature support
        })
    }

    /// Import and merge multiple DID updates
    ///
    /// # Arguments
    /// * `updates` - Vector of DID updates to import
    ///
    /// # Returns
    /// Number of DIDs updated
    pub async fn import_updates(&self, updates: Vec<DIDUpdate>) -> Result<usize> {
        let mut count = 0;

        for update in updates {
            match self.merge_update(update).await {
                Ok(_) => count += 1,
                Err(e) => {
                    tracing::warn!("Failed to merge update: {}", e);
                }
            }
        }

        Ok(count)
    }

    // ==================== Blockchain Anchoring Methods ====================

    /// Anchor a DID's current state to the blockchain
    ///
    /// This creates a tamper-proof record of the DID's state at a specific point in time.
    ///
    /// # Arguments
    /// * `did` - The DID to anchor
    ///
    /// # Returns
    /// The anchor record if successful
    ///
    /// # Errors
    /// - DIDNotFound if the DID doesn't exist
    /// - InvalidOperation if anchoring service is not configured
    /// - InvalidOperation if minimum anchor interval hasn't elapsed
    pub async fn anchor(&self, did: &str) -> Result<AnchorRecord> {
        let anchoring = self.anchoring.as_ref().ok_or_else(|| {
            AjnaError::InvalidOperation("Anchoring service not configured".to_string())
        })?;

        // Get current Merkle root
        let merkle_root = self.get_merkle_root(did).await?;

        // Get operation count
        let operations = self.get_history(did).await?;
        let operation_count = operations.len();

        // Submit anchor
        anchoring
            .submit_anchor(did.to_string(), merkle_root, operation_count)
            .await
    }

    /// Get the blockchain anchor for a DID
    ///
    /// Returns the latest anchor record if the DID has been anchored
    pub async fn get_anchor(&self, did: &str) -> Option<AnchorRecord> {
        if let Some(anchoring) = &self.anchoring {
            anchoring.get_anchor(did).await
        } else {
            None
        }
    }

    /// Get all historical anchors for a DID
    pub async fn get_anchor_history(&self, did: &str) -> Vec<AnchorRecord> {
        if let Some(anchoring) = &self.anchoring {
            anchoring.get_anchor_history(did).await
        } else {
            Vec::new()
        }
    }

    /// Verify if a DID's current state matches its blockchain anchor
    ///
    /// # Returns
    /// - `Some(true)` if current state matches anchor
    /// - `Some(false)` if current state differs from anchor (has been updated)
    /// - `None` if DID has never been anchored
    pub async fn verify_against_anchor(&self, did: &str) -> Option<bool> {
        if let Some(anchoring) = &self.anchoring {
            if let Ok(merkle_root) = self.get_merkle_root(did).await {
                anchoring.verify_anchor(did, &merkle_root).await
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if a DID has been anchored to the blockchain
    pub async fn is_anchored(&self, did: &str) -> bool {
        if let Some(anchoring) = &self.anchoring {
            anchoring.is_anchored(did).await
        } else {
            false
        }
    }

    /// Resolve a DID with blockchain verification
    ///
    /// This checks if the current state matches the blockchain anchor.
    /// If not, it includes anchor information in the returned document.
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    /// The DID document with blockchain anchor information if available
    pub async fn resolve_with_anchor(&self, did: &str) -> Result<AjnaDocument> {
        let mut document = self.resolve(did).await?;

        // Check if we have an anchor
        if let Some(anchor) = self.get_anchor(did).await {
            // Update document with blockchain anchor info
            document.blockchain_anchor = Some(crate::ajna::document::BlockchainAnchor {
                network: anchor.network,
                tx_hash: anchor.tx_hash,
                block_number: anchor.block_number,
                timestamp: anchor.timestamp,
                merkle_root: anchor.merkle_root,
            });
        }

        Ok(document)
    }

    /// Check if anchoring service is available
    pub fn has_anchoring(&self) -> bool {
        self.anchoring.is_some()
    }

    /// Clear all DIDs from the registry (for testing)
    #[cfg(test)]
    pub async fn clear(&self) {
        let mut registry = self.registry.write().await;
        registry.clear();

        let mut history = self.history.write().await;
        history.clear();

        if let Some(anchoring) = &self.anchoring {
            anchoring.clear().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::{Service, VerificationMethod};

    fn create_test_method() -> VerificationMethod {
        VerificationMethod {
            id: "did:ajna:test#key-1".to_string(),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: "did:ajna:test".to_string(),
            public_key_multibase: "z6Mktest123".to_string(),
            purpose: Some(vec!["authentication".to_string()]),
        }
    }

    fn create_test_service() -> Service {
        Service {
            id: "did:ajna:test#service-1".to_string(),
            type_: "MessagingService".to_string(),
            service_endpoint: "https://example.com/msg".to_string(),
            properties: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_create_did() {
        let method = AjnaMethod::new("node1".to_string());

        let doc = method
            .create("did:ajna:test".to_string())
            .await
            .expect("Failed to create DID");

        assert_eq!(doc.id, "did:ajna:test");
        assert_eq!(doc.node_id, "node1");
    }

    #[tokio::test]
    async fn test_resolve_did() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        let doc = method.resolve(&did).await.expect("Failed to resolve DID");
        assert_eq!(doc.id, did);
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_did() {
        let method = AjnaMethod::new("node1".to_string());

        let result = method.resolve("did:ajna:nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_apply_operation() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm.clone(), "node1".to_string());

        let doc = method
            .apply_operation(&did, op)
            .await
            .expect("Failed to apply operation");

        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.contains(&vm));
    }

    #[tokio::test]
    async fn test_apply_multiple_operations() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        let vm = create_test_method();
        let service = create_test_service();

        let ops = vec![
            CRDTOperation::add_verification_method(vm.clone(), "node1".to_string()),
            CRDTOperation::set_service(service.clone(), "node1".to_string()),
        ];

        let doc = method
            .apply_operations(&did, ops)
            .await
            .expect("Failed to apply operations");

        assert_eq!(doc.verification_methods.len(), 1);
        assert_eq!(doc.service.as_ref().map(|s| s.len()).unwrap_or(0), 1);
    }

    #[tokio::test]
    async fn test_get_history() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm, "node1".to_string());

        method.apply_operation(&did, op.clone()).await.unwrap();

        let history = method
            .get_history(&did)
            .await
            .expect("Failed to get history");
        assert_eq!(history.len(), 1);
    }

    #[tokio::test]
    async fn test_merkle_root() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm, "node1".to_string());

        method.apply_operation(&did, op).await.unwrap();

        let root = method
            .get_merkle_root(&did)
            .await
            .expect("Failed to get Merkle root");
        assert!(!root.is_empty());
    }

    #[tokio::test]
    async fn test_export_import_update() {
        let method1 = AjnaMethod::new("node1".to_string());
        let method2 = AjnaMethod::new("node2".to_string());

        let did = "did:ajna:test".to_string();
        method1.create(did.clone()).await.unwrap();

        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm.clone(), "node1".to_string());

        method1.apply_operation(&did, op).await.unwrap();

        // Export from method1
        let update = method1
            .export_update(&did)
            .await
            .expect("Failed to export update");

        // Import into method2
        method2
            .merge_update(update)
            .await
            .expect("Failed to merge update");

        // Verify method2 has the DID
        let doc = method2.resolve(&did).await.expect("Failed to resolve DID");
        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.contains(&vm));
    }

    #[tokio::test]
    async fn test_list_dids() {
        let method = AjnaMethod::new("node1".to_string());

        method.create("did:ajna:test1".to_string()).await.unwrap();
        method.create("did:ajna:test2".to_string()).await.unwrap();
        method.create("did:ajna:test3".to_string()).await.unwrap();

        let dids = method.list_dids().await;
        assert_eq!(dids.len(), 3);
    }

    #[tokio::test]
    async fn test_count_and_exists() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        assert_eq!(method.count().await, 0);
        assert!(!method.exists(&did).await);

        method.create(did.clone()).await.unwrap();

        assert_eq!(method.count().await, 1);
        assert!(method.exists(&did).await);
    }

    #[tokio::test]
    async fn test_import_multiple_updates() {
        let method1 = AjnaMethod::new("node1".to_string());
        let method2 = AjnaMethod::new("node2".to_string());

        // Create multiple DIDs on method1
        method1.create("did:ajna:test1".to_string()).await.unwrap();
        method1.create("did:ajna:test2".to_string()).await.unwrap();

        let vm1 = create_test_method();
        let op1 = CRDTOperation::add_verification_method(vm1, "node1".to_string());
        method1
            .apply_operation("did:ajna:test1", op1)
            .await
            .unwrap();

        let service = create_test_service();
        let op2 = CRDTOperation::set_service(service, "node1".to_string());
        method1
            .apply_operation("did:ajna:test2", op2)
            .await
            .unwrap();

        // Export all updates
        let update1 = method1.export_update("did:ajna:test1").await.unwrap();
        let update2 = method1.export_update("did:ajna:test2").await.unwrap();

        // Import into method2
        let count = method2
            .import_updates(vec![update1, update2])
            .await
            .expect("Failed to import updates");

        assert_eq!(count, 2);
        assert_eq!(method2.count().await, 2);
    }

    // ==================== Blockchain Anchoring Tests ====================

    #[tokio::test]
    async fn test_with_anchoring() {
        let method =
            AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 3600);

        assert!(method.has_anchoring());
    }

    #[tokio::test]
    async fn test_without_anchoring() {
        let method = AjnaMethod::new("node1".to_string());
        assert!(!method.has_anchoring());
    }

    #[tokio::test]
    async fn test_anchor_did() {
        let method = AjnaMethod::with_anchoring(
            "node1".to_string(),
            "ajna-testnet".to_string(),
            0, // No interval for testing
        );

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // Add some operations
        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm, "node1".to_string());
        method.apply_operation(&did, op).await.unwrap();

        // Not anchored yet
        assert!(!method.is_anchored(&did).await);

        // Anchor the DID
        let anchor = method.anchor(&did).await.expect("Failed to anchor");

        assert_eq!(anchor.did, did);
        assert!(!anchor.tx_hash.is_empty());
        assert!(anchor.block_number > 0);
        assert_eq!(anchor.network, "ajna-testnet");
        assert_eq!(anchor.operation_count, Some(1));

        // Now it's anchored
        assert!(method.is_anchored(&did).await);
    }

    #[tokio::test]
    async fn test_anchor_without_service() {
        let method = AjnaMethod::new("node1".to_string());

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // Try to anchor without service
        let result = method.anchor(&did).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn test_get_anchor() {
        let method = AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 0);

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // No anchor yet
        assert!(method.get_anchor(&did).await.is_none());

        // Anchor the DID
        method.anchor(&did).await.unwrap();

        // Get anchor
        let anchor = method.get_anchor(&did).await.expect("Anchor not found");
        assert_eq!(anchor.did, did);
    }

    #[tokio::test]
    async fn test_verify_against_anchor() {
        let method = AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 0);

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // Add operation
        let vm = create_test_method();
        let op = CRDTOperation::add_verification_method(vm, "node1".to_string());
        method.apply_operation(&did, op).await.unwrap();

        // No anchor yet
        assert_eq!(method.verify_against_anchor(&did).await, None);

        // Anchor the DID
        method.anchor(&did).await.unwrap();

        // State matches anchor
        assert_eq!(method.verify_against_anchor(&did).await, Some(true));

        // Add another operation (changes state)
        let service = create_test_service();
        let op2 = CRDTOperation::set_service(service, "node1".to_string());
        method.apply_operation(&did, op2).await.unwrap();

        // State no longer matches anchor
        assert_eq!(method.verify_against_anchor(&did).await, Some(false));
    }

    #[tokio::test]
    async fn test_resolve_with_anchor() {
        let method = AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 0);

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // Resolve without anchor
        let doc1 = method.resolve_with_anchor(&did).await.unwrap();
        assert!(doc1.blockchain_anchor.is_none());

        // Anchor the DID
        method.anchor(&did).await.unwrap();

        // Resolve with anchor
        let doc2 = method.resolve_with_anchor(&did).await.unwrap();
        assert!(doc2.blockchain_anchor.is_some());

        let anchor_info = doc2.blockchain_anchor.unwrap();
        assert_eq!(anchor_info.network, "ajna-testnet");
        assert!(!anchor_info.tx_hash.is_empty());
    }

    #[tokio::test]
    async fn test_anchor_history() {
        let method = AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 0);

        let did = "did:ajna:test".to_string();
        method.create(did.clone()).await.unwrap();

        // Add operation and anchor
        let vm = create_test_method();
        let op1 = CRDTOperation::add_verification_method(vm, "node1".to_string());
        method.apply_operation(&did, op1).await.unwrap();
        method.anchor(&did).await.unwrap();

        // Add another operation and anchor again
        let service = create_test_service();
        let op2 = CRDTOperation::set_service(service, "node1".to_string());
        method.apply_operation(&did, op2).await.unwrap();
        method.anchor(&did).await.unwrap();

        // Get history
        let history = method.get_anchor_history(&did).await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].operation_count, Some(1));
        assert_eq!(history[1].operation_count, Some(2));
    }

    #[tokio::test]
    async fn test_multiple_dids_anchored() {
        let method = AjnaMethod::with_anchoring("node1".to_string(), "ajna-testnet".to_string(), 0);

        // Create and anchor multiple DIDs
        method.create("did:ajna:alice".to_string()).await.unwrap();
        method.create("did:ajna:bob".to_string()).await.unwrap();

        method.anchor("did:ajna:alice").await.unwrap();
        method.anchor("did:ajna:bob").await.unwrap();

        // Both are anchored
        assert!(method.is_anchored("did:ajna:alice").await);
        assert!(method.is_anchored("did:ajna:bob").await);

        // Get both anchors
        let alice_anchor = method.get_anchor("did:ajna:alice").await.unwrap();
        let bob_anchor = method.get_anchor("did:ajna:bob").await.unwrap();

        assert_eq!(alice_anchor.did, "did:ajna:alice");
        assert_eq!(bob_anchor.did, "did:ajna:bob");
        assert_ne!(alice_anchor.tx_hash, bob_anchor.tx_hash);
    }

    #[tokio::test]
    async fn test_anchor_provides_finality() {
        // This test demonstrates the finality model:
        // 1. Local CRDT updates are immediate
        // 2. Blockchain anchor provides finality
        // 3. Anchored state can be verified independently

        let method =
            AjnaMethod::with_anchoring("node1".to_string(), "ajna-mainnet".to_string(), 3600);

        let did = "did:ajna:citizen123".to_string();
        method.create(did.clone()).await.unwrap();

        // Local updates (CRDT, offline-capable)
        let vm1 = VerificationMethod {
            id: format!("{}#key-1", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mkkey1".to_string(),
            purpose: Some(vec!["authentication".to_string()]),
        };
        method
            .apply_operation(
                &did,
                CRDTOperation::add_verification_method(vm1, "node1".to_string()),
            )
            .await
            .unwrap();

        // Get current state
        let merkle_root_before_anchor = method.get_merkle_root(&did).await.unwrap();

        // Anchor to blockchain (provides finality)
        let anchor = method.anchor(&did).await.unwrap();

        // Verify finality
        assert_eq!(anchor.merkle_root, merkle_root_before_anchor);
        assert!(method.verify_against_anchor(&did).await.unwrap());

        // Make more local updates after anchor
        let vm2 = VerificationMethod {
            id: format!("{}#key-2", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mkkey2".to_string(),
            purpose: Some(vec!["assertion".to_string()]),
        };
        method
            .apply_operation(
                &did,
                CRDTOperation::add_verification_method(vm2, "node1".to_string()),
            )
            .await
            .unwrap();

        // Current state differs from anchored state
        assert!(!method.verify_against_anchor(&did).await.unwrap());

        // But we can still resolve the document with anchor info
        let doc = method.resolve_with_anchor(&did).await.unwrap();
        assert!(doc.blockchain_anchor.is_some());
        assert_eq!(doc.verification_methods.len(), 2); // Has both keys

        // The anchor provides a verifiable checkpoint in history
        let anchor_info = doc.blockchain_anchor.unwrap();
        assert_eq!(anchor_info.network, "ajna-mainnet");
        assert_eq!(anchor_info.merkle_root, merkle_root_before_anchor);
    }

    #[tokio::test]
    async fn test_create_with_genesis() {
        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();

        // Create with initial controllers and policy
        let controllers = vec!["did:ajna:controller1".to_string()];
        let policy = vec![
            ("auth.quorum.update".to_string(), serde_json::json!(2)),
            ("auth.threshold".to_string(), serde_json::json!("2-of-3")),
        ];

        let doc = method
            .create_with_genesis(did.clone(), controllers.clone(), policy)
            .await
            .unwrap();

        // Verify document has genesis data
        assert_eq!(doc.id, did);
        assert!(doc.is_controller("did:ajna:controller1"));
        assert_eq!(doc.get_policy_int("auth.quorum.update"), Some(2));
        assert_eq!(
            doc.get_policy("auth.threshold").and_then(|v| v.as_str()),
            Some("2-of-3")
        );
    }

    #[tokio::test]
    async fn test_deactivate_did() {
        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();

        // Create DID
        method.create(did.clone()).await.unwrap();

        // Verify not deactivated
        let doc = method.resolve(&did).await.unwrap();
        assert!(!doc.is_deactivated());

        // Deactivate
        let deactivated_doc = method
            .deactivate(&did, Some("Testing deactivation".to_string()))
            .await
            .unwrap();

        // Verify deactivated
        assert!(deactivated_doc.is_deactivated());

        // Resolve should still work
        let doc = method.resolve(&did).await.unwrap();
        assert!(doc.is_deactivated());

        // Cannot deactivate twice
        let result = method.deactivate(&did, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_genesis_with_empty_controllers() {
        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();

        // Create with no controllers (self-controlled)
        let doc = method
            .create_with_genesis(did.clone(), vec![], vec![])
            .await
            .unwrap();

        // Verify document exists but has no controllers
        assert_eq!(doc.id, did);
        assert!(!doc.is_controller("did:ajna:anyone"));
    }

    #[tokio::test]
    async fn test_apply_operation_v2() {
        use crate::ajna::operation_v2::{ClockEntry, Delta, Operation};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();

        // Create DID
        method.create(did.clone()).await.unwrap();

        // Create operation to add verification method
        let vm = VerificationMethod {
            id: format!("{}#key-1", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: None,
        };

        let signing_key = SigningKey::generate(&mut OsRng);
        let operation = Operation::new(
            did.clone(),
            vec![],
            did.clone(), // Self-controlled
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd { entry: vm.clone() },
            &signing_key,
            format!("{}#key-1", did),
        )
        .unwrap();

        // Apply operation
        let doc = method.apply_operation_v2(&operation).await.unwrap();

        // Verify verification method was added
        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.contains(&vm));
    }

    #[tokio::test]
    async fn test_apply_operation_v2_unauthorized() {
        use crate::ajna::operation_v2::{ClockEntry, Delta, Operation};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();
        let attacker = "did:ajna:attacker".to_string();

        // Create DID
        method.create(did.clone()).await.unwrap();

        // Attacker tries to add verification method
        let vm = VerificationMethod {
            id: format!("{}#key-1", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: None,
        };

        let signing_key = SigningKey::generate(&mut OsRng);
        let operation = Operation::new(
            did.clone(),
            vec![],
            attacker.clone(), // Unauthorized actor
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd { entry: vm },
            &signing_key,
            format!("{}#key-1", attacker),
        )
        .unwrap();

        // Should fail authorization
        let result = method.apply_operation_v2(&operation).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_apply_operation_v2_with_controller() {
        use crate::ajna::operation_v2::{ClockEntry, Delta, Operation};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();
        let controller = "did:ajna:controller1".to_string();

        // Create DID with controller
        method
            .create_with_genesis(did.clone(), vec![controller.clone()], vec![])
            .await
            .unwrap();

        // Controller adds verification method
        let vm = VerificationMethod {
            id: format!("{}#key-1", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: None,
        };

        let signing_key = SigningKey::generate(&mut OsRng);
        let operation = Operation::new(
            did.clone(),
            vec![],
            controller.clone(), // Authorized controller
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd { entry: vm.clone() },
            &signing_key,
            format!("{}#key-1", controller),
        )
        .unwrap();

        // Should succeed
        let doc = method.apply_operation_v2(&operation).await.unwrap();
        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.contains(&vm));
    }

    #[tokio::test]
    async fn test_apply_operation_v2_deactivated() {
        use crate::ajna::operation_v2::{ClockEntry, Delta, Operation};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let method = AjnaMethod::new("node1".to_string());
        let did = "did:ajna:test123".to_string();

        // Create and deactivate DID
        method.create(did.clone()).await.unwrap();
        method.deactivate(&did, None).await.unwrap();

        // Try to add verification method to deactivated DID
        let vm = VerificationMethod {
            id: format!("{}#key-1", did),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.clone(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: None,
        };

        let signing_key = SigningKey::generate(&mut OsRng);
        let operation = Operation::new(
            did.clone(),
            vec![],
            did.clone(),
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd { entry: vm },
            &signing_key,
            format!("{}#key-1", did),
        )
        .unwrap();

        // Should fail - cannot modify deactivated DID
        let result = method.apply_operation_v2(&operation).await;
        assert!(result.is_err());
    }
}
