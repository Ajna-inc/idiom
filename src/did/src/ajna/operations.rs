//! CRDT Operations for did:ajna
//!
//! This module defines the operations that can be performed on a AjnaDocument.
//! Operations are serializable and can be broadcast via the gossip protocol.

use crate::ajna::{
    document::{Service, VerificationMethod},
    Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// CRDT operation on a DID document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CRDTOperation {
    /// Add a verification method
    AddVerificationMethod {
        method: VerificationMethod,
        timestamp: DateTime<Utc>,
        node_id: String,
    },

    /// Remove a verification method
    RemoveVerificationMethod {
        method_id: String,
        method: VerificationMethod, // Full method for OR-Set removal
        timestamp: DateTime<Utc>,
        node_id: String,
    },

    /// Set/update a service
    SetService {
        service: Service,
        timestamp: DateTime<Utc>,
        node_id: String,
    },

    /// Remove a service
    RemoveService {
        service_id: String,
        timestamp: DateTime<Utc>,
        node_id: String,
    },
}

impl CRDTOperation {
    /// Create an add verification method operation
    pub fn add_verification_method(method: VerificationMethod, node_id: String) -> Self {
        Self::AddVerificationMethod {
            method,
            timestamp: Utc::now(),
            node_id,
        }
    }

    /// Create a remove verification method operation
    pub fn remove_verification_method(
        method_id: String,
        method: VerificationMethod,
        node_id: String,
    ) -> Self {
        Self::RemoveVerificationMethod {
            method_id,
            method,
            timestamp: Utc::now(),
            node_id,
        }
    }

    /// Create a set service operation
    pub fn set_service(service: Service, node_id: String) -> Self {
        Self::SetService {
            service,
            timestamp: Utc::now(),
            node_id,
        }
    }

    /// Create a remove service operation
    pub fn remove_service(service_id: String, node_id: String) -> Self {
        Self::RemoveService {
            service_id,
            timestamp: Utc::now(),
            node_id,
        }
    }

    /// Get the timestamp of this operation
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::AddVerificationMethod { timestamp, .. } => *timestamp,
            Self::RemoveVerificationMethod { timestamp, .. } => *timestamp,
            Self::SetService { timestamp, .. } => *timestamp,
            Self::RemoveService { timestamp, .. } => *timestamp,
        }
    }

    /// Get the node ID that performed this operation
    pub fn node_id(&self) -> &str {
        match self {
            Self::AddVerificationMethod { node_id, .. } => node_id,
            Self::RemoveVerificationMethod { node_id, .. } => node_id,
            Self::SetService { node_id, .. } => node_id,
            Self::RemoveService { node_id, .. } => node_id,
        }
    }

    /// Apply this operation to a AjnaDocument
    pub fn apply(&self, document: &mut crate::ajna::AjnaDocument) -> Result<()> {
        // Increment vector clock for the node that performed this operation
        document.vector_clock.increment(self.node_id());

        match self {
            Self::AddVerificationMethod { method, .. } => {
                document.add_verification_method(method.clone());
            }
            Self::RemoveVerificationMethod { method_id, .. } => {
                document.remove_verification_method(method_id);
            }
            Self::SetService {
                service,
                timestamp,
                node_id,
            } => {
                document.set_service_with_timestamp(service.clone(), *timestamp, node_id.clone());
            }
            Self::RemoveService {
                service_id,
                timestamp,
                node_id,
            } => {
                document.remove_service_with_timestamp(service_id, *timestamp, node_id.clone());
            }
        }

        // Update document timestamp
        document.updated = Utc::now();

        Ok(())
    }
}

/// Batch of CRDT operations
///
/// Used for efficient syncing of multiple operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationBatch {
    /// DID this batch applies to
    pub did: String,

    /// List of operations
    pub operations: Vec<CRDTOperation>,

    /// Batch timestamp
    pub timestamp: DateTime<Utc>,

    /// Optional batch signature (for verification)
    pub signature: Option<String>,
}

impl OperationBatch {
    /// Create a new operation batch
    pub fn new(did: String, operations: Vec<CRDTOperation>) -> Self {
        Self {
            did,
            operations,
            timestamp: Utc::now(),
            signature: None,
        }
    }

    /// Add an operation to the batch
    pub fn add_operation(&mut self, operation: CRDTOperation) {
        self.operations.push(operation);
    }

    /// Get the number of operations in the batch
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Set the signature for this batch
    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    /// Verify the signature of this batch
    pub fn verify_signature(&self, _public_key: &str) -> Result<bool> {
        // TODO: Implement signature verification
        // For now, return true if signature exists
        Ok(self.signature.is_some())
    }
}

/// Update message for syncing DID documents
///
/// This is what gets broadcast via the gossip protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDUpdate {
    /// DID being updated
    pub did: String,

    /// Operations to apply
    pub operations: Vec<CRDTOperation>,

    /// Vector clock state (for causality)
    pub clock: Vec<(String, u64)>, // Serialized as vec for JSON compatibility

    /// Update timestamp
    pub timestamp: DateTime<Utc>,

    /// Node that originated this update
    pub origin_node: String,

    /// Optional signature
    pub signature: Option<String>,
}

impl DIDUpdate {
    /// Create a new DID update
    pub fn new(
        did: String,
        operations: Vec<CRDTOperation>,
        clock: Vec<(String, u64)>,
        origin_node: String,
    ) -> Self {
        Self {
            did,
            operations,
            clock,
            timestamp: Utc::now(),
            origin_node,
            signature: None,
        }
    }

    /// Set the signature for this update
    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    /// Get the number of operations
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Check if this is an empty update
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

/// Delta sync message for efficient synchronization
///
/// Instead of sending the full document, we send only the delta (difference)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSync {
    /// DID being synced
    pub did: String,

    /// Operations since the given vector clock
    pub delta_operations: Vec<CRDTOperation>,

    /// Current vector clock state
    pub current_clock: Vec<(String, u64)>,

    /// Vector clock state that this delta is based on
    pub base_clock: Vec<(String, u64)>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl DeltaSync {
    /// Create a new delta sync message
    pub fn new(
        did: String,
        delta_operations: Vec<CRDTOperation>,
        current_clock: Vec<(String, u64)>,
        base_clock: Vec<(String, u64)>,
    ) -> Self {
        Self {
            did,
            delta_operations,
            current_clock,
            base_clock,
            timestamp: Utc::now(),
        }
    }

    /// Check if this delta is empty
    pub fn is_empty(&self) -> bool {
        self.delta_operations.is_empty()
    }

    /// Get the number of operations in the delta
    pub fn delta_size(&self) -> usize {
        self.delta_operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::VerificationMethod;
    use std::collections::HashMap;

    fn create_test_method() -> VerificationMethod {
        VerificationMethod {
            id: "did:ajna:test#key-1".to_string(),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: "did:ajna:test".to_string(),
            public_key_multibase: "z6Mktest".to_string(),
            purpose: Some(vec!["authentication".to_string()]),
        }
    }

    fn create_test_service() -> Service {
        Service {
            id: "didcomm".to_string(),
            type_: "DIDCommMessaging".to_string(),
            service_endpoint: "https://example.com".to_string(),
            properties: HashMap::new(),
        }
    }

    #[test]
    fn test_create_add_operation() {
        let method = create_test_method();
        let op = CRDTOperation::add_verification_method(method.clone(), "node_a".to_string());

        match op {
            CRDTOperation::AddVerificationMethod {
                method: m, node_id, ..
            } => {
                assert_eq!(m, method);
                assert_eq!(node_id, "node_a");
            }
            _ => panic!("Wrong operation type"),
        }
    }

    #[test]
    fn test_create_remove_operation() {
        let method = create_test_method();
        let op = CRDTOperation::remove_verification_method(
            method.id.clone(),
            method.clone(),
            "node_a".to_string(),
        );

        match op {
            CRDTOperation::RemoveVerificationMethod {
                method_id, node_id, ..
            } => {
                assert_eq!(method_id, method.id);
                assert_eq!(node_id, "node_a");
            }
            _ => panic!("Wrong operation type"),
        }
    }

    #[test]
    fn test_operation_batch() {
        let mut batch = OperationBatch::new("did:ajna:test".to_string(), vec![]);

        let method = create_test_method();
        let op1 = CRDTOperation::add_verification_method(method, "node_a".to_string());
        batch.add_operation(op1);

        let service = create_test_service();
        let op2 = CRDTOperation::set_service(service, "node_a".to_string());
        batch.add_operation(op2);

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_did_update() {
        let method = create_test_method();
        let op = CRDTOperation::add_verification_method(method, "node_a".to_string());

        let update = DIDUpdate::new(
            "did:ajna:test".to_string(),
            vec![op],
            vec![("node_a".to_string(), 1)],
            "node_a".to_string(),
        );

        assert_eq!(update.did, "did:ajna:test");
        assert_eq!(update.operation_count(), 1);
        assert!(!update.is_empty());
        assert_eq!(update.origin_node, "node_a");
    }

    #[test]
    fn test_delta_sync() {
        let method = create_test_method();
        let op = CRDTOperation::add_verification_method(method, "node_a".to_string());

        let delta = DeltaSync::new(
            "did:ajna:test".to_string(),
            vec![op],
            vec![("node_a".to_string(), 2)],
            vec![("node_a".to_string(), 1)],
        );

        assert_eq!(delta.did, "did:ajna:test");
        assert_eq!(delta.delta_size(), 1);
        assert!(!delta.is_empty());
    }

    #[test]
    fn test_operation_serialization() {
        let method = create_test_method();
        let op = CRDTOperation::add_verification_method(method, "node_a".to_string());

        // Serialize to JSON
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("add_verification_method"));

        // Deserialize back
        let op2: CRDTOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op.node_id(), op2.node_id());
    }

    #[test]
    fn test_batch_serialization() {
        let mut batch = OperationBatch::new("did:ajna:test".to_string(), vec![]);

        let method = create_test_method();
        let op = CRDTOperation::add_verification_method(method, "node_a".to_string());
        batch.add_operation(op);

        // Serialize
        let json = serde_json::to_string(&batch).unwrap();

        // Deserialize
        let batch2: OperationBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch.did, batch2.did);
        assert_eq!(batch.len(), batch2.len());
    }
}
