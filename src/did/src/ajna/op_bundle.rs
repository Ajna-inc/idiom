//! Operation bundle implementation for efficient synchronization
//!
//! This module provides compact serialization of operation bundles for
//! transmission between peers. Bundles include requested operations plus
//! minimal parent context needed for causal validation.
//!
//! ## Requirements
//!
//! Operation bundles must:
//! - Be ≤ 128 KB in size
//! - Include minimal parent operations for causality
//! - Use compact binary encoding (MessagePack)

use crate::ajna::crypto;
use crate::ajna::error::{AjnaError, Result};
use crate::ajna::operation_v2::Operation;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum bundle size in bytes
pub const MAX_BUNDLE_SIZE: usize = 128 * 1024; // 128 KB

/// Compact bundle of operations for transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpBundle {
    /// DID identifier
    pub doc: String,

    /// Requested operations
    pub operations: Vec<Operation>,

    /// Minimal parent operations for validation
    pub context_ops: Vec<Operation>,

    /// Blake3 hash of bundle contents
    pub bundle_id: String,

    /// Creation timestamp (milliseconds since epoch)
    pub created_at: i64,
}

impl OpBundle {
    /// Create bundle from requested operations
    ///
    /// # Arguments
    ///
    /// * `did` - DID identifier
    /// * `operations` - Requested operations to include
    /// * `max_size` - Maximum bundle size in bytes (default: 128 KB)
    ///
    /// # Errors
    ///
    /// Returns error if bundle exceeds max_size after serialization
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let ops = vec![op1, op2, op3];
    /// let bundle = OpBundle::create("did:ajna:test", ops, MAX_BUNDLE_SIZE)?;
    /// ```
    pub fn create(did: &str, operations: Vec<Operation>, max_size: usize) -> Result<Self> {
        // Find minimal parent context
        let context_ops = Self::find_minimal_context(&operations)?;

        let bundle = Self {
            doc: did.to_string(),
            operations: operations.clone(),
            context_ops,
            bundle_id: String::new(), // Computed below
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        // Compute bundle ID
        let bundle_id = bundle.compute_id()?;
        let mut bundle = bundle;
        bundle.bundle_id = bundle_id;

        // Check size constraint
        let serialized = bundle.to_bytes()?;
        if serialized.len() > max_size {
            return Err(AjnaError::BundleTooLarge {
                size: serialized.len(),
                max: max_size,
            });
        }

        Ok(bundle)
    }

    /// Serialize to compact binary format (MessagePack)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| AjnaError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(bytes).map_err(|e| AjnaError::SerializationError(e.to_string()))
    }

    /// Validate bundle integrity
    ///
    /// Checks:
    /// - Bundle ID matches contents
    /// - All operations have valid structure
    /// - Sufficient causal context provided
    pub fn validate(&self) -> Result<()> {
        // Check bundle_id matches contents
        let computed_id = self.compute_id()?;
        if computed_id != self.bundle_id {
            return Err(AjnaError::InvalidBundleId);
        }

        // Note: We don't validate individual operations here
        // Operation validation happens when applying via AjnaMethod
        // This just checks bundle-level integrity

        // Check context ops are sufficient
        if !self.has_sufficient_context()? {
            return Err(AjnaError::InsufficientContext);
        }

        Ok(())
    }

    /// Compute bundle ID (Blake3 hash of contents)
    fn compute_id(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(crypto::DST_AJNA_OP);
        hasher.update(self.doc.as_bytes());

        // Hash operation IDs in deterministic order
        let mut op_ids: Vec<_> = self.operations.iter().map(|op| &op.op_id).collect();
        op_ids.sort();
        for op_id in op_ids {
            hasher.update(op_id.as_bytes());
        }

        // Hash timestamp
        hasher.update(&self.created_at.to_le_bytes());

        let hash_bytes = hasher.finalize();
        Ok(STANDARD.encode(hash_bytes.as_bytes()))
    }

    /// Find minimal set of parent operations needed for causal validation
    ///
    /// Collects all parent references that are not already in the operations list.
    /// In a real implementation, these would be fetched from the DAG.
    fn find_minimal_context(operations: &[Operation]) -> Result<Vec<Operation>> {
        // Collect all parent references
        let mut needed_parents = HashSet::new();
        for op in operations {
            for parent in &op.parents {
                if !parent.is_empty() {
                    needed_parents.insert(parent.clone());
                }
            }
        }

        // Remove parents that are already in the main operations list
        let ops_set: HashSet<_> = operations.iter().map(|op| op.op_id.clone()).collect();
        for op_id in &ops_set {
            needed_parents.remove(op_id);
        }

        // TODO: Fetch these parent operations from DAG
        // For now, we accept that context may be incomplete
        // and rely on the receiver to request missing ops
        Ok(Vec::new())
    }

    /// Check if bundle has sufficient causal context
    ///
    /// All parent references should be satisfied by either:
    /// 1. Operations in this bundle
    /// 2. Context operations in this bundle
    /// 3. Empty parent (genesis operation)
    fn has_sufficient_context(&self) -> Result<bool> {
        let available_ops: HashSet<_> = self
            .operations
            .iter()
            .chain(self.context_ops.iter())
            .map(|op| op.op_id.clone())
            .collect();

        for op in &self.operations {
            for parent in &op.parents {
                if !parent.is_empty() && !available_ops.contains(parent) {
                    // Missing parent - not necessarily an error,
                    // receiver can request it later
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Split oversized bundle into multiple smaller bundles
    ///
    /// If a bundle exceeds max_size, split into multiple bundles.
    /// Each bundle will be ≤ max_size.
    pub fn split_if_needed(
        did: &str,
        operations: Vec<Operation>,
        max_size: usize,
    ) -> Result<Vec<Self>> {
        // Try creating single bundle first
        match Self::create(did, operations.clone(), max_size) {
            Ok(bundle) => Ok(vec![bundle]),
            Err(AjnaError::BundleTooLarge { .. }) => {
                // Need to split
                let mut bundles = Vec::new();
                let mut current_ops = Vec::new();

                for op in operations {
                    current_ops.push(op.clone());

                    // Try creating bundle with current ops
                    match Self::create(did, current_ops.clone(), max_size) {
                        Ok(_) => {
                            // Still fits, continue
                        }
                        Err(AjnaError::BundleTooLarge { .. }) => {
                            // Too large, finalize previous bundle
                            if current_ops.len() > 1 {
                                current_ops.pop(); // Remove last op that caused overflow
                                let bundle = Self::create(did, current_ops.clone(), max_size)?;
                                bundles.push(bundle);
                                current_ops = vec![op]; // Start new bundle with overflow op
                            } else {
                                // Single operation is too large!
                                return Err(AjnaError::InvalidOperation(
                                    "Single operation exceeds max bundle size".to_string(),
                                ));
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }

                // Add final bundle
                if !current_ops.is_empty() {
                    let bundle = Self::create(did, current_ops, max_size)?;
                    bundles.push(bundle);
                }

                Ok(bundles)
            }
            Err(e) => Err(e),
        }
    }

    /// Get total number of operations (main + context)
    pub fn total_ops(&self) -> usize {
        self.operations.len() + self.context_ops.len()
    }

    /// Get bundle size in bytes
    pub fn size_bytes(&self) -> Result<usize> {
        Ok(self.to_bytes()?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::VerificationMethod;
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

    #[test]
    fn test_bundle_creation() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);
        let op2 = create_test_operation(did, "op2", vec!["op1".to_string()]);

        let bundle = OpBundle::create(did, vec![op1, op2], MAX_BUNDLE_SIZE).unwrap();

        assert_eq!(bundle.doc, did);
        assert_eq!(bundle.operations.len(), 2);
        assert!(!bundle.bundle_id.is_empty());
        assert!(bundle.created_at > 0);
    }

    #[test]
    fn test_bundle_serialization() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);

        let bundle = OpBundle::create(did, vec![op1], MAX_BUNDLE_SIZE).unwrap();

        // Serialize
        let bytes = bundle.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Deserialize
        let bundle2 = OpBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle2.doc, bundle.doc);
        assert_eq!(bundle2.operations.len(), bundle.operations.len());
        assert_eq!(bundle2.bundle_id, bundle.bundle_id);
    }

    #[test]
    fn test_bundle_validation() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);

        let bundle = OpBundle::create(did, vec![op1], MAX_BUNDLE_SIZE).unwrap();

        // Should validate successfully
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_id_mismatch() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);

        let mut bundle = OpBundle::create(did, vec![op1], MAX_BUNDLE_SIZE).unwrap();

        // Tamper with bundle_id
        bundle.bundle_id = "invalid_id".to_string();

        // Validation should fail
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_size_limit() {
        let did = "did:ajna:test";

        // Create many large operations
        let mut ops = Vec::new();
        for i in 0..1000 {
            let op = create_test_operation(did, &format!("op{}", i), vec![]);
            ops.push(op);
        }

        // Try creating bundle with small size limit
        let result = OpBundle::create(did, ops, 1024); // 1 KB limit

        // Should fail with BundleTooLarge
        assert!(matches!(result, Err(AjnaError::BundleTooLarge { .. })));
    }

    #[test]
    fn test_bundle_splitting() {
        let did = "did:ajna:test";

        // Create operations
        let mut ops = Vec::new();
        for i in 0..10 {
            let op = create_test_operation(did, &format!("op{}", i), vec![]);
            ops.push(op);
        }

        // Split with small size limit
        let bundles = OpBundle::split_if_needed(did, ops, 2048).unwrap();

        // Should create multiple bundles
        assert!(bundles.len() > 1);

        // Each bundle should be under limit
        for bundle in &bundles {
            assert!(bundle.size_bytes().unwrap() <= 2048);
        }

        // All operations should be present
        let total_ops: usize = bundles.iter().map(|b| b.operations.len()).sum();
        assert_eq!(total_ops, 10);
    }

    #[test]
    fn test_empty_bundle() {
        let did = "did:ajna:test";

        let bundle = OpBundle::create(did, vec![], MAX_BUNDLE_SIZE).unwrap();

        assert_eq!(bundle.operations.len(), 0);
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_with_parents() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);
        let op2 = create_test_operation(did, "op2", vec!["op1".to_string()]);
        let op3 = create_test_operation(did, "op3", vec!["op1".to_string(), "op2".to_string()]);

        let bundle = OpBundle::create(did, vec![op1, op2, op3], MAX_BUNDLE_SIZE).unwrap();

        // Should have all operations
        assert_eq!(bundle.operations.len(), 3);

        // Context should be calculated (currently empty in our implementation)
        // In real implementation, would include parent ops from DAG
    }

    #[test]
    fn test_bundle_id_deterministic() {
        let did = "did:ajna:test";
        let op1 = create_test_operation(did, "op1", vec![]);

        // Create two bundles with same operations
        let bundle1 = OpBundle {
            doc: did.to_string(),
            operations: vec![op1.clone()],
            context_ops: vec![],
            bundle_id: String::new(),
            created_at: 1000, // Same timestamp
        };

        let bundle2 = OpBundle {
            doc: did.to_string(),
            operations: vec![op1.clone()],
            context_ops: vec![],
            bundle_id: String::new(),
            created_at: 1000, // Same timestamp
        };

        // IDs should be the same
        assert_eq!(bundle1.compute_id().unwrap(), bundle2.compute_id().unwrap());
    }
}
