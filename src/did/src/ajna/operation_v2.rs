//! DID Operation Format
//!
//! This module implements the complete operation format as specified:
//! - op_id: Blake3 hash of canonical bytes
//! - parents: Strong refs to prior DAG tips
//! - actor: Device/agent DID
//! - clock: Compressed vector clock
//! - delta: CRDT intent
//! - auth: Ed25519 signature proof
//! - timestamp_ms: Millisecond timestamp

use crate::ajna::{
    crypto,
    document::{Service, VerificationMethod},
    AjnaError, Result,
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Operation type constant
pub const OP_TYPE: &str = "org.ajna.did/op/1.0";

/// Complete DID operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Operation type
    #[serde(rename = "type")]
    pub op_type: String,

    /// DID this operation applies to
    pub doc: String,

    /// Operation ID (Blake3 hash of canonical bytes)
    pub op_id: String,

    /// Parent operation IDs (DAG structure)
    pub parents: Vec<String>,

    /// Actor (device/agent DID or key ID)
    pub actor: String,

    /// Vector clock entry
    pub clock: ClockEntry,

    /// CRDT delta (the actual mutation intent)
    pub delta: Delta,

    /// Authorization (signature proof)
    pub auth: AuthProof,

    /// Timestamp in milliseconds since Unix epoch
    pub timestamp_ms: i64,
}

/// Compressed vector clock entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClockEntry {
    /// Actor ID (small integer, assigned per document)
    #[serde(rename = "actorId")]
    pub actor_id: u32,

    /// Lamport counter for this actor
    pub counter: u64,
}

/// CRDT Delta - the mutation intent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Delta {
    /// Add a verification method
    VmAdd { entry: VerificationMethod },

    /// Remove a verification method
    VmRemove { id: String },

    /// Add a reference to a verification method for a purpose
    RefAdd {
        purpose: VerificationPurpose,
        #[serde(rename = "ref")]
        ref_: String,
    },

    /// Remove a reference
    RefRemove {
        purpose: VerificationPurpose,
        #[serde(rename = "ref")]
        ref_: String,
    },

    /// Add a service
    ServiceAdd { entry: Service },

    /// Remove a service
    ServiceRemove { id: String },

    /// Set a property (LWW)
    PropSet {
        key: String,
        value: serde_json::Value,
        ts: u64, // Lamport time
    },

    /// Add a controller
    ControllerAdd { did: String },

    /// Remove a controller
    ControllerRemove { did: String },

    /// Deactivate the DID
    Deactivate { reason: Option<String> },
}

/// Verification method purpose
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum VerificationPurpose {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

impl std::fmt::Display for VerificationPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication => write!(f, "authentication"),
            Self::AssertionMethod => write!(f, "assertionMethod"),
            Self::KeyAgreement => write!(f, "keyAgreement"),
            Self::CapabilityInvocation => write!(f, "capabilityInvocation"),
            Self::CapabilityDelegation => write!(f, "capabilityDelegation"),
        }
    }
}

/// Authorization proof (Ed25519 signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProof {
    /// Ed25519 signature (base64url)
    pub proof: String,

    /// Key ID that signed (e.g., "did:ajna:abc#key-1")
    pub kid: String,
}

impl Operation {
    /// Create a new operation (automatically computes op_id and signs)
    ///
    /// # Arguments
    /// * `doc` - DID this operation applies to
    /// * `parents` - Parent operation IDs
    /// * `actor` - Actor DID/key ID
    /// * `clock` - Vector clock entry
    /// * `delta` - CRDT mutation
    /// * `signing_key` - Ed25519 signing key
    /// * `kid` - Key ID for signature
    pub fn new(
        doc: String,
        parents: Vec<String>,
        actor: String,
        clock: ClockEntry,
        delta: Delta,
        signing_key: &SigningKey,
        kid: String,
    ) -> Result<Self> {
        let timestamp_ms = Utc::now().timestamp_millis();

        // Create operation without op_id and auth (will be computed)
        let mut op = Operation {
            op_type: OP_TYPE.to_string(),
            doc,
            op_id: String::new(), // Will be computed
            parents,
            actor,
            clock,
            delta,
            auth: AuthProof {
                proof: String::new(), // Will be computed
                kid,
            },
            timestamp_ms,
        };

        // Compute op_id from canonical bytes
        let canonical = op.canonical_bytes()?;
        let op_id_bytes = crypto::hash_operation(&canonical);
        op.op_id = crypto::hash_to_base64url(&op_id_bytes);

        // Sign the operation
        let sig_bytes = crypto::hash_for_signature(&canonical);
        let signature = signing_key.sign(&sig_bytes);
        op.auth.proof = base64_encode_signature(&signature);

        Ok(op)
    }

    /// Get canonical bytes for hashing/signing
    ///
    /// Includes: type, doc, parents, actor, clock, delta, timestamp_ms
    /// Excludes: op_id, auth (these are computed FROM the canonical bytes)
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct CanonicalOp<'a> {
            #[serde(rename = "type")]
            op_type: &'a str,
            doc: &'a str,
            parents: &'a [String],
            actor: &'a str,
            clock: &'a ClockEntry,
            delta: &'a Delta,
            timestamp_ms: i64,
        }

        let canonical = CanonicalOp {
            op_type: &self.op_type,
            doc: &self.doc,
            parents: &self.parents,
            actor: &self.actor,
            clock: &self.clock,
            delta: &self.delta,
            timestamp_ms: self.timestamp_ms,
        };

        serde_json::to_vec(&canonical)
            .map_err(|e| AjnaError::SerializationError(format!("Canonical bytes: {}", e)))
    }

    /// Verify the operation signature
    ///
    /// # Arguments
    /// * `verifying_key` - Ed25519 public key to verify with
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<bool> {
        // Recompute canonical bytes
        let canonical = self.canonical_bytes()?;

        // Hash for signature verification
        let sig_bytes = crypto::hash_for_signature(&canonical);

        // Decode signature
        let signature = base64_decode_signature(&self.auth.proof)?;

        // Verify
        match verifying_key.verify(&sig_bytes, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify the op_id hash
    pub fn verify_op_id(&self) -> Result<bool> {
        let canonical = self.canonical_bytes()?;
        let computed_bytes = crypto::hash_operation(&canonical);
        let computed_id = crypto::hash_to_base64url(&computed_bytes);
        Ok(computed_id == self.op_id)
    }

    /// Get the Lamport timestamp from the clock
    pub fn lamport_time(&self) -> u64 {
        self.clock.counter
    }
}

/// Helper: encode Ed25519 signature to base64url
fn base64_encode_signature(sig: &Signature) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

/// Helper: decode base64url to Ed25519 signature
fn base64_decode_signature(s: &str) -> Result<Signature> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AjnaError::InvalidSignature(format!("Invalid base64url: {}", e)))?;

    Signature::from_slice(&bytes)
        .map_err(|e| AjnaError::InvalidSignature(format!("Invalid signature: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn create_test_key() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_create_operation() {
        let (signing_key, _verifying_key) = create_test_key();

        let op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd {
                entry: VerificationMethod {
                    id: "did:ajna:test#key-1".to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:ajna:test".to_string(),
                    public_key_multibase: "z6MkhaXg...".to_string(),
                    purpose: None,
                },
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("Failed to create operation");

        assert_eq!(op.op_type, OP_TYPE);
        assert!(!op.op_id.is_empty());
        assert_eq!(op.op_id.len(), 43); // base64url of 32 bytes
        assert!(!op.auth.proof.is_empty());
    }

    #[test]
    fn test_verify_signature() {
        let (signing_key, verifying_key) = create_test_key();

        let op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd {
                entry: VerificationMethod {
                    id: "did:ajna:test#key-1".to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:ajna:test".to_string(),
                    public_key_multibase: "z6MkhaXg...".to_string(),
                    purpose: None,
                },
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("Failed to create operation");

        // Should verify with correct key
        assert!(op.verify_signature(&verifying_key).unwrap());

        // Should fail with wrong key
        let (_, wrong_key) = create_test_key();
        assert!(!op.verify_signature(&wrong_key).unwrap());
    }

    #[test]
    fn test_verify_op_id() {
        let (signing_key, _) = create_test_key();

        let op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::Deactivate { reason: None },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("Failed to create operation");

        assert!(op.verify_op_id().unwrap());
    }

    #[test]
    fn test_operation_with_parents() {
        let (signing_key, _) = create_test_key();

        let op = Operation::new(
            "did:ajna:test".to_string(),
            vec!["parent1".to_string(), "parent2".to_string()],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 5,
            },
            Delta::ServiceAdd {
                entry: Service {
                    id: "did:ajna:test#svc1".to_string(),
                    type_: "DIDCommMessaging".to_string(),
                    service_endpoint: "https://example.com".to_string(),
                    properties: std::collections::HashMap::new(),
                },
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("Failed to create operation");

        assert_eq!(op.parents.len(), 2);
        assert_eq!(op.clock.counter, 5);
    }

    #[test]
    fn test_all_delta_types() {
        let (signing_key, _) = create_test_key();

        // VmAdd
        let _op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 1,
            },
            Delta::VmAdd {
                entry: VerificationMethod {
                    id: "did:ajna:test#key-1".to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:ajna:test".to_string(),
                    public_key_multibase: "z6MkhaXg...".to_string(),
                    purpose: None,
                },
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("VmAdd failed");

        // VmRemove
        let _op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 2,
            },
            Delta::VmRemove {
                id: "did:ajna:test#key-1".to_string(),
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("VmRemove failed");

        // RefAdd
        let _op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 3,
            },
            Delta::RefAdd {
                purpose: VerificationPurpose::Authentication,
                ref_: "did:ajna:test#key-1".to_string(),
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("RefAdd failed");

        // PropSet
        let _op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 4,
            },
            Delta::PropSet {
                key: "policy.auth.quorum.update".to_string(),
                value: serde_json::json!(2),
                ts: 4,
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("PropSet failed");

        // Deactivate
        let _op = Operation::new(
            "did:ajna:test".to_string(),
            vec![],
            "did:ajna:device:1".to_string(),
            ClockEntry {
                actor_id: 1,
                counter: 5,
            },
            Delta::Deactivate {
                reason: Some("Test deactivation".to_string()),
            },
            &signing_key,
            "did:ajna:test#key-1".to_string(),
        )
        .expect("Deactivate failed");
    }

    #[test]
    fn test_deterministic_op_id() {
        let (signing_key, _) = create_test_key();

        let create_op = || {
            Operation::new(
                "did:ajna:test".to_string(),
                vec![],
                "did:ajna:device:1".to_string(),
                ClockEntry {
                    actor_id: 1,
                    counter: 1,
                },
                Delta::VmRemove {
                    id: "did:ajna:test#key-1".to_string(),
                },
                &signing_key,
                "did:ajna:test#key-1".to_string(),
            )
        };

        // Note: op_id will be DIFFERENT each time because timestamp_ms changes
        // This is correct - each operation has a unique timestamp
        let op1 = create_op().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let op2 = create_op().unwrap();

        // Different timestamps -> different op_ids
        assert_ne!(op1.timestamp_ms, op2.timestamp_ms);
        assert_ne!(op1.op_id, op2.op_id);
    }
}
