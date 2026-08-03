//! AjnaDocument - CRDT-based DID Document
//!
//! This module defines the core DID document structure for did:ajna,
//! which uses CRDTs for conflict-free updates.

use crate::ajna::{AjnaError, LWWMap, ORSet, Result, VectorClock};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Verification method type constants
pub mod verification_method_types {
    /// SLH-DSA-SHAKE-128s (NIST FIPS 205) - Quantum-resistant signature scheme
    /// - Public key: 32 bytes
    /// - Signature: 7856 bytes
    /// - Security level: 128-bit quantum-safe
    /// - Use for: User signatures, DID operations, general-purpose signing
    pub const SLHDSA_2024: &str = "SLH-DSA-SHAKE-128s-2024";

    /// ML-DSA-65 (NIST FIPS 204) - Quantum-resistant signature scheme
    /// - Public key: 1952 bytes
    /// - Signature: 3309 bytes
    /// - Security level: ~128-bit quantum-safe
    /// - Use for: Validator signatures, consensus operations, high-throughput signing
    pub const MLDSA65_2024: &str = "ML-DSA-65-2024";

    /// DEPRECATED: Ed25519 - Classical signature scheme (quantum-vulnerable)
    /// Only for backward compatibility with existing DIDs
    #[deprecated(note = "Use SLHDSA_2024 for quantum safety")]
    pub const ED25519_2020: &str = "Ed25519VerificationKey2020";

    /// DEPRECATED: X25519 - Classical key agreement (quantum-vulnerable)
    /// Only for backward compatibility with existing DIDs
    #[deprecated(note = "Post-quantum key agreement not yet standardized")]
    pub const X25519_2020: &str = "X25519KeyAgreementKey2020";

    /// DEPRECATED: ECDSA P-256 - Classical signature scheme (quantum-vulnerable)
    /// Only for backward compatibility with existing DIDs
    #[deprecated(note = "Use SLHDSA_2024 for quantum safety")]
    pub const ECDSA_SECP256R1_2019: &str = "EcdsaSecp256r1VerificationKey2019";
}

/// Verification method (public key) in a DID document
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Full ID of the verification method (e.g., did:ajna:abc#key-1)
    pub id: String,

    /// Type of the verification method
    #[serde(rename = "type")]
    pub type_: String,

    /// Controller DID
    pub controller: String,

    /// Public key in multibase format
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,

    /// Optional purpose (authentication, assertion, keyAgreement, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Vec<String>>,
}

impl VerificationMethod {
    /// Create a new verification method with SLH-DSA quantum-resistant key
    pub fn new_slhdsa(
        did: &str,
        key_id: &str,
        public_key_multibase: String,
        purpose: Option<Vec<String>>,
    ) -> Self {
        Self {
            id: format!("{}#{}", did, key_id),
            type_: verification_method_types::SLHDSA_2024.to_string(),
            controller: did.to_string(),
            public_key_multibase,
            purpose,
        }
    }

    /// Create a new verification method with ML-DSA-65 quantum-resistant key
    pub fn new_mldsa65(
        did: &str,
        key_id: &str,
        public_key_multibase: String,
        purpose: Option<Vec<String>>,
    ) -> Self {
        Self {
            id: format!("{}#{}", did, key_id),
            type_: verification_method_types::MLDSA65_2024.to_string(),
            controller: did.to_string(),
            public_key_multibase,
            purpose,
        }
    }

    /// Check if this verification method uses a quantum-resistant key type
    pub fn is_quantum_resistant(&self) -> bool {
        matches!(
            self.type_.as_str(),
            verification_method_types::SLHDSA_2024 | verification_method_types::MLDSA65_2024
        )
    }

    /// Check if this verification method uses a deprecated classical key type
    #[allow(deprecated)] // intentionally matches the deprecated key-type constants
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self.type_.as_str(),
            verification_method_types::ED25519_2020
                | verification_method_types::X25519_2020
                | verification_method_types::ECDSA_SECP256R1_2019
        )
    }
}

/// Service endpoint in a DID document
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Service {
    /// Service ID (e.g., "didcomm", "profile")
    pub id: String,

    /// Service type
    #[serde(rename = "type")]
    pub type_: String,

    /// Service endpoint URL
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,

    /// Optional additional properties
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

/// CRDT-based DID Document for did:ajna
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjnaDocument {
    /// DID identifier (e.g., did:ajna:abc123)
    pub id: String,

    /// Verification methods (uses OR-Set CRDT)
    #[serde(rename = "verificationMethod")]
    pub verification_methods: ORSet<VerificationMethod>,

    /// References to verification methods by purpose
    /// Each purpose has its own OR-Set of references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ORSet<String>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "assertionMethod")]
    pub assertion_method: Option<ORSet<String>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "keyAgreement")]
    pub key_agreement: Option<ORSet<String>>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "capabilityInvocation"
    )]
    pub capability_invocation: Option<ORSet<String>>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "capabilityDelegation"
    )]
    pub capability_delegation: Option<ORSet<String>>,

    /// Controllers (uses OR-Set CRDT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<ORSet<String>>,

    /// Service endpoints (uses LWW-Map CRDT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<LWWMap<String, Service>>,

    /// Policy properties (LWW-Map)
    /// e.g., {"auth.quorum.update": 2, "auth.threshold": "2-of-3"}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<LWWMap<String, serde_json::Value>>,

    /// Deactivated flag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// Vector clock for causality tracking
    #[serde(rename = "clock")]
    pub vector_clock: VectorClock,

    /// Creation timestamp
    pub created: DateTime<Utc>,

    /// Last update timestamp (maintained locally)
    pub updated: DateTime<Utc>,

    /// Node ID that created/owns this document
    #[serde(rename = "nodeId")]
    pub node_id: String,

    /// Optional blockchain anchor (for finality)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_anchor: Option<BlockchainAnchor>,
}

/// Blockchain anchor information (optional)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    /// Blockchain network (e.g., "ajna-mainnet")
    pub network: String,

    /// Transaction hash
    pub tx_hash: String,

    /// Block number
    pub block_number: u64,

    /// Timestamp of anchor
    pub timestamp: DateTime<Utc>,

    /// Merkle root of the document state
    pub merkle_root: String,
}

impl AjnaDocument {
    /// Create a new AjnaDocument
    pub fn new(did: String, node_id: String) -> Self {
        Self {
            id: did,
            verification_methods: ORSet::new(),
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            controller: None,
            service: None,
            policy: None,
            deactivated: None,
            vector_clock: VectorClock::new(),
            created: Utc::now(),
            updated: Utc::now(),
            node_id,
            blockchain_anchor: None,
        }
    }

    /// Create a genesis document with initial controllers and policy
    pub fn new_with_genesis(
        did: String,
        node_id: String,
        initial_controllers: Vec<String>,
        initial_policy: Vec<(String, serde_json::Value)>,
    ) -> Self {
        let mut doc = Self::new(did, node_id);

        // Add initial controllers
        if !initial_controllers.is_empty() {
            let mut controllers = ORSet::new();
            for controller in initial_controllers {
                controllers.add(controller);
            }
            doc.controller = Some(controllers);
        }

        // Add initial policy
        if !initial_policy.is_empty() {
            let mut policy = LWWMap::new();
            for (key, value) in initial_policy {
                policy.set(key, value, doc.node_id.clone());
            }
            doc.policy = Some(policy);
        }

        doc
    }

    /// Add a verification method to the document
    pub fn add_verification_method(&mut self, method: VerificationMethod) -> Uuid {
        let uuid = self.verification_methods.add(method);
        self.vector_clock.increment(&self.node_id);
        self.updated = Utc::now();
        uuid
    }

    /// Remove a verification method by ID
    pub fn remove_verification_method(&mut self, method_id: &str) {
        // Find the method and remove it
        let methods = self.verification_methods.elements();
        for method in methods {
            if method.id == method_id {
                self.verification_methods.remove(&method);
                break;
            }
        }
        self.vector_clock.increment(&self.node_id);
        self.updated = Utc::now();
    }

    /// Add or update a service
    pub fn set_service(&mut self, service: Service) {
        let service_map = self.service.get_or_insert_with(LWWMap::new);
        service_map.set(service.id.clone(), service, self.node_id.clone());
        self.vector_clock.increment(&self.node_id);
        self.updated = Utc::now();
    }

    /// Add or update a service with a specific timestamp
    pub fn set_service_with_timestamp(
        &mut self,
        service: Service,
        timestamp: DateTime<Utc>,
        node_id: String,
    ) {
        let service_map = self.service.get_or_insert_with(LWWMap::new);
        service_map.set_with_timestamp(service.id.clone(), service, timestamp, node_id);
        self.updated = Utc::now();
    }

    /// Remove a service
    pub fn remove_service(&mut self, service_id: &str) {
        if let Some(service_map) = &mut self.service {
            service_map.remove(service_id.to_string(), self.node_id.clone());
        }
        self.vector_clock.increment(&self.node_id);
        self.updated = Utc::now();
    }

    /// Remove a service with a specific timestamp
    pub fn remove_service_with_timestamp(
        &mut self,
        service_id: &str,
        timestamp: DateTime<Utc>,
        node_id: String,
    ) {
        if let Some(service_map) = &mut self.service {
            service_map.remove_with_timestamp(service_id.to_string(), timestamp, node_id);
        }
        self.updated = Utc::now();
    }

    /// Get a verification method by ID
    pub fn get_verification_method(&self, method_id: &str) -> Option<VerificationMethod> {
        self.verification_methods
            .elements()
            .into_iter()
            .find(|m| m.id == method_id)
    }

    /// Get all verification methods with a specific purpose
    pub fn get_verification_methods_by_purpose(&self, purpose: &str) -> Vec<VerificationMethod> {
        self.verification_methods
            .elements()
            .into_iter()
            .filter(|m| {
                m.purpose
                    .as_ref()
                    .is_some_and(|purposes| purposes.contains(&purpose.to_string()))
            })
            .collect()
    }

    /// Get a service by ID
    pub fn get_service(&self, service_id: &str) -> Option<&Service> {
        self.service.as_ref()?.get(&service_id.to_string())
    }

    /// Get all services of a specific type
    pub fn get_services_by_type(&self, service_type: &str) -> Vec<Service> {
        self.service
            .as_ref()
            .map(|s| {
                s.values()
                    .into_iter()
                    .filter(|svc| svc.type_ == service_type)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge another AjnaDocument into this one
    ///
    /// This implements the CRDT merge operation
    pub fn merge(&mut self, other: &AjnaDocument) -> Result<()> {
        // Verify we're merging the same DID
        if self.id != other.id {
            return Err(AjnaError::InvalidOperation(
                "Cannot merge documents with different DIDs".to_string(),
            ));
        }

        // Merge verification methods (OR-Set merge)
        self.verification_methods.merge(&other.verification_methods);

        // Merge services (LWW-Map merge)
        if let Some(ref other_service) = other.service {
            let service_map = self.service.get_or_insert_with(LWWMap::new);
            service_map.merge(other_service);
        }

        // Merge purpose OR-Sets
        if let Some(ref other_auth) = other.authentication {
            let auth = self.authentication.get_or_insert_with(ORSet::new);
            auth.merge(other_auth);
        }
        if let Some(ref other_assertion) = other.assertion_method {
            let assertion = self.assertion_method.get_or_insert_with(ORSet::new);
            assertion.merge(other_assertion);
        }
        if let Some(ref other_key_agreement) = other.key_agreement {
            let key_agreement = self.key_agreement.get_or_insert_with(ORSet::new);
            key_agreement.merge(other_key_agreement);
        }
        if let Some(ref other_cap_invocation) = other.capability_invocation {
            let cap_invocation = self.capability_invocation.get_or_insert_with(ORSet::new);
            cap_invocation.merge(other_cap_invocation);
        }
        if let Some(ref other_cap_delegation) = other.capability_delegation {
            let cap_delegation = self.capability_delegation.get_or_insert_with(ORSet::new);
            cap_delegation.merge(other_cap_delegation);
        }

        // Merge controllers
        if let Some(ref other_controller) = other.controller {
            let controller = self.controller.get_or_insert_with(ORSet::new);
            controller.merge(other_controller);
        }

        // Merge policy
        if let Some(ref other_policy) = other.policy {
            let policy = self.policy.get_or_insert_with(LWWMap::new);
            policy.merge(other_policy);
        }

        // Merge deactivated (true wins)
        if other.deactivated == Some(true) {
            self.deactivated = Some(true);
        }

        // Merge vector clocks
        self.vector_clock.merge(&other.vector_clock);

        // Update timestamp to latest
        if other.updated > self.updated {
            self.updated = other.updated;
        }

        // Keep earliest creation time
        if other.created < self.created {
            self.created = other.created;
        }

        // Keep blockchain anchor with latest block number
        if let Some(ref other_anchor) = other.blockchain_anchor {
            match &self.blockchain_anchor {
                Some(ref self_anchor) => {
                    if other_anchor.block_number > self_anchor.block_number {
                        self.blockchain_anchor = Some(other_anchor.clone());
                    }
                }
                None => {
                    self.blockchain_anchor = Some(other_anchor.clone());
                }
            }
        }

        Ok(())
    }

    // ==================== Operation V2 Application Methods ====================

    /// Apply an operation_v2::Delta to this document
    ///
    /// This is the main entry point for applying operations
    pub fn apply_delta_v2(&mut self, delta: &crate::ajna::operation_v2::Delta) -> Result<()> {
        use crate::ajna::operation_v2::Delta;

        match delta {
            Delta::VmAdd { entry } => {
                self.verification_methods.add(entry.clone());
            }
            Delta::VmRemove { id } => {
                let methods = self.verification_methods.elements();
                for method in methods {
                    if method.id == *id {
                        self.verification_methods.remove(&method);
                        break;
                    }
                }
            }
            Delta::RefAdd { purpose, ref_ } => {
                self.add_purpose_ref(*purpose, ref_.clone())?;
            }
            Delta::RefRemove { purpose, ref_ } => {
                self.remove_purpose_ref(*purpose, ref_)?;
            }
            Delta::ServiceAdd { entry } => {
                let service_map = self.service.get_or_insert_with(LWWMap::new);
                service_map.set(entry.id.clone(), entry.clone(), self.node_id.clone());
            }
            Delta::ServiceRemove { id } => {
                if let Some(service_map) = &mut self.service {
                    service_map.remove(id.clone(), self.node_id.clone());
                }
            }
            Delta::PropSet { key, value, ts } => {
                let policy_map = self.policy.get_or_insert_with(LWWMap::new);
                // Use Lamport timestamp and node_id for LWW
                policy_map.set_with_timestamp(
                    key.clone(),
                    value.clone(),
                    chrono::Utc.timestamp_millis_opt(*ts as i64).unwrap(),
                    self.node_id.clone(),
                );
            }
            Delta::ControllerAdd { did } => {
                let controllers = self.controller.get_or_insert_with(ORSet::new);
                controllers.add(did.clone());
            }
            Delta::ControllerRemove { did } => {
                if let Some(controllers) = &mut self.controller {
                    controllers.remove(did);
                }
            }
            Delta::Deactivate { .. } => {
                self.deactivated = Some(true);
            }
        }

        self.updated = Utc::now();
        Ok(())
    }

    /// Add a reference to a verification method for a specific purpose
    fn add_purpose_ref(
        &mut self,
        purpose: crate::ajna::operation_v2::VerificationPurpose,
        ref_: String,
    ) -> Result<()> {
        use crate::ajna::operation_v2::VerificationPurpose;

        let or_set = match purpose {
            VerificationPurpose::Authentication => {
                self.authentication.get_or_insert_with(ORSet::new)
            }
            VerificationPurpose::AssertionMethod => {
                self.assertion_method.get_or_insert_with(ORSet::new)
            }
            VerificationPurpose::KeyAgreement => self.key_agreement.get_or_insert_with(ORSet::new),
            VerificationPurpose::CapabilityInvocation => {
                self.capability_invocation.get_or_insert_with(ORSet::new)
            }
            VerificationPurpose::CapabilityDelegation => {
                self.capability_delegation.get_or_insert_with(ORSet::new)
            }
        };

        or_set.add(ref_);
        Ok(())
    }

    /// Remove a reference from a verification method purpose
    fn remove_purpose_ref(
        &mut self,
        purpose: crate::ajna::operation_v2::VerificationPurpose,
        ref_: &str,
    ) -> Result<()> {
        use crate::ajna::operation_v2::VerificationPurpose;

        let or_set = match purpose {
            VerificationPurpose::Authentication => self.authentication.as_mut(),
            VerificationPurpose::AssertionMethod => self.assertion_method.as_mut(),
            VerificationPurpose::KeyAgreement => self.key_agreement.as_mut(),
            VerificationPurpose::CapabilityInvocation => self.capability_invocation.as_mut(),
            VerificationPurpose::CapabilityDelegation => self.capability_delegation.as_mut(),
        };

        if let Some(set) = or_set {
            set.remove(&ref_.to_string());
        }

        Ok(())
    }

    /// Check if this document is deactivated
    pub fn is_deactivated(&self) -> bool {
        self.deactivated.unwrap_or(false)
    }

    /// Get policy value
    pub fn get_policy(&self, key: &str) -> Option<&serde_json::Value> {
        self.policy.as_ref().and_then(|p| p.get(&key.to_string()))
    }

    /// Get policy value as integer
    pub fn get_policy_int(&self, key: &str) -> Option<i64> {
        self.get_policy(key).and_then(|v| v.as_i64())
    }

    /// Check if a DID is a controller
    pub fn is_controller(&self, did: &str) -> bool {
        self.controller
            .as_ref()
            .map(|c| c.contains(&did.to_string()))
            .unwrap_or(false)
    }

    /// Convert to standard DID Document format (W3C)
    pub fn to_did_document(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": self.id,
            "verificationMethod": self.verification_methods.elements(),
            "service": self.service.as_ref().map(|s| s.values()).unwrap_or_default(),
        });

        // Add authentication, assertionMethod, etc. based on purpose
        let auth_methods: Vec<String> = self
            .get_verification_methods_by_purpose("authentication")
            .into_iter()
            .map(|m| m.id)
            .collect();

        if !auth_methods.is_empty() {
            doc["authentication"] = serde_json::json!(auth_methods);
        }

        let assertion_methods: Vec<String> = self
            .get_verification_methods_by_purpose("assertionMethod")
            .into_iter()
            .map(|m| m.id)
            .collect();

        if !assertion_methods.is_empty() {
            doc["assertionMethod"] = serde_json::json!(assertion_methods);
        }

        let key_agreement: Vec<String> = self
            .get_verification_methods_by_purpose("keyAgreement")
            .into_iter()
            .map(|m| m.id)
            .collect();

        if !key_agreement.is_empty() {
            doc["keyAgreement"] = serde_json::json!(key_agreement);
        }

        doc
    }

    /// Check if this document has updates relative to another
    pub fn has_updates_since(&self, other: &AjnaDocument) -> bool {
        // Check if our clock has events the other doesn't
        for node in self.vector_clock.node_ids() {
            if self.vector_clock.get(&node) > other.vector_clock.get(&node) {
                return true;
            }
        }
        false
    }

    /// Get the total number of events (updates) in this document
    pub fn total_updates(&self) -> u64 {
        self.vector_clock.total_events()
    }

    /// Set blockchain anchor
    pub fn set_blockchain_anchor(&mut self, anchor: BlockchainAnchor) {
        self.blockchain_anchor = Some(anchor);
    }

    /// Create an AjnaDocument from a crate::core::DidDocument
    ///
    /// This converts a standard W3C DID Core document to the CRDT-based AjnaDocument format.
    /// This is a "snapshot" conversion - it creates a new CRDT with the current state
    /// but without historical causality tracking.
    pub fn from_did_core(doc: &crate::core::DidDocument) -> Result<Self> {
        // Generate a node ID for this conversion (using the DID)
        let node_id = doc.id.clone();

        // Convert verification methods
        let mut verification_methods = ORSet::new();
        for vm in &doc.verification_method {
            // Determine purpose from relationships
            let mut purposes = Vec::new();
            for auth in &doc.authentication {
                if let crate::core::VerificationRelationship::Reference(ref id) = auth {
                    if id.contains(&vm.id) || vm.id.ends_with(id) {
                        purposes.push("authentication".to_string());
                        break;
                    }
                }
            }
            for ka in &doc.key_agreement {
                if let crate::core::VerificationRelationship::Reference(ref id) = ka {
                    if id.contains(&vm.id) || vm.id.ends_with(id) {
                        purposes.push("keyAgreement".to_string());
                        break;
                    }
                }
            }
            for am in &doc.assertion_method {
                if let crate::core::VerificationRelationship::Reference(ref id) = am {
                    if id.contains(&vm.id) || vm.id.ends_with(id) {
                        purposes.push("assertionMethod".to_string());
                        break;
                    }
                }
            }

            // Get public key
            let public_key = vm
                .public_key_multibase
                .clone()
                .or_else(|| vm.public_key_base58.clone())
                .unwrap_or_default();

            let ajna_vm = VerificationMethod {
                id: vm.id.clone(),
                type_: vm.type_.clone(),
                controller: vm.controller.clone(),
                public_key_multibase: public_key,
                purpose: if purposes.is_empty() {
                    None
                } else {
                    Some(purposes)
                },
            };

            verification_methods.add(ajna_vm);
        }

        // Convert services
        let mut service_map = LWWMap::new();
        for svc in &doc.service {
            // Extract endpoint URL
            let endpoint = if svc.service_endpoint.is_string() {
                svc.service_endpoint.as_str().unwrap_or("").to_string()
            } else if let Some(obj) = svc.service_endpoint.as_object() {
                obj.get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                String::new()
            };

            let ajna_service = Service {
                id: svc.id.clone(),
                type_: svc.type_.clone(),
                service_endpoint: endpoint,
                properties: HashMap::new(),
            };

            service_map.set(svc.id.clone(), ajna_service, node_id.clone());
        }

        // Build the AjnaDocument
        let now = Utc::now();
        Ok(Self {
            id: doc.id.clone(),
            verification_methods,
            authentication: if doc.authentication.is_empty() {
                None
            } else {
                let mut set = ORSet::new();
                for auth in &doc.authentication {
                    if let crate::core::VerificationRelationship::Reference(ref id) = auth {
                        set.add(id.clone());
                    }
                }
                Some(set)
            },
            assertion_method: if doc.assertion_method.is_empty() {
                None
            } else {
                let mut set = ORSet::new();
                for am in &doc.assertion_method {
                    if let crate::core::VerificationRelationship::Reference(ref id) = am {
                        set.add(id.clone());
                    }
                }
                Some(set)
            },
            key_agreement: if doc.key_agreement.is_empty() {
                None
            } else {
                let mut set = ORSet::new();
                for ka in &doc.key_agreement {
                    if let crate::core::VerificationRelationship::Reference(ref id) = ka {
                        set.add(id.clone());
                    }
                }
                Some(set)
            },
            capability_invocation: None,
            capability_delegation: None,
            controller: None,
            service: if doc.service.is_empty() {
                None
            } else {
                Some(service_map)
            },
            policy: None,
            deactivated: None,
            vector_clock: VectorClock::new(),
            created: now,
            updated: now,
            node_id,
            blockchain_anchor: None,
        })
    }
}

impl PartialEq for AjnaDocument {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.verification_methods == other.verification_methods
            && self.service == other.service
            && self.vector_clock == other.vector_clock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_method(did: &str, key_num: u32) -> VerificationMethod {
        VerificationMethod {
            id: format!("{}#key-{}", did, key_num),
            type_: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase: format!("z6Mktest{}", key_num),
            purpose: Some(vec!["authentication".to_string()]),
        }
    }

    fn create_test_service(id: &str) -> Service {
        Service {
            id: id.to_string(),
            type_: "DIDCommMessaging".to_string(),
            service_endpoint: format!("https://{}.example.com", id),
            properties: HashMap::new(),
        }
    }

    #[test]
    fn test_create_document() {
        let doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        assert_eq!(doc.id, "did:ajna:test123");
        assert_eq!(doc.node_id, "node_a");
        assert_eq!(doc.verification_methods.len(), 0);
        assert_eq!(doc.service.as_ref().map(|s| s.len()).unwrap_or(0), 0);
    }

    #[test]
    fn test_add_verification_method() {
        let mut doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        let method = create_test_method("did:ajna:test123", 1);
        doc.add_verification_method(method.clone());

        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.verification_methods.contains(&method));
        assert_eq!(doc.vector_clock.get("node_a"), 1);
    }

    #[test]
    fn test_remove_verification_method() {
        let mut doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        let method = create_test_method("did:ajna:test123", 1);
        doc.add_verification_method(method.clone());
        assert_eq!(doc.verification_methods.len(), 1);

        doc.remove_verification_method(&method.id);
        assert_eq!(doc.verification_methods.len(), 0);
        assert_eq!(doc.vector_clock.get("node_a"), 2); // add + remove
    }

    #[test]
    fn test_add_service() {
        let mut doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        let service = create_test_service("didcomm");
        doc.set_service(service.clone());

        assert_eq!(doc.service.as_ref().map(|s| s.len()).unwrap_or(0), 1);
        assert_eq!(doc.get_service("didcomm"), Some(&service));
    }

    #[test]
    fn test_merge_documents() {
        let mut doc1 = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());
        let mut doc2 = AjnaDocument::new("did:ajna:test123".to_string(), "node_b".to_string());

        // doc1 adds key1
        let method1 = create_test_method("did:ajna:test123", 1);
        doc1.add_verification_method(method1.clone());

        // doc2 adds key2
        let method2 = create_test_method("did:ajna:test123", 2);
        doc2.add_verification_method(method2.clone());

        // Merge doc2 into doc1
        doc1.merge(&doc2).unwrap();

        // Should have both keys
        assert_eq!(doc1.verification_methods.len(), 2);
        assert!(doc1.verification_methods.contains(&method1));
        assert!(doc1.verification_methods.contains(&method2));

        // Vector clock should have both nodes
        assert_eq!(doc1.vector_clock.get("node_a"), 1);
        assert_eq!(doc1.vector_clock.get("node_b"), 1);
    }

    #[test]
    fn test_merge_different_dids_fails() {
        let mut doc1 = AjnaDocument::new("did:ajna:abc".to_string(), "node_a".to_string());
        let doc2 = AjnaDocument::new("did:ajna:xyz".to_string(), "node_b".to_string());

        let result = doc1.merge(&doc2);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_did_document() {
        let mut doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        let method = create_test_method("did:ajna:test123", 1);
        doc.add_verification_method(method);

        let service = create_test_service("didcomm");
        doc.set_service(service);

        let did_doc = doc.to_did_document();

        assert_eq!(did_doc["id"], "did:ajna:test123");
        assert!(did_doc["verificationMethod"].is_array());
        assert!(did_doc["service"].is_array());
        assert!(did_doc["authentication"].is_array());
    }

    #[test]
    fn test_has_updates_since() {
        let mut doc1 = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());
        let doc2 = doc1.clone();

        // Initially no updates
        assert!(!doc1.has_updates_since(&doc2));

        // Add a key
        let method = create_test_method("did:ajna:test123", 1);
        doc1.add_verification_method(method);

        // Now doc1 has updates
        assert!(doc1.has_updates_since(&doc2));
        assert!(!doc2.has_updates_since(&doc1));
    }

    #[test]
    fn test_get_verification_methods_by_purpose() {
        let mut doc = AjnaDocument::new("did:ajna:test123".to_string(), "node_a".to_string());

        let mut auth_method = create_test_method("did:ajna:test123", 1);
        auth_method.purpose = Some(vec!["authentication".to_string()]);

        let mut assertion_method = create_test_method("did:ajna:test123", 2);
        assertion_method.purpose = Some(vec!["assertionMethod".to_string()]);

        doc.add_verification_method(auth_method.clone());
        doc.add_verification_method(assertion_method);

        let auth_methods = doc.get_verification_methods_by_purpose("authentication");
        assert_eq!(auth_methods.len(), 1);
        assert_eq!(auth_methods[0].id, auth_method.id);
    }
}
