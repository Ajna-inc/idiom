//! DID Document types
//!
//! Implements W3C DID Core specification for DID Documents.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DID Document (W3C DID Core specification)
///
/// Represents a DID Document containing verification methods, services, and relationships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DidDocument {
    /// The DID that this document describes
    #[serde(rename = "id")]
    pub id: String,

    /// Verification methods
    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication verification relationships
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<VerificationRelationship>,

    /// Assertion method verification relationships
    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<VerificationRelationship>,

    /// Key agreement verification relationships
    #[serde(
        rename = "keyAgreement",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<VerificationRelationship>,

    /// Capability invocation verification relationships
    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<VerificationRelationship>,

    /// Capability delegation verification relationships
    #[serde(
        rename = "capabilityDelegation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<VerificationRelationship>,

    /// Services
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,

    /// Context (JSON-LD)
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,

    /// Also known as (alternative identifiers)
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,

    /// Controller (who controls this DID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<serde_json::Value>, // Can be string or array
}

/// Verification Method in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationMethod {
    /// Verification method ID (e.g., "did:example:123#key-1")
    pub id: String,

    /// Type of verification method
    #[serde(rename = "type")]
    pub type_: String,

    /// Controller of this verification method
    pub controller: String,

    /// Public key in Base58 format (for legacy methods)
    #[serde(rename = "publicKeyBase58", skip_serializing_if = "Option::is_none")]
    pub public_key_base58: Option<String>,

    /// Public key in multibase format
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,

    /// Public key as JWK (JSON Web Key)
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

/// Verification Relationship (reference or embedded)
///
/// Can be either a string reference (e.g., "#key-1") or an embedded VerificationMethod.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum VerificationRelationship {
    /// Reference to a verification method by ID
    Reference(String),
    /// Embedded verification method
    Embedded(VerificationMethod),
}

/// Service in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Service {
    /// Service ID (e.g., "did:example:123#service-1")
    pub id: String,

    /// Service type (e.g., "DIDCommMessaging")
    /// Can be a string or array of strings
    #[serde(rename = "type", with = "service_type_serde")]
    pub type_: String,

    /// Service endpoint (can be string, array, or object)
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,

    /// Additional service-specific properties
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

/// Custom serde module to handle type being either string or array of strings
mod service_type_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(type_: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(type_)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrArray {
            String(String),
            Array(Vec<String>),
        }

        match StringOrArray::deserialize(deserializer)? {
            StringOrArray::String(s) => Ok(s),
            StringOrArray::Array(arr) => {
                // Take the first element if array
                arr.into_iter()
                    .next()
                    .ok_or_else(|| Error::custom("type array cannot be empty"))
            }
        }
    }
}

impl DidDocument {
    /// Create a new minimal DID Document
    pub fn new(id: String) -> Self {
        Self {
            id,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            context: None,
            also_known_as: Vec::new(),
            controller: None,
        }
    }

    /// Add a verification method
    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        self.verification_method.push(method);
    }

    /// Add an authentication verification relationship
    pub fn add_authentication(&mut self, relationship: VerificationRelationship) {
        self.authentication.push(relationship);
    }

    /// Add a key agreement verification relationship
    pub fn add_key_agreement(&mut self, relationship: VerificationRelationship) {
        self.key_agreement.push(relationship);
    }

    /// Add a service
    pub fn add_service(&mut self, service: Service) {
        self.service.push(service);
    }
}

impl VerificationMethod {
    /// Create a new verification method
    pub fn new(id: String, type_: String, controller: String) -> Self {
        Self {
            id,
            type_,
            controller,
            public_key_base58: None,
            public_key_multibase: None,
            public_key_jwk: None,
        }
    }

    /// Set public key in Base58 format
    pub fn with_public_key_base58(mut self, key: String) -> Self {
        self.public_key_base58 = Some(key);
        self
    }

    /// Set public key in multibase format
    pub fn with_public_key_multibase(mut self, key: String) -> Self {
        self.public_key_multibase = Some(key);
        self
    }

    /// Set public key as JWK
    pub fn with_public_key_jwk(mut self, jwk: serde_json::Value) -> Self {
        self.public_key_jwk = Some(jwk);
        self
    }
}

impl Service {
    /// Create a new service
    pub fn new(id: String, type_: String, service_endpoint: serde_json::Value) -> Self {
        Self {
            id,
            type_,
            service_endpoint,
            properties: HashMap::new(),
        }
    }

    /// Add a custom property to the service
    pub fn with_property(mut self, key: String, value: serde_json::Value) -> Self {
        self.properties.insert(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_did_document_creation() {
        let doc = DidDocument::new("did:example:123".to_string());
        assert_eq!(doc.id, "did:example:123");
        assert!(doc.verification_method.is_empty());
    }

    #[test]
    fn test_verification_method() {
        let vm = VerificationMethod::new(
            "did:example:123#key-1".to_string(),
            "Ed25519VerificationKey2018".to_string(),
            "did:example:123".to_string(),
        )
        .with_public_key_base58("H3C2AVvL...".to_string());

        assert_eq!(vm.id, "did:example:123#key-1");
        assert_eq!(vm.type_, "Ed25519VerificationKey2018");
        assert!(vm.public_key_base58.is_some());
    }

    #[test]
    fn test_service() {
        let service = Service::new(
            "did:example:123#service-1".to_string(),
            "DIDCommMessaging".to_string(),
            json!("https://example.com/endpoint"),
        );

        assert_eq!(service.id, "did:example:123#service-1");
        assert_eq!(service.type_, "DIDCommMessaging");
    }

    #[test]
    fn test_did_document_serialization() {
        let mut doc = DidDocument::new("did:example:123".to_string());

        let vm = VerificationMethod::new(
            "did:example:123#key-1".to_string(),
            "Ed25519VerificationKey2018".to_string(),
            "did:example:123".to_string(),
        )
        .with_public_key_base58("H3C2AVvL...".to_string());

        doc.add_verification_method(vm);
        doc.add_authentication(VerificationRelationship::Reference("#key-1".to_string()));

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, doc.id);
        assert_eq!(deserialized.verification_method.len(), 1);
        assert_eq!(deserialized.authentication.len(), 1);
    }

    #[test]
    fn test_verification_relationship_reference() {
        let rel = VerificationRelationship::Reference("#key-1".to_string());
        let json = serde_json::to_value(&rel).unwrap();
        assert_eq!(json, json!("#key-1"));
    }

    #[test]
    fn test_verification_relationship_embedded() {
        let vm = VerificationMethod::new(
            "#key-1".to_string(),
            "Ed25519VerificationKey2018".to_string(),
            "did:example:123".to_string(),
        );

        let rel = VerificationRelationship::Embedded(vm);
        let json = serde_json::to_value(&rel).unwrap();

        assert!(json.is_object());
        assert_eq!(json.get("id").unwrap(), "#key-1");
    }
}
