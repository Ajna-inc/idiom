//! DID Record types for storage
//!

use crate::core::document::DidDocument;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// DID Record stored in storage    
///
/// Storage:
/// - Category: `"DidRecord"` (PascalCase!)
/// - Name: UUID (NOT the DID!)
/// - Value: Serialized DidRecord (JSON)
/// - Tags: role, method, did, methodSpecificIdentifier, recipientKeyFingerprints, etc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DidRecord {
    /// Record ID (UUID) - NOT the DID itself!
    pub id: String,

    /// The actual DID
    pub did: String,

    /// Role of this DID (created by us vs received from peer)
    pub role: DidRole,

    /// Cached DID Document (optional)
    #[serde(rename = "didDocument", skip_serializing_if = "Option::is_none")]
    pub did_document: Option<DidDocument>,

    /// Keys linked to this DID (references to KMS)
    pub keys: Vec<DidDocumentKey>,

    /// When this record was created
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    /// When this record was last updated
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Link between DID and KMS key
///
/// This struct represents the relationship between a DID and a key stored in the KMS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocumentKey {
    /// Key ID in Askar KMS (UUID)
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,

    /// Relative key ID in DID Document (e.g., "#key-1" or "#z6Mkp...")
    #[serde(rename = "didDocumentRelativeKeyId")]
    pub did_document_relative_key_id: String,
}

/// Role of a DID (created vs received)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DidRole {
    /// We created this DID
    Created,
    /// We received this DID from a peer
    Received,
}

/// Storage constants
pub mod storage {
    /// Category name for DID records (PascalCase)
    pub const DID_RECORD_TYPE: &str = "DidRecord";

    /// Tag names for DID records
    pub mod tags {
        pub const ROLE: &str = "role";
        pub const METHOD: &str = "method";
        pub const DID: &str = "did";
        pub const METHOD_SPECIFIC_ID: &str = "methodSpecificIdentifier";
    }
}

impl DidRecord {
    /// Create a new DID record
    pub fn new(id: String, did: String, role: DidRole) -> Self {
        Self {
            id,
            did,
            role,
            did_document: None,
            keys: Vec::new(),
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    /// Builder pattern for DID record
    pub fn builder(id: String, did: String, role: DidRole) -> DidRecordBuilder {
        DidRecordBuilder::new(id, did, role)
    }

    /// Add a key to this DID record
    pub fn add_key(&mut self, key: DidDocumentKey) {
        self.keys.push(key);
        self.updated_at = Some(Utc::now());
    }

    /// Set the DID document
    pub fn set_document(&mut self, document: DidDocument) {
        self.did_document = Some(document);
        self.updated_at = Some(Utc::now());
    }

    /// Get all KMS key IDs associated with this DID
    pub fn kms_key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|k| k.kms_key_id.as_str()).collect()
    }

    /// Extract the DID method from the DID
    pub fn method(&self) -> &str {
        // did:method:id -> extract "method"
        let parts: Vec<&str> = self.did.splitn(3, ':').collect();
        parts.get(1).unwrap_or(&"")
    }

    /// Extract the method-specific ID from the DID
    pub fn method_specific_id(&self) -> &str {
        // did:method:id -> extract "id"
        let parts: Vec<&str> = self.did.splitn(3, ':').collect();
        parts.get(2).unwrap_or(&"")
    }
}

/// Builder for DidRecord
pub struct DidRecordBuilder {
    id: String,
    did: String,
    role: DidRole,
    did_document: Option<DidDocument>,
    keys: Vec<DidDocumentKey>,
}

impl DidRecordBuilder {
    pub fn new(id: String, did: String, role: DidRole) -> Self {
        Self {
            id,
            did,
            role,
            did_document: None,
            keys: Vec::new(),
        }
    }

    pub fn document(mut self, document: DidDocument) -> Self {
        self.did_document = Some(document);
        self
    }

    pub fn keys(mut self, keys: Vec<DidDocumentKey>) -> Self {
        self.keys = keys;
        self
    }

    pub fn add_key(mut self, key: DidDocumentKey) -> Self {
        self.keys.push(key);
        self
    }

    pub fn build(self) -> DidRecord {
        DidRecord {
            id: self.id,
            did: self.did,
            role: self.role,
            did_document: self.did_document,
            keys: self.keys,
            created_at: Utc::now(),
            updated_at: None,
        }
    }
}

impl DidDocumentKey {
    /// Create a new DID document key link
    pub fn new(kms_key_id: String, did_document_relative_key_id: String) -> Self {
        Self {
            kms_key_id,
            did_document_relative_key_id,
        }
    }
}

impl DidRole {
    /// Convert to string (lowercase for tags)
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Received => "received",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_record_creation() {
        let record = DidRecord::new(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        );

        assert_eq!(record.id, "uuid-123");
        assert_eq!(record.did, "did:peer:2.Ez6LSms");
        assert_eq!(record.role, DidRole::Created);
        assert!(record.keys.is_empty());
        assert!(record.did_document.is_none());
    }

    #[test]
    fn test_did_record_builder() {
        let key = DidDocumentKey::new("key-uuid-1".to_string(), "#key-1".to_string());

        let record = DidRecord::builder(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        )
        .add_key(key)
        .build();

        assert_eq!(record.keys.len(), 1);
        assert_eq!(record.keys[0].kms_key_id, "key-uuid-1");
    }

    #[test]
    fn test_did_record_serialization() {
        let record = DidRecord::new(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        );

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: DidRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.did, record.did);
        assert_eq!(deserialized.role, record.role);
    }

    #[test]
    fn test_did_record_camel_case() {
        let record = DidRecord::new(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        );

        let json = serde_json::to_value(&record).unwrap();

        assert!(json.get("createdAt").is_some());
        assert!(json.get("didDocument").is_none()); // Optional, should be omitted
    }

    #[test]
    fn test_did_document_key() {
        let key = DidDocumentKey::new("uuid-key-1".to_string(), "#z6Mkp...".to_string());

        let json = serde_json::to_value(&key).unwrap();

        assert_eq!(
            json.get("kmsKeyId").unwrap().as_str().unwrap(),
            "uuid-key-1"
        );
        assert_eq!(
            json.get("didDocumentRelativeKeyId")
                .unwrap()
                .as_str()
                .unwrap(),
            "#z6Mkp..."
        );
    }

    #[test]
    fn test_did_role_serialization() {
        let created = DidRole::Created;
        let received = DidRole::Received;

        let created_json = serde_json::to_string(&created).unwrap();
        let received_json = serde_json::to_string(&received).unwrap();

        assert_eq!(created_json, "\"created\"");
        assert_eq!(received_json, "\"received\"");
    }

    #[test]
    fn test_extract_method() {
        let record = DidRecord::new(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        );

        assert_eq!(record.method(), "peer");
        assert_eq!(record.method_specific_id(), "2.Ez6LSms");
    }

    #[test]
    fn test_kms_key_ids() {
        let mut record = DidRecord::new(
            "uuid-123".to_string(),
            "did:peer:2.Ez6LSms".to_string(),
            DidRole::Created,
        );

        record.add_key(DidDocumentKey::new("key-1".to_string(), "#k1".to_string()));
        record.add_key(DidDocumentKey::new("key-2".to_string(), "#k2".to_string()));

        let key_ids = record.kms_key_ids();
        assert_eq!(key_ids, vec!["key-1", "key-2"]);
    }
}
