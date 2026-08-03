use crate::domain::{DidExchangeRole, DidExchangeState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Connection Record
///
/// Represents a DID Exchange connection with full state tracking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Unique identifier for this connection
    pub id: String,

    /// Current state of the DID Exchange protocol
    pub state: DidExchangeState,

    /// Role in the DID Exchange protocol
    pub role: DidExchangeRole,

    /// Thread ID from the request message
    #[serde(rename = "threadId")]
    pub thread_id: String,

    /// Parent thread ID (invitation ID from OOB)
    #[serde(rename = "outOfBandId")]
    pub out_of_band_id: String,

    /// Our DID for this connection
    pub did: String,

    /// Their DID for this connection (optional until response received)
    #[serde(rename = "theirDid", skip_serializing_if = "Option::is_none")]
    pub their_did: Option<String>,

    /// Their Ed25519 authentication public key (base58) from did_doc~attach
    /// This is used as the `kid` in JWE recipient headers (for wallet lookup)
    #[serde(
        rename = "theirAuthenticationKeyBase58",
        skip_serializing_if = "Option::is_none"
    )]
    pub their_authentication_key_base58: Option<String>,

    /// Their X25519 keyAgreement public key (base58) from did_doc~attach
    /// This is used for ECDH encryption without DID resolution
    #[serde(
        rename = "theirKeyAgreementKeyBase58",
        skip_serializing_if = "Option::is_none"
    )]
    pub their_key_agreement_key_base58: Option<String>,

    /// Our label (human-readable name)
    #[serde(rename = "ourLabel", skip_serializing_if = "Option::is_none")]
    pub our_label: Option<String>,

    /// Their label (from request message)
    #[serde(rename = "theirLabel", skip_serializing_if = "Option::is_none")]
    pub their_label: Option<String>,

    /// Previous DIDs we've used (for DID rotation)
    #[serde(
        rename = "previousDids",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub previous_dids: Vec<String>,

    /// Previous DIDs they've used (for DID rotation)
    #[serde(
        rename = "previousTheirDids",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub previous_their_dids: Vec<String>,

    /// Auto-accept connection flag
    #[serde(
        rename = "autoAcceptConnection",
        skip_serializing_if = "Option::is_none"
    )]
    pub auto_accept_connection: Option<bool>,

    /// Image URL for connection (optional)
    #[serde(rename = "imageUrl", skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,

    /// Error message if connection failed
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Custom metadata for application-specific data (e.g., PLC height, peer capabilities)
    /// This field is optional and defaults to null to maintain backward compatibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// DIDComm version negotiated for this connection.
    /// "1" = DIDComm v1 (did:peer:1, base58 keys, did_doc~attach)
    /// "2" = DIDComm v2 (did:peer:2, self-resolving, EnvelopeService packing)
    /// None = treated as "1" for backward compatibility with existing records.
    #[serde(
        rename = "didcommVersion",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub didcomm_version: Option<String>,

    /// Protocol type (always "connections" for DID Exchange)
    pub protocol: String,

    /// Creation timestamp
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,

    /// Tags for querying (not serialized to storage)
    #[serde(skip)]
    pub tags: ConnectionTags,
}

/// Tags for efficient querying
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionTags {
    pub role: DidExchangeRole,
    pub state: DidExchangeState,
    pub thread_id: String,
    pub out_of_band_id: String,
    pub did: String,
    pub their_did: Option<String>,
}

impl Default for ConnectionTags {
    fn default() -> Self {
        Self {
            role: DidExchangeRole::Requester,
            state: DidExchangeState::Start,
            thread_id: String::new(),
            out_of_band_id: String::new(),
            did: String::new(),
            their_did: None,
        }
    }
}

impl ConnectionRecord {
    /// Protocol constant
    pub const PROTOCOL: &'static str = "connections/1.0";

    /// Create a new connection record
    pub fn new(
        role: DidExchangeRole,
        state: DidExchangeState,
        thread_id: String,
        out_of_band_id: String,
        did: String,
    ) -> Self {
        let now = Utc::now();
        let id = uuid::Uuid::new_v4().to_string();

        let tags = ConnectionTags {
            role,
            state,
            thread_id: thread_id.clone(),
            out_of_band_id: out_of_band_id.clone(),
            did: did.clone(),
            their_did: None,
        };

        Self {
            id,
            state,
            role,
            thread_id,
            out_of_band_id,
            did,
            their_did: None,
            their_authentication_key_base58: None,
            their_key_agreement_key_base58: None,
            our_label: None,
            their_label: None,
            previous_dids: Vec::new(),
            previous_their_dids: Vec::new(),
            auto_accept_connection: None,
            image_url: None,
            error_message: None,
            metadata: None,
            didcomm_version: None,
            protocol: Self::PROTOCOL.to_string(),
            created_at: now,
            updated_at: now,
            tags,
        }
    }

    /// Returns true if this connection uses DIDComm v2.
    pub fn is_v2(&self) -> bool {
        self.didcomm_version.as_deref() == Some("2")
    }

    /// Set metadata
    ///
    /// Metadata can be used to store application-specific data like:
    /// - PLC height: {"last_plc_height": 12345}
    /// - Peer capabilities: {"capabilities": ["plc", "mesh", "validator"]}
    /// - Sync timestamps: {"last_sync": "2024-01-01T00:00:00Z"}
    pub fn set_metadata(&mut self, metadata: serde_json::Value) {
        self.metadata = Some(metadata);
        self.updated_at = Utc::now();
    }

    /// Update metadata by merging with existing metadata
    ///
    /// If metadata is an object, this will merge the new values with existing ones.
    /// Otherwise, it will replace the metadata entirely.
    pub fn update_metadata(&mut self, new_metadata: serde_json::Value) {
        if let Some(existing) = &mut self.metadata {
            if let (Some(existing_obj), Some(new_obj)) =
                (existing.as_object_mut(), new_metadata.as_object())
            {
                // Merge objects
                for (key, value) in new_obj {
                    existing_obj.insert(key.clone(), value.clone());
                }
            } else {
                // Replace non-object metadata
                *existing = new_metadata;
            }
        } else {
            self.metadata = Some(new_metadata);
        }
        self.updated_at = Utc::now();
    }

    /// Get metadata value
    pub fn get_metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }

    /// Clear metadata
    pub fn clear_metadata(&mut self) {
        self.metadata = None;
        self.updated_at = Utc::now();
    }

    /// Update the connection state
    pub fn update_state(&mut self, new_state: DidExchangeState) {
        self.state = new_state;
        self.tags.state = new_state;
        self.updated_at = Utc::now();
    }

    /// Set their DID (when receiving response)
    pub fn set_their_did(&mut self, their_did: String) {
        self.their_did = Some(their_did.clone());
        self.tags.their_did = Some(their_did);
        self.updated_at = Utc::now();
    }

    /// Set their Ed25519 authentication public key (base58) from did_doc~attach
    pub fn set_their_authentication_key(&mut self, key_base58: String) {
        self.their_authentication_key_base58 = Some(key_base58);
        self.updated_at = Utc::now();
    }

    /// Set their X25519 keyAgreement public key (base58) from did_doc~attach
    pub fn set_their_key_agreement_key(&mut self, key_base58: String) {
        self.their_key_agreement_key_base58 = Some(key_base58);
        self.updated_at = Utc::now();
    }

    /// Set their label
    pub fn set_their_label(&mut self, label: String) {
        self.their_label = Some(label);
        self.updated_at = Utc::now();
    }

    /// Set our label
    pub fn set_our_label(&mut self, label: String) {
        self.our_label = Some(label);
        self.updated_at = Utc::now();
    }

    /// Rotate our DID
    pub fn rotate_did(&mut self, new_did: String) {
        self.previous_dids.push(self.did.clone());
        self.did = new_did.clone();
        self.tags.did = new_did;
        self.updated_at = Utc::now();
    }

    /// Rotate their DID
    pub fn rotate_their_did(&mut self, new_did: String) {
        if let Some(current_their_did) = &self.their_did {
            self.previous_their_dids.push(current_their_did.clone());
        }
        self.set_their_did(new_did);
    }

    /// Set error message
    pub fn set_error(&mut self, error: String) {
        self.error_message = Some(error);
        self.state = DidExchangeState::Abandoned;
        self.tags.state = DidExchangeState::Abandoned;
        self.updated_at = Utc::now();
    }

    /// Check if connection is completed
    pub fn is_completed(&self) -> bool {
        self.state == DidExchangeState::Completed
    }

    /// Check if connection is active (not terminal)
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// Builder for ConnectionRecord
pub struct ConnectionRecordBuilder {
    role: DidExchangeRole,
    state: DidExchangeState,
    thread_id: String,
    out_of_band_id: String,
    did: String,
    their_did: Option<String>,
    our_label: Option<String>,
    their_label: Option<String>,
    auto_accept_connection: Option<bool>,
    image_url: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl ConnectionRecordBuilder {
    pub fn new(
        role: DidExchangeRole,
        state: DidExchangeState,
        thread_id: String,
        out_of_band_id: String,
        did: String,
    ) -> Self {
        Self {
            role,
            state,
            thread_id,
            out_of_band_id,
            did,
            their_did: None,
            our_label: None,
            their_label: None,
            auto_accept_connection: None,
            image_url: None,
            metadata: None,
        }
    }

    pub fn their_did(mut self, their_did: String) -> Self {
        self.their_did = Some(their_did);
        self
    }

    pub fn our_label(mut self, label: String) -> Self {
        self.our_label = Some(label);
        self
    }

    pub fn their_label(mut self, label: String) -> Self {
        self.their_label = Some(label);
        self
    }

    pub fn auto_accept_connection(mut self, auto_accept: bool) -> Self {
        self.auto_accept_connection = Some(auto_accept);
        self
    }

    pub fn image_url(mut self, url: String) -> Self {
        self.image_url = Some(url);
        self
    }

    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn build(self) -> ConnectionRecord {
        let mut record = ConnectionRecord::new(
            self.role,
            self.state,
            self.thread_id,
            self.out_of_band_id,
            self.did,
        );

        if let Some(their_did) = self.their_did {
            record.set_their_did(their_did);
        }
        if let Some(our_label) = self.our_label {
            record.set_our_label(our_label);
        }
        if let Some(their_label) = self.their_label {
            record.set_their_label(their_label);
        }
        record.auto_accept_connection = self.auto_accept_connection;
        record.image_url = self.image_url;
        record.metadata = self.metadata;

        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_record_creation() {
        let record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-123".to_string(),
            "oob-456".to_string(),
            "did:peer:abc".to_string(),
        );

        assert_eq!(record.role, DidExchangeRole::Requester);
        assert_eq!(record.state, DidExchangeState::RequestSent);
        assert_eq!(record.thread_id, "thread-123");
        assert_eq!(record.out_of_band_id, "oob-456");
        assert_eq!(record.did, "did:peer:abc");
        assert!(record.their_did.is_none());
        assert_eq!(record.protocol, ConnectionRecord::PROTOCOL);
    }

    #[test]
    fn test_update_state() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        let initial_updated_at = record.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));

        record.update_state(DidExchangeState::ResponseReceived);

        assert_eq!(record.state, DidExchangeState::ResponseReceived);
        assert_eq!(record.tags.state, DidExchangeState::ResponseReceived);
        assert!(record.updated_at > initial_updated_at);
    }

    #[test]
    fn test_set_their_did() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        record.set_their_did("did:peer:2".to_string());

        assert_eq!(record.their_did, Some("did:peer:2".to_string()));
        assert_eq!(record.tags.their_did, Some("did:peer:2".to_string()));
    }

    #[test]
    fn test_did_rotation() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:old".to_string(),
        );

        record.rotate_did("did:peer:new".to_string());

        assert_eq!(record.did, "did:peer:new");
        assert_eq!(record.previous_dids, vec!["did:peer:old".to_string()]);
        assert_eq!(record.tags.did, "did:peer:new");
    }

    #[test]
    fn test_their_did_rotation() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Responder,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        record.set_their_did("did:peer:old".to_string());
        record.rotate_their_did("did:peer:new".to_string());

        assert_eq!(record.their_did, Some("did:peer:new".to_string()));
        assert_eq!(record.previous_their_dids, vec!["did:peer:old".to_string()]);
    }

    #[test]
    fn test_set_error() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        record.set_error("Connection timeout".to_string());

        assert_eq!(record.error_message, Some("Connection timeout".to_string()));
        assert_eq!(record.state, DidExchangeState::Abandoned);
        assert_eq!(record.tags.state, DidExchangeState::Abandoned);
    }

    #[test]
    fn test_is_completed() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        assert!(!record.is_completed());

        record.update_state(DidExchangeState::Completed);
        assert!(record.is_completed());
    }

    #[test]
    fn test_is_active() {
        let record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        assert!(record.is_active());

        let mut completed_record = record.clone();
        completed_record.update_state(DidExchangeState::Completed);
        assert!(!completed_record.is_active());

        let mut abandoned_record = record.clone();
        abandoned_record.set_error("Failed".to_string());
        assert!(!abandoned_record.is_active());
    }

    #[test]
    fn test_builder_minimal() {
        let record = ConnectionRecordBuilder::new(
            DidExchangeRole::Requester,
            DidExchangeState::InvitationReceived,
            "thread-abc".to_string(),
            "oob-xyz".to_string(),
            "did:peer:requester".to_string(),
        )
        .build();

        assert_eq!(record.role, DidExchangeRole::Requester);
        assert_eq!(record.thread_id, "thread-abc");
        assert!(record.their_did.is_none());
    }

    #[test]
    fn test_builder_full() {
        let record = ConnectionRecordBuilder::new(
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
            "thread-123".to_string(),
            "oob-456".to_string(),
            "did:peer:responder".to_string(),
        )
        .their_did("did:peer:requester".to_string())
        .our_label("My Agent".to_string())
        .their_label("Their Agent".to_string())
        .auto_accept_connection(true)
        .image_url("https://example.com/avatar.png".to_string())
        .build();

        assert_eq!(record.their_did, Some("did:peer:requester".to_string()));
        assert_eq!(record.our_label, Some("My Agent".to_string()));
        assert_eq!(record.their_label, Some("Their Agent".to_string()));
        assert_eq!(record.auto_accept_connection, Some(true));
        assert_eq!(
            record.image_url,
            Some("https://example.com/avatar.png".to_string())
        );
    }

    #[test]
    fn test_serialization() {
        let record = ConnectionRecordBuilder::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        )
        .their_did("did:peer:2".to_string())
        .our_label("Alice".to_string())
        .build();

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("threadId"));
        assert!(json.contains("outOfBandId"));
        assert!(json.contains("theirDid"));
        assert!(json.contains("ourLabel"));

        let deserialized: ConnectionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.thread_id, record.thread_id);
        assert_eq!(deserialized.their_did, record.their_did);
    }

    #[test]
    fn test_tags_sync() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        // Tags should match initial state
        assert_eq!(record.tags.role, record.role);
        assert_eq!(record.tags.state, record.state);
        assert_eq!(record.tags.thread_id, record.thread_id);
        assert_eq!(record.tags.did, record.did);

        // Tags should update with state
        record.update_state(DidExchangeState::ResponseReceived);
        assert_eq!(record.tags.state, DidExchangeState::ResponseReceived);

        // Tags should update with their_did
        record.set_their_did("did:peer:2".to_string());
        assert_eq!(record.tags.their_did, Some("did:peer:2".to_string()));

        // Tags should update with DID rotation
        record.rotate_did("did:peer:new".to_string());
        assert_eq!(record.tags.did, "did:peer:new");
    }

    #[test]
    fn test_metadata_set_and_get() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        // Initially no metadata
        assert!(record.get_metadata().is_none());

        // Set metadata for PLC tracking
        let plc_metadata = serde_json::json!({
            "last_plc_height": 12345,
            "last_sync": "2024-01-01T00:00:00Z",
            "peer_capabilities": ["plc", "mesh", "validator"]
        });
        record.set_metadata(plc_metadata.clone());

        // Verify metadata is set
        let metadata = record.get_metadata().unwrap();
        assert_eq!(metadata["last_plc_height"], 12345);
        assert_eq!(metadata["peer_capabilities"][0], "plc");
    }

    #[test]
    fn test_metadata_update_merge() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        // Set initial metadata
        record.set_metadata(serde_json::json!({
            "last_plc_height": 12345,
            "capabilities": ["plc"]
        }));

        // Update with new fields (should merge)
        record.update_metadata(serde_json::json!({
            "last_plc_height": 12350,
            "last_sync": "2024-01-02T00:00:00Z"
        }));

        let metadata = record.get_metadata().unwrap();
        assert_eq!(metadata["last_plc_height"], 12350); // Updated
        assert_eq!(metadata["capabilities"][0], "plc"); // Preserved
        assert_eq!(metadata["last_sync"], "2024-01-02T00:00:00Z"); // Added
    }

    #[test]
    fn test_metadata_clear() {
        let mut record = ConnectionRecord::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        );

        // Set metadata
        record.set_metadata(serde_json::json!({"key": "value"}));
        assert!(record.get_metadata().is_some());

        // Clear metadata
        record.clear_metadata();
        assert!(record.get_metadata().is_none());
    }

    #[test]
    fn test_metadata_serialization() {
        let record = ConnectionRecordBuilder::new(
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
            "thread-1".to_string(),
            "oob-1".to_string(),
            "did:peer:1".to_string(),
        )
        .metadata(serde_json::json!({
            "last_plc_height": 12345,
            "peer_capabilities": ["plc", "mesh"]
        }))
        .build();

        // Serialize to JSON
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("metadata"));
        assert!(json.contains("last_plc_height"));

        // Deserialize back
        let deserialized: ConnectionRecord = serde_json::from_str(&json).unwrap();
        let metadata = deserialized.get_metadata().unwrap();
        assert_eq!(metadata["last_plc_height"], 12345);
        assert_eq!(metadata["peer_capabilities"][1], "mesh");
    }

    #[test]
    fn test_metadata_backward_compatibility() {
        // Test that records without metadata can be deserialized
        let json_without_metadata = r#"{
            "id": "test-id",
            "state": "Completed",
            "role": "requester",
            "threadId": "thread-1",
            "outOfBandId": "oob-1",
            "did": "did:peer:1",
            "protocol": "connections/1.0",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        }"#;

        let record: ConnectionRecord = serde_json::from_str(json_without_metadata).unwrap();
        assert!(record.get_metadata().is_none());
        assert_eq!(record.id, "test-id");
    }

    #[test]
    fn test_builder_with_metadata() {
        let record = ConnectionRecordBuilder::new(
            DidExchangeRole::Responder,
            DidExchangeState::Completed,
            "thread-123".to_string(),
            "oob-456".to_string(),
            "did:peer:responder".to_string(),
        )
        .their_did("did:peer:requester".to_string())
        .our_label("My Agent".to_string())
        .metadata(serde_json::json!({
            "validator": true,
            "stake": 1000
        }))
        .build();

        assert_eq!(record.their_did, Some("did:peer:requester".to_string()));
        assert_eq!(record.our_label, Some("My Agent".to_string()));

        let metadata = record.get_metadata().unwrap();
        assert_eq!(metadata["validator"], true);
        assert_eq!(metadata["stake"], 1000);
    }
}
