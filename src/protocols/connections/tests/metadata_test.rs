//! Test connection metadata functionality
//!
//! Tests that metadata can be added to connections without breaking
//! wire compatibility (metadata is optional and doesn't affect serialization)

use protocol_connections::domain::{DidExchangeRole, DidExchangeState};
use protocol_connections::repository::{ConnectionRecord, ConnectionRecordBuilder};
use serde_json::json;

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
    let plc_metadata = json!({
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
    record.set_metadata(json!({
        "last_plc_height": 12345,
        "capabilities": ["plc"]
    }));

    // Update with new fields (should merge)
    record.update_metadata(json!({
        "last_plc_height": 12350,
        "last_sync": "2024-01-02T00:00:00Z"
    }));

    let metadata = record.get_metadata().unwrap();
    assert_eq!(metadata["last_plc_height"], 12350); // Updated
    assert_eq!(metadata["capabilities"][0], "plc"); // Preserved
    assert_eq!(metadata["last_sync"], "2024-01-02T00:00:00Z"); // Added
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
    .metadata(json!({
        "last_plc_height": 12345,
        "peer_capabilities": ["plc", "mesh"]
    }))
    .build();

    // Serialize to JSON
    let json_str = serde_json::to_string(&record).unwrap();
    assert!(json_str.contains("metadata"));
    assert!(json_str.contains("last_plc_height"));

    // Deserialize back
    let deserialized: ConnectionRecord = serde_json::from_str(&json_str).unwrap();
    let metadata = deserialized.get_metadata().unwrap();
    assert_eq!(metadata["last_plc_height"], 12345);
    assert_eq!(metadata["peer_capabilities"][1], "mesh");
}

#[test]
fn test_metadata_backward_compatibility() {
    // Test that records without metadata can be deserialized
    // This ensures wire compatibility is maintained
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
    assert_eq!(record.state, DidExchangeState::Completed);
}

#[test]
fn test_metadata_ajna_use_case() {
    // Test realistic Ajna blockchain use case
    let mut record = ConnectionRecord::new(
        DidExchangeRole::Responder,
        DidExchangeState::Completed,
        "thread-abc".to_string(),
        "oob-xyz".to_string(),
        "did:peer:validator1".to_string(),
    );
    record.set_their_did("did:peer:validator2".to_string());

    // Track PLC sync state
    record.set_metadata(json!({
        "last_plc_height": 12345,
        "last_plc_sync": "2024-01-01T10:00:00Z",
        "peer_capabilities": ["plc", "mesh", "validator"],
        "stake": 1000,
        "validator_pubkey": "ed25519:..."
    }));

    // Simulate PLC update
    record.update_metadata(json!({
        "last_plc_height": 12350,
        "last_plc_sync": "2024-01-01T10:05:00Z"
    }));

    let metadata = record.get_metadata().unwrap();
    assert_eq!(metadata["last_plc_height"], 12350);
    assert_eq!(metadata["stake"], 1000);
    assert_eq!(metadata["peer_capabilities"].as_array().unwrap().len(), 3);
}
