//! Wire-fixture compatibility tests for Message Pickup V2 (RFC 0685).
//!
//! Fixture shape notes:
//! - `status.json` uses the minimal status shape — `threadId`, `recipientKey`,
//!   `messageCount` only. Minimal status responses do NOT populate
//!   `longestWaitedSeconds` or `totalBytes` (valid optional fields that are
//!   simply left unset).
//! - `status_with_extensions.json` is what our mediator emits — we additionally
//!   populate `longest_waited_seconds` + `total_bytes`. These are valid
//!   optional fields; recipients that ignore them are still compliant.
//! - `delivery.json` uses a `data.json` payload (`data: { json: encryptedMessage }`).
//!   `data.base64` is also valid per RFC 0044; both shapes are accepted.

use protocol_pickup::{
    DeliveryRequestMessage, LiveDeliveryChangeMessage, MessageDeliveryMessage,
    MessagesReceivedMessage, StatusMessage, StatusRequestMessage,
};

fn load_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/aries/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"))
}

#[test]
fn fixture_status_request_decodes() {
    let json = load_fixture("status_request.json");
    let decoded: StatusRequestMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.msg_type, StatusRequestMessage::TYPE);
    assert_eq!(decoded.id, "97cba1de-65ab-44c6-a3ad-7d3ba61e4cdf");
    assert!(decoded.recipient_key.is_none());
}

/// Canonical minimal Status (minimum fields).
#[test]
fn fixture_status_aries_minimum_decodes() {
    let json = load_fixture("status.json");
    let decoded: StatusMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.message_count, 5);
    // Minimal status responses do NOT populate these — assert absence.
    assert!(
        decoded.longest_waited_seconds.is_none(),
        "Aries TS's processStatusRequest does not populate longest_waited_seconds"
    );
    assert!(
        decoded.total_bytes.is_none(),
        "Aries TS's processStatusRequest does not populate total_bytes"
    );
    assert!(
        decoded.live_delivery.is_none(),
        "Status from processStatusRequest does not carry live_delivery"
    );
    assert_eq!(
        decoded.thread_id(),
        Some("97cba1de-65ab-44c6-a3ad-7d3ba61e4cdf")
    );
}

/// Our extended Status — our mediator emits optional fields that the
/// protocol allows but minimal implementations skip. Decoders must still accept them.
#[test]
fn fixture_status_with_extensions_decodes() {
    let json = load_fixture("status_with_extensions.json");
    let decoded: StatusMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.message_count, 5);
    assert_eq!(decoded.longest_waited_seconds, Some(3600));
    assert_eq!(decoded.total_bytes, Some(8192));
    assert_eq!(decoded.live_delivery, Some(false));
}

#[test]
fn fixture_delivery_request_decodes() {
    let json = load_fixture("delivery_request.json");
    let decoded: DeliveryRequestMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.limit, 10);
}

/// Delivery with `data.json` attachment payload — the canonical emission shape.
/// Our `process_delivery` recipient already handles both `data.json` and
/// `data.base64`, so this exercises the json branch.
#[test]
fn fixture_delivery_aries_data_json_decodes() {
    let json = load_fixture("delivery.json");
    let decoded: MessageDeliveryMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.attachments.len(), 2);
    assert_eq!(decoded.attachments[0].id.as_deref(), Some("m-1"));
    assert_eq!(decoded.attachments[1].id.as_deref(), Some("m-2"));
    // Verify the attachment data branch is `json` (the canonical emission shape).
    use didcomm::core::models::AttachmentData;
    match &decoded.attachments[0].data {
        AttachmentData::Json { json: payload } => {
            assert_eq!(payload["protected"], "encrypted-jwe-1");
        }
        other => panic!("expected AttachmentData::Json, got {other:?}"),
    }
}

#[test]
fn fixture_messages_received_decodes() {
    let json = load_fixture("messages_received.json");
    let decoded: MessagesReceivedMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.message_id_list, vec!["m-1", "m-2", "m-3"]);
    assert_eq!(decoded.thread_id(), Some("th-orig"));
}

#[test]
fn fixture_live_delivery_change_decodes() {
    let json = load_fixture("live_delivery_change.json");
    let decoded: LiveDeliveryChangeMessage = serde_json::from_str(&json).unwrap();
    assert!(decoded.live_delivery);
}

/// Structural round-trip on the minimum Status: encode our decoded
/// struct, re-parse, key fields match.
#[test]
fn fixture_status_round_trips_structurally() {
    let json = load_fixture("status.json");
    let decoded: StatusMessage = serde_json::from_str(&json).unwrap();
    let re = serde_json::to_string(&decoded).unwrap();
    let original: serde_json::Value = serde_json::from_str(&json).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&re).unwrap();
    assert_eq!(original["@type"], reparsed["@type"]);
    assert_eq!(original["message_count"], reparsed["message_count"]);
    assert_eq!(original["~thread"]["thid"], reparsed["~thread"]["thid"]);
    // Verify we don't accidentally emit fields that weren't in the input.
    assert!(reparsed.get("longest_waited_seconds").is_none());
    assert!(reparsed.get("total_bytes").is_none());
}

/// E2E parse → ACK round-trip: parse delivery fixture, extract ids,
/// build ACK. This is the data path a real recipient walks on the wire.
#[test]
fn fixture_delivery_parses_into_ack_payload() {
    let json = load_fixture("delivery.json");
    let delivery: MessageDeliveryMessage = serde_json::from_str(&json).unwrap();
    let ids: Vec<String> = delivery
        .attachments
        .iter()
        .filter_map(|a| a.id.clone())
        .collect();
    assert_eq!(ids, vec!["m-1", "m-2"]);

    let ack = MessagesReceivedMessage::new(ids.clone());
    assert_eq!(ack.message_id_list, ids);
}
