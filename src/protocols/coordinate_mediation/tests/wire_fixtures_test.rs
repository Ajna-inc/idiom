//! Wire-fixture compatibility tests for mediation (RFC 0211) +
//! routing (RFC 0094 Forward). Each fixture under
//! `tests/fixtures/aries/*.json` matches the canonical DIDComm wire shape.
//!
//! Fixture recapture: dump a JWE → decrypt → write the inner plaintext into
//! the matching file here. If a fixture starts failing, our parser has
//! drifted from the canonical wire shape.

use protocol_coordinate_mediation::{
    domain::{KeylistAction, KeylistResult},
    ForwardMessage, KeylistUpdateMessage, KeylistUpdateResponseMessage, MediationDenyMessage,
    MediationGrantMessage, MediationRequestMessage,
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
fn fixture_mediate_request_decodes() {
    let json = load_fixture("mediate_request.json");
    let decoded: MediationRequestMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.msg_type, MediationRequestMessage::TYPE);
    assert_eq!(decoded.id, "9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4");
}

#[test]
fn fixture_mediate_grant_decodes() {
    let json = load_fixture("mediate_grant.json");
    let decoded: MediationGrantMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.endpoint, "https://mediator.example.com/didcomm");
    assert_eq!(
        decoded.routing_keys,
        vec!["did:key:zRouter1", "did:key:zRouter2"]
    );
    assert_eq!(
        decoded.thread_id(),
        Some("9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4")
    );
}

#[test]
fn fixture_mediate_deny_decodes() {
    let json = load_fixture("mediate_deny.json");
    let decoded: MediationDenyMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.msg_type, MediationDenyMessage::TYPE);
    assert_eq!(decoded.thread_id(), Some("th-1"));
}

#[test]
fn fixture_keylist_update_decodes() {
    let json = load_fixture("keylist_update.json");
    let decoded: KeylistUpdateMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.updates.len(), 2);
    assert_eq!(decoded.updates[0].action, KeylistAction::Add);
    assert_eq!(decoded.updates[0].recipient_key, "did:key:zABC");
    assert_eq!(decoded.updates[1].action, KeylistAction::Remove);
    assert_eq!(decoded.updates[1].recipient_key, "did:key:zDEF");
}

#[test]
fn fixture_keylist_update_response_decodes() {
    let json = load_fixture("keylist_update_response.json");
    let decoded: KeylistUpdateResponseMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.updated.len(), 1);
    assert_eq!(decoded.updated[0].action, KeylistAction::Add);
    assert_eq!(decoded.updated[0].result, KeylistResult::Success);
}

#[test]
fn fixture_forward_decodes() {
    let json = load_fixture("forward.json");
    let decoded: ForwardMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.to, "did:key:zRecipient");
    assert!(decoded.message.is_object());
    assert_eq!(decoded.message["protected"], "...");
    assert_eq!(decoded.message["ciphertext"], "...");
}

/// Structural round-trip: encode our decoded struct, re-parse, fields
/// match. Catches accidental key renames or skip_serializing changes.
#[test]
fn fixture_grant_round_trips_structurally() {
    let json = load_fixture("mediate_grant.json");
    let decoded: MediationGrantMessage = serde_json::from_str(&json).unwrap();
    let re = serde_json::to_string(&decoded).unwrap();
    let original: serde_json::Value = serde_json::from_str(&json).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&re).unwrap();
    assert_eq!(original["@type"], reparsed["@type"]);
    assert_eq!(original["endpoint"], reparsed["endpoint"]);
    assert_eq!(original["routing_keys"], reparsed["routing_keys"]);
    assert_eq!(original["~thread"]["thid"], reparsed["~thread"]["thid"]);
}
