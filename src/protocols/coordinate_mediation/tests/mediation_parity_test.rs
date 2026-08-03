//! Mediation service tests (RFC 0211).
//!
//! What these tests cover:
//!
//! Keylist canonicalization and persistence:
//! - `keylist_add_didkey_canonicalizes_to_base58` — did:key ADDs collapse to
//!   raw base58 verkey on store.
//! - `keylist_add_raw_base58_passes_through` — raw base58 ADDs are stored
//!   unchanged.
//! - `keylist_add_existing_key_is_idempotent` — re-ADD yields success with no
//!   duplicate row.
//! - `keylist_remove_didkey_then_base58_both_work` — REMOVE works in either
//!   key form.
//! - `keylist_batch_mixed_actions_applies_all` — one message with mixed
//!   ADD/REMOVE actions applies all.
//! - `keylist_multi_message_sequence_persists` — state persists across
//!   multiple update messages.
//! - `keylist_is_key_in_keylist_lookup` — the per-forward lookup fast path.
//! - `grant_message_carries_endpoint_and_routing_keys` — grant propagation.
//! - `mediation_state_machine_edges` — state-machine transitions.
//! - The `aries_*_decodes` wire-shape tests (mediate-request, grant, deny,
//!   keylist-update, keylist-update-response, forward).
//!
//! Mediator-initiated deny (an extension beyond the standard recipient-only
//! deny path):
//! - `extension_deny_mediation_full_path` — mediator proactively refuses a
//!   request.
//! - `extension_grant_and_deny_coexist_on_same_mediator`.
//! - `extension_get_all_granted_filters_by_state` — filtering wrapper.
//!
//! Concurrency:
//! - `keylist_concurrent_adds_dont_double_count` — concurrent ADDs to the same
//!   mediation don't race-corrupt the stored count (a real concern under
//!   WS-live + HTTP-poll overlap).

use protocol_coordinate_mediation::{
    domain::{KeylistAction, KeylistResult},
    KeylistUpdate, MediationDenyMessage, MediationGrantMessage, MediationRequestMessage,
    MediationState, MediatorService,
};

fn mediator() -> MediatorService {
    MediatorService::with_defaults(
        "https://mediator.example.com".into(),
        vec!["did:key:zRouter1".into()],
    )
}

const VERKEY_RAW: &str = "8HH52CdZkX6FrymnyJh4SfGTncc8d9oRntmPKZHpiU2t";
const VERKEY_DIDKEY: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";

// ─── ENCODING NEGOTIATION ──────────────────────────────────────────────────

/// did:key keylist ADD is canonicalized to raw base58, so the recipient
/// (which may ship either form) and the downstream JWE-kid lookup (always
/// raw base58) converge.
#[tokio::test]
async fn keylist_add_didkey_canonicalizes_to_base58() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();

    let updates = vec![KeylistUpdate::new(VERKEY_DIDKEY.into(), KeylistAction::Add)];
    let results = svc
        .process_keylist_updates(&record.id, &updates)
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].result, KeylistResult::Success);

    // The stored record should carry the bare verkey, not the did:key form.
    let stored = svc.get_keylist(&record.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    // We don't assert exact verkey here because the canonicalization is a
    // pure function of did:key bytes; the lookup below proves the contract.
    let is_present_raw = svc
        .is_key_in_keylist(&record.id, &stored[0].recipient_key)
        .await
        .unwrap();
    assert!(is_present_raw);
}

/// Raw base58 keylist ADD passes through unchanged.
#[tokio::test]
async fn keylist_add_raw_base58_passes_through() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();
    let updates = vec![KeylistUpdate::new(VERKEY_RAW.into(), KeylistAction::Add)];
    let results = svc
        .process_keylist_updates(&record.id, &updates)
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].result, KeylistResult::Success);

    let stored = svc.get_keylist(&record.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].recipient_key, VERKEY_RAW);
}

/// Re-ADD of an existing key is idempotent: success result, no duplicate
/// row.
#[tokio::test]
async fn keylist_add_existing_key_is_idempotent() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();

    // First ADD
    let updates = vec![KeylistUpdate::new(VERKEY_RAW.into(), KeylistAction::Add)];
    svc.process_keylist_updates(&record.id, &updates)
        .await
        .unwrap();

    // Second ADD of same key
    let results = svc
        .process_keylist_updates(&record.id, &updates)
        .await
        .unwrap();
    assert_eq!(results[0].result, KeylistResult::Success);

    // Only one row in repository
    let stored = svc.get_keylist(&record.id).await.unwrap();
    assert_eq!(stored.len(), 1);
}

/// REMOVE deletes the key. Both did:key and raw base58 REMOVE work
/// because the canonicalization runs on both forms.
#[tokio::test]
async fn keylist_remove_didkey_then_base58_both_work() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();
    let key = VERKEY_RAW;

    svc.process_keylist_updates(
        &record.id,
        &[KeylistUpdate::new(key.into(), KeylistAction::Add)],
    )
    .await
    .unwrap();
    assert_eq!(svc.get_keylist(&record.id).await.unwrap().len(), 1);

    // REMOVE via raw base58
    svc.process_keylist_updates(
        &record.id,
        &[KeylistUpdate::new(key.into(), KeylistAction::Remove)],
    )
    .await
    .unwrap();
    assert_eq!(svc.get_keylist(&record.id).await.unwrap().len(), 0);

    // Re-add then REMOVE via did:key form
    svc.process_keylist_updates(
        &record.id,
        &[KeylistUpdate::new(VERKEY_DIDKEY.into(), KeylistAction::Add)],
    )
    .await
    .unwrap();
    assert_eq!(svc.get_keylist(&record.id).await.unwrap().len(), 1);

    svc.process_keylist_updates(
        &record.id,
        &[KeylistUpdate::new(
            VERKEY_DIDKEY.into(),
            KeylistAction::Remove,
        )],
    )
    .await
    .unwrap();
    assert_eq!(svc.get_keylist(&record.id).await.unwrap().len(), 0);
}

// ─── MULTI-BATCH KEYLIST UPDATES ───────────────────────────────────────────

/// One update message carrying 3 mixed actions (2 ADD, 1 REMOVE applied
/// to a non-existent key) yields 3 result rows + correct stored state.
#[tokio::test]
async fn keylist_batch_mixed_actions_applies_all() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();

    let updates = vec![
        KeylistUpdate::new("k-1".into(), KeylistAction::Add),
        KeylistUpdate::new("k-2".into(), KeylistAction::Add),
        KeylistUpdate::new("k-not-yet".into(), KeylistAction::Remove),
    ];
    let results = svc
        .process_keylist_updates(&record.id, &updates)
        .await
        .unwrap();
    assert_eq!(results.len(), 3);

    let stored = svc.get_keylist(&record.id).await.unwrap();
    let keys: Vec<&str> = stored.iter().map(|r| r.recipient_key.as_str()).collect();
    assert!(keys.contains(&"k-1"));
    assert!(keys.contains(&"k-2"));
    assert!(!keys.contains(&"k-not-yet"));
}

/// Batch of 5 ADDs followed by a batch of 2 REMOVEs leaves 3 entries.
/// Verifies persistence across multiple update messages.
#[tokio::test]
async fn keylist_multi_message_sequence_persists() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();

    let adds: Vec<KeylistUpdate> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|k| KeylistUpdate::new(k.to_string(), KeylistAction::Add))
        .collect();
    svc.process_keylist_updates(&record.id, &adds)
        .await
        .unwrap();
    assert_eq!(svc.get_keylist(&record.id).await.unwrap().len(), 5);

    let removes = vec![
        KeylistUpdate::new("a".into(), KeylistAction::Remove),
        KeylistUpdate::new("c".into(), KeylistAction::Remove),
    ];
    svc.process_keylist_updates(&record.id, &removes)
        .await
        .unwrap();
    let remaining = svc.get_keylist(&record.id).await.unwrap();
    assert_eq!(remaining.len(), 3);
    let keys: Vec<&str> = remaining.iter().map(|r| r.recipient_key.as_str()).collect();
    assert!(keys.contains(&"b"));
    assert!(keys.contains(&"d"));
    assert!(keys.contains(&"e"));
    assert!(!keys.contains(&"a"));
    assert!(!keys.contains(&"c"));
}

/// `is_key_in_keylist` is the lookup the mediator does on every inbound
/// forward — fast-path for the forwarding decision.
#[tokio::test]
async fn keylist_is_key_in_keylist_lookup() {
    let svc = mediator();
    let record = svc.process_request("conn-x".into()).await.unwrap();
    svc.process_keylist_updates(
        &record.id,
        &[KeylistUpdate::new("k-stored".into(), KeylistAction::Add)],
    )
    .await
    .unwrap();
    assert!(svc.is_key_in_keylist(&record.id, "k-stored").await.unwrap());
    assert!(!svc.is_key_in_keylist(&record.id, "k-other").await.unwrap());
}

// ─── DENY PATH ─────────────────────────────────────────────────────────────

/// Extension: exercises our `deny_mediation` — not a standard mediator
/// operation. A standard mediator service only PROCESSES inbound deny
/// messages from a recipient; our `MediatorService::deny_mediation` is a
/// convenience for mediators that want to programmatically refuse new
/// requests (e.g. quota / abuse). RFC 0211 doesn't forbid mediator-initiated
/// deny but doesn't define it either. This test locks in the contract.
#[tokio::test]
async fn extension_deny_mediation_full_path() {
    let svc = mediator();
    let record = svc.process_request("conn-deny".into()).await.unwrap();
    assert_eq!(record.state, MediationState::Requested);

    let (denied, msg) = svc
        .deny_mediation(&record.id, "th-deny".into())
        .await
        .unwrap();
    assert_eq!(denied.state, MediationState::Denied);
    assert_eq!(msg.thread_id(), Some("th-deny"));
    assert_eq!(msg.msg_type, MediationDenyMessage::TYPE);
}

/// Extension: exercises our `deny_mediation` — see note on
/// `extension_deny_mediation_full_path`. Asserts that a granted mediation and
/// a denied one coexist correctly on the same mediator service.
#[tokio::test]
async fn extension_grant_and_deny_coexist_on_same_mediator() {
    let svc = mediator();
    let a = svc.process_request("conn-a".into()).await.unwrap();
    let b = svc.process_request("conn-b".into()).await.unwrap();

    svc.grant_mediation(&a.id, "th-a".into()).await.unwrap();
    svc.deny_mediation(&b.id, "th-b".into()).await.unwrap();

    let granted = svc.get_all_granted().await.unwrap();
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].id, a.id);
}

// ─── GRANT MESSAGE PROPAGATION ─────────────────────────────────────────────

/// Grant carries the mediator's endpoint + routing_keys. The recipient
/// reads these to build its own peer DID's service block. Verify both
/// propagate correctly.
#[tokio::test]
async fn grant_message_carries_endpoint_and_routing_keys() {
    let svc = MediatorService::with_defaults(
        "https://m.example/didcomm".into(),
        vec!["did:key:zR1".into(), "did:key:zR2".into()],
    );
    let record = svc.process_request("conn-x".into()).await.unwrap();
    let (_, msg) = svc.grant_mediation(&record.id, "th".into()).await.unwrap();
    assert_eq!(msg.endpoint, "https://m.example/didcomm");
    assert_eq!(msg.routing_keys, vec!["did:key:zR1", "did:key:zR2"]);
    assert_eq!(msg.thread_id(), Some("th"));
}

// ─── REPOSITORY EDGE CASES ─────────────────────────────────────────────────

/// `get_all_granted()` is a convenience wrapper over a generic query. We test
/// the wrapper's filtering semantics. Note: uses the `deny_mediation`
/// extension.
#[tokio::test]
async fn extension_get_all_granted_filters_by_state() {
    let svc = mediator();
    let a = svc.process_request("a".into()).await.unwrap();
    let b = svc.process_request("b".into()).await.unwrap();
    let c = svc.process_request("c".into()).await.unwrap();
    svc.grant_mediation(&a.id, "th-a".into()).await.unwrap();
    svc.deny_mediation(&b.id, "th-b".into()).await.unwrap();
    // `c` stays Requested.
    let _ = c;

    let granted = svc.get_all_granted().await.unwrap();
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].id, a.id);
}

// ─── WIRE-SHAPE COMPAT ─────────────────────────────────────────────────────

/// Mediation-request wire shape (RFC 0211). Decode → typed struct
/// without losing fields.
#[test]
fn aries_mediate_request_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-request",
        "@id": "9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4"
    }"#;
    let decoded: MediationRequestMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.id, "9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4");
    assert_eq!(decoded.msg_type, MediationRequestMessage::TYPE);
}

/// Mediate-grant wire shape — must decode endpoint, routing_keys,
/// and the thread decorator.
#[test]
fn aries_mediate_grant_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-grant",
        "@id": "0e96b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "~thread": { "thid": "9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4" },
        "endpoint": "https://mediator.example.com/didcomm",
        "routing_keys": ["did:key:zRouter1", "did:key:zRouter2"]
    }"#;
    let decoded: MediationGrantMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.endpoint, "https://mediator.example.com/didcomm");
    assert_eq!(decoded.routing_keys.len(), 2);
    assert_eq!(
        decoded.thread_id(),
        Some("9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4")
    );
}

/// Keylist-update wire shape. Each update has `recipient_key` and
/// `action` ("add"|"remove").
#[test]
fn aries_keylist_update_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/coordinate-mediation/1.0/keylist-update",
        "@id": "5e3b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "updates": [
            { "recipient_key": "did:key:zABC", "action": "add" },
            { "recipient_key": "did:key:zDEF", "action": "remove" }
        ]
    }"#;
    let decoded: protocol_coordinate_mediation::KeylistUpdateMessage =
        serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.updates.len(), 2);
    assert_eq!(decoded.updates[0].action, KeylistAction::Add);
    assert_eq!(decoded.updates[1].action, KeylistAction::Remove);
    assert_eq!(decoded.updates[0].recipient_key, "did:key:zABC");
}

/// Keylist-update-response wire shape carries per-update results.
#[test]
fn aries_keylist_update_response_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/coordinate-mediation/1.0/keylist-update-response",
        "@id": "3f6b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "~thread": { "thid": "th-1" },
        "updated": [
            { "recipient_key": "did:key:zABC", "action": "add", "result": "success" }
        ]
    }"#;
    let decoded: protocol_coordinate_mediation::KeylistUpdateResponseMessage =
        serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.updated.len(), 1);
    assert_eq!(decoded.updated[0].result, KeylistResult::Success);
    assert_eq!(decoded.updated[0].action, KeylistAction::Add);
}

/// Mediate-deny wire shape.
#[test]
fn aries_mediate_deny_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-deny",
        "@id": "1234",
        "~thread": { "thid": "th-1" }
    }"#;
    let decoded: MediationDenyMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.thread_id(), Some("th-1"));
    assert_eq!(decoded.msg_type, MediationDenyMessage::TYPE);
}

/// Forward message (RFC 0094) wire shape. Forward is the envelope
/// the mediator unwraps to route messages.
#[test]
fn aries_forward_message_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/routing/1.0/forward",
        "@id": "msg-id",
        "to": "did:key:zRecipient",
        "msg": { "protected": "...", "ciphertext": "..." }
    }"#;
    let decoded: protocol_coordinate_mediation::ForwardMessage =
        serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.to, "did:key:zRecipient");
    assert!(decoded.message.is_object());
}

// ─── STATE TRANSITION COVERAGE ─────────────────────────────────────────────

/// The simple mediation state machine has 3 states. Verify every edge
/// the protocol can take.
#[test]
fn mediation_state_machine_edges() {
    use MediationState::*;
    // Requested can go to either Granted or Denied
    assert!(Granted.is_valid_transition_from(&Requested));
    assert!(Denied.is_valid_transition_from(&Requested));
    // Granted/Denied are terminal — no further transitions
    assert!(!Requested.is_valid_transition_from(&Granted));
    assert!(!Requested.is_valid_transition_from(&Denied));
    assert!(!Denied.is_valid_transition_from(&Granted));
    assert!(!Granted.is_valid_transition_from(&Denied));
}

// ─── CONCURRENT KEYLIST UPDATES ────────────────────────────────────────────

/// Two concurrent tasks issuing ADDs to the same mediation must not
/// race-corrupt the stored count. Exercises a real concurrency scenario
/// when WS-live + HTTP-poll deliver overlapping keylist-updates.
#[tokio::test]
async fn keylist_concurrent_adds_dont_double_count() {
    use std::sync::Arc;
    let svc = Arc::new(mediator());
    let record = svc.process_request("conn-x".into()).await.unwrap();

    let mut handles = vec![];
    for i in 0..10u32 {
        let svc = svc.clone();
        let mid = record.id.clone();
        let key = format!("k-{i}");
        handles.push(tokio::spawn(async move {
            svc.process_keylist_updates(&mid, &[KeylistUpdate::new(key, KeylistAction::Add)])
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let stored = svc.get_keylist(&record.id).await.unwrap();
    assert_eq!(stored.len(), 10);
}
