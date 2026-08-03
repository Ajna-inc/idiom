//! Connection lifecycle + state-machine tests.
//!
//! This file tests the service layer directly (no wallet stub) so we
//! exercise:
//!
//! - **Every legal state transition** through `ConnectionService` methods
//!   (`Start → InvitationReceived → RequestSent → ResponseReceived →
//!   Completed`; responder side: `Start → InvitationSent → RequestReceived
//!   → ResponseSent → Completed`)
//! - **Role enforcement** — Responder methods reject Requester records and
//!   vice-versa
//! - **State enforcement** — methods reject records in unexpected states
//!   (`create_response` must reject anything but `RequestReceived`)
//! - **Duplicate request idempotency** — a replayed `process_request` for
//!   the same thread_id returns the existing connection rather than
//!   creating a second
//! - **Thread-ID propagation** — `request.thread_id` becomes the
//!   connection's `thread_id` and the parent_thread_id is the OOB
//!   invitation id
//! - **Their-DID + key capture** — the responder stores the requester's
//!   DID and (optional) auth + key-agreement keys on `process_request`;
//!   the requester stores the responder's DID + keys on `process_response`
//! - **Wire-shape compat** — DID Exchange messages from other DIDComm
//!   agents decode into our typed structs and back without losing fields
//! - **Repository convenience queries** — `find_by_did`,
//!   `find_by_their_did`, `find_by_state`, and friends
//!
//! The full agent-level e2e is in `agent/tests/e2e_connections.rs` — those
//! tests cover signing + transport wire-up. This file isolates the state
//! machine.

use std::sync::Arc;

use protocol_connections::{
    domain::{DidExchangeRole, DidExchangeState},
    messages::{DidExchangeCompleteMessage, DidExchangeRequestMessage, DidExchangeResponseMessage},
    repository::{ConnectionRepository, ConnectionRepositoryTrait},
    services::ConnectionService,
    ConnectionError,
};
use protocol_oob::{
    domain::OutOfBandRole,
    messages::{InlineService, OutOfBandInvitation, OutOfBandService},
    repository::OutOfBandRecord,
};

fn sample_oob_record(label: &str) -> OutOfBandRecord {
    let service = OutOfBandService::Inline(InlineService::new(
        "#inline-0".into(),
        vec!["did:key:zRecipient".into()],
        vec![],
        "https://example.com/didcomm".into(),
    ));
    let mut invitation = OutOfBandInvitation::new(vec![service]);
    invitation.label = Some(label.into());
    OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
}

fn service() -> (ConnectionService, Arc<ConnectionRepository>) {
    let repo = Arc::new(ConnectionRepository::new());
    let svc = ConnectionService::new(repo.clone());
    (svc, repo)
}

// ─── REQUESTER SIDE ────────────────────────────────────────────────────────

/// `create_request`: Start → RequestSent (via InvitationReceived). The
/// record's role is Requester, its parent_thread is the OOB invitation's
/// id, and its thread_id is set from the generated request message.
#[tokio::test]
async fn create_request_emits_record_in_request_sent() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");

    let (record, request) = svc
        .create_request(&oob, "did:peer:requester".into(), Some("Bob".into()))
        .await
        .unwrap();

    assert_eq!(record.state, DidExchangeState::RequestSent);
    assert_eq!(record.role, DidExchangeRole::Requester);
    assert_eq!(record.thread_id, request.thread_id());
    assert_eq!(record.out_of_band_id, oob.invitation.id);
    assert_eq!(record.did, "did:peer:requester");
    assert_eq!(record.our_label.as_deref(), Some("Bob"));
    // The peer's label propagates from the invitation.
    assert_eq!(record.their_label.as_deref(), Some("Alice"));
    assert_eq!(request.parent_thread_id(), Some(oob.invitation.id.as_str()));
}

/// `process_response` advances RequestSent → ResponseReceived and captures
/// the responder's DID + keys.
#[tokio::test]
async fn process_response_advances_to_response_received_and_stores_keys() {
    let (svc, _repo) = service();
    let oob = sample_oob_record("Alice");

    // 1. requester creates request (RequestSent).
    let (req_record, request) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();

    // 2. peer responds.
    let response =
        DidExchangeResponseMessage::new("did:peer:responder".into(), request.thread_id().into());
    let updated = svc
        .process_response(
            &response,
            Some("their-auth-key".into()),
            Some("their-ka-key".into()),
        )
        .await
        .unwrap();

    assert_eq!(updated.id, req_record.id);
    assert_eq!(updated.state, DidExchangeState::ResponseReceived);
    assert_eq!(updated.their_did.as_deref(), Some("did:peer:responder"));
    assert_eq!(
        updated.their_authentication_key_base58.as_deref(),
        Some("their-auth-key")
    );
    assert_eq!(
        updated.their_key_agreement_key_base58.as_deref(),
        Some("their-ka-key")
    );
}

/// `process_response` against a record NOT in `RequestSent` is rejected.
#[tokio::test]
async fn process_response_rejects_wrong_state() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (mut record, _) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();

    // Manually advance to a state that's not RequestSent.
    record.update_state(DidExchangeState::ResponseReceived);
    repo.update(&record).await.unwrap();

    let response =
        DidExchangeResponseMessage::new("did:peer:responder".into(), record.thread_id.clone());
    let err = svc
        .process_response(&response, None, None)
        .await
        .unwrap_err();
    match err {
        ConnectionError::InvalidState { expected, actual } => {
            assert_eq!(expected, vec![DidExchangeState::RequestSent]);
            assert_eq!(actual, DidExchangeState::ResponseReceived);
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

/// `process_response` for an unknown thread_id is a NotFound error.
#[tokio::test]
async fn process_response_unknown_thread_is_not_found() {
    let (svc, _) = service();
    let response =
        DidExchangeResponseMessage::new("did:peer:responder".into(), "no-such-thread".into());
    let err = svc
        .process_response(&response, None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, ConnectionError::NotFound(_)));
}

/// `create_complete` advances ResponseReceived → Completed and emits a
/// complete message threaded to the request.
#[tokio::test]
async fn create_complete_advances_response_received_to_completed() {
    let (svc, _repo) = service();
    let oob = sample_oob_record("Alice");
    let (req_record, request) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();
    let response =
        DidExchangeResponseMessage::new("did:peer:responder".into(), request.thread_id().into());
    svc.process_response(&response, None, None).await.unwrap();

    let (completed_record, complete_msg) = svc.create_complete(&req_record.id).await.unwrap();
    assert_eq!(completed_record.state, DidExchangeState::Completed);
    assert_eq!(complete_msg.thread_id(), request.thread_id());
    assert_eq!(
        complete_msg.parent_thread_id(),
        Some(oob.invitation.id.as_str())
    );
}

/// `create_complete` rejects records not in `ResponseReceived`.
#[tokio::test]
async fn create_complete_rejects_wrong_state() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let (record, _) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();
    let err = svc.create_complete(&record.id).await.unwrap_err();
    assert!(matches!(err, ConnectionError::InvalidState { .. }));
}

// ─── RESPONDER SIDE ────────────────────────────────────────────────────────

/// `process_request`: Start → RequestReceived. Captures requester's DID +
/// keys, sets thread_id from request, and sets role=Responder.
#[tokio::test]
async fn process_request_creates_responder_record_in_request_received() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let request = DidExchangeRequestMessage::new(
        "Bob".into(),
        "did:peer:requester".into(),
        oob.invitation.id.clone(),
    );

    let record = svc
        .process_request(
            &request,
            &oob,
            "did:peer:responder".into(),
            Some("their-auth-key".into()),
            Some("their-ka-key".into()),
        )
        .await
        .unwrap();
    assert_eq!(record.state, DidExchangeState::RequestReceived);
    assert_eq!(record.role, DidExchangeRole::Responder);
    assert_eq!(record.thread_id, request.thread_id());
    assert_eq!(record.their_did.as_deref(), Some("did:peer:requester"));
    assert_eq!(record.their_label.as_deref(), Some("Bob"));
    assert_eq!(
        record.their_authentication_key_base58.as_deref(),
        Some("their-auth-key")
    );
    assert_eq!(
        record.their_key_agreement_key_base58.as_deref(),
        Some("their-ka-key")
    );
    assert_eq!(record.out_of_band_id, oob.invitation.id);
}

/// `process_request` is idempotent: replaying the same request (same
/// thread_id, Responder role) returns the existing record, not a new one.
/// Critical for WS-live-mode + HTTP-poll coexistence where the same
/// message may arrive twice.
#[tokio::test]
async fn process_request_is_idempotent_for_duplicate_thread() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let request = DidExchangeRequestMessage::new(
        "Bob".into(),
        "did:peer:requester".into(),
        oob.invitation.id.clone(),
    );

    let first = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap();
    let second = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap();
    assert_eq!(
        first.id, second.id,
        "duplicate request must return same record"
    );

    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 1, "no duplicate records persisted");
}

/// `process_request` rejects a request whose `parent_thread_id` does not
/// match the OOB invitation. Otherwise an attacker could forge a request
/// against an unrelated invitation.
#[tokio::test]
async fn process_request_rejects_pthid_mismatch() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let request = DidExchangeRequestMessage::new(
        "Bob".into(),
        "did:peer:requester".into(),
        "different-invitation".into(),
    );
    let err = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, ConnectionError::Protocol(_)));
}

/// `create_response`: RequestReceived → ResponseSent.
#[tokio::test]
async fn create_response_advances_request_received_to_response_sent() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let request = DidExchangeRequestMessage::new(
        "Bob".into(),
        "did:peer:requester".into(),
        oob.invitation.id.clone(),
    );
    let record = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap();
    let (updated, response) = svc.create_response(&record.id).await.unwrap();
    assert_eq!(updated.state, DidExchangeState::ResponseSent);
    assert_eq!(response.thread_id(), record.thread_id);
    assert_eq!(response.did, "did:peer:responder");
}

/// `create_response` rejects records not in `RequestReceived`.
#[tokio::test]
async fn create_response_rejects_wrong_state() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let (record, _) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();
    // Record is RequestSent (requester side), not RequestReceived → reject.
    let err = svc.create_response(&record.id).await.unwrap_err();
    match err {
        ConnectionError::InvalidState { expected, actual } => {
            assert_eq!(expected, vec![DidExchangeState::RequestReceived]);
            assert_eq!(actual, DidExchangeState::RequestSent);
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

/// `create_response` also enforces the role: a Requester record cannot be
/// asked to produce a response (Responder-only operation).
#[tokio::test]
async fn create_response_rejects_wrong_role() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (mut record, _) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();
    // Manually rebuild as RequestReceived (right state, wrong role).
    record.update_state(DidExchangeState::RequestReceived);
    repo.update(&record).await.unwrap();
    let err = svc.create_response(&record.id).await.unwrap_err();
    assert!(matches!(err, ConnectionError::InvalidRole { .. }));
}

/// `process_complete`: ResponseSent → Completed on the responder side.
#[tokio::test]
async fn process_complete_advances_response_sent_to_completed() {
    let (svc, _) = service();
    let oob = sample_oob_record("Alice");
    let request = DidExchangeRequestMessage::new(
        "Bob".into(),
        "did:peer:requester".into(),
        oob.invitation.id.clone(),
    );
    let record = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap();
    let (record_after_response, _response) = svc.create_response(&record.id).await.unwrap();

    // Build a complete message threaded to this connection.
    let complete = DidExchangeCompleteMessage::new(
        record_after_response.thread_id.clone(),
        oob.invitation.id.clone(),
    );
    let final_record = svc.process_complete(&complete).await.unwrap();
    assert_eq!(final_record.state, DidExchangeState::Completed);
}

// ─── FULL CYCLE (REQUESTER+RESPONDER COEXIST IN ONE SERVICE) ───────────────

/// Walk the entire DID Exchange protocol with both roles persisted in the
/// same repository — a full protocol flow. Every state transition fires;
/// final records pair up by thread_id.
#[tokio::test]
async fn full_protocol_flow_both_roles_complete() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");

    // Requester side: create_request.
    let (req_after_create, request) = svc
        .create_request(&oob, "did:peer:requester".into(), Some("Bob".into()))
        .await
        .unwrap();
    assert_eq!(req_after_create.state, DidExchangeState::RequestSent);

    // Responder side: process_request → create_response.
    let resp_after_process = svc
        .process_request(
            &request,
            &oob,
            "did:peer:responder".into(),
            Some("auth-key".into()),
            Some("ka-key".into()),
        )
        .await
        .unwrap();
    assert_eq!(resp_after_process.state, DidExchangeState::RequestReceived);
    let (resp_after_create, response) = svc.create_response(&resp_after_process.id).await.unwrap();
    assert_eq!(resp_after_create.state, DidExchangeState::ResponseSent);

    // Requester side: process_response.
    let req_after_response = svc
        .process_response(&response, Some("resp-auth".into()), Some("resp-ka".into()))
        .await
        .unwrap();
    assert_eq!(req_after_response.state, DidExchangeState::ResponseReceived);
    assert_eq!(
        req_after_response.their_did.as_deref(),
        Some("did:peer:responder")
    );

    // Requester side: create_complete.
    let (req_completed, complete_msg) = svc.create_complete(&req_after_response.id).await.unwrap();
    assert_eq!(req_completed.state, DidExchangeState::Completed);

    // Responder side: process_complete.
    let resp_completed = svc.process_complete(&complete_msg).await.unwrap();
    assert_eq!(resp_completed.state, DidExchangeState::Completed);

    // Both records persist with paired thread IDs.
    let all = repo.get_all().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|r| r.state == DidExchangeState::Completed));
    assert_eq!(all[0].thread_id, all[1].thread_id);
}

// ─── REPOSITORY EDGE CASES ─────────────────────────────────────────────────

/// `find_by_role_and_thread_id` returns the right record when both
/// Requester and Responder records share the same thread_id (the typical
/// single-process "loopback" test setup). Without this filter the two
/// records would collide.
#[tokio::test]
async fn repository_role_scoped_lookup_separates_requester_from_responder() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (_req_record, request) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();
    let _resp = svc
        .process_request(&request, &oob, "did:peer:responder".into(), None, None)
        .await
        .unwrap();

    let req = repo
        .find_by_role_and_thread_id(DidExchangeRole::Requester, request.thread_id())
        .await
        .unwrap()
        .expect("requester record");
    let resp = repo
        .find_by_role_and_thread_id(DidExchangeRole::Responder, request.thread_id())
        .await
        .unwrap()
        .expect("responder record");

    assert_eq!(req.role, DidExchangeRole::Requester);
    assert_eq!(resp.role, DidExchangeRole::Responder);
    assert_ne!(req.id, resp.id);
}

/// `find_by_state` filters across the full DB.
#[tokio::test]
async fn repository_find_by_state_filters_correctly() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");

    // Create two records: one in RequestSent, one fast-forwarded to Completed.
    let (r1, _) = svc
        .create_request(&oob, "did:peer:r1".into(), None)
        .await
        .unwrap();
    let (mut r2, _) = svc
        .create_request(&oob, "did:peer:r2".into(), None)
        .await
        .unwrap();
    r2.update_state(DidExchangeState::Completed);
    repo.update(&r2).await.unwrap();

    let request_sent = repo
        .find_by_state(DidExchangeState::RequestSent)
        .await
        .unwrap();
    assert_eq!(request_sent.len(), 1);
    assert_eq!(request_sent[0].id, r1.id);

    let completed = repo
        .find_by_state(DidExchangeState::Completed)
        .await
        .unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].id, r2.id);
}

/// Repository `find_by_did` finds connections by our own DID. Useful for
/// reverse lookups when the agent receives a message addressed to it.
#[tokio::test]
async fn repository_find_by_our_did() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (record, _) = svc
        .create_request(&oob, "did:peer:our-unique-1".into(), None)
        .await
        .unwrap();
    let found = repo.find_by_did("did:peer:our-unique-1").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, record.id);
}

/// Repository `find_by_their_did` finds connections by the peer's DID.
/// Used after `process_response` lands the peer DID — handlers route
/// subsequent messages to this connection by `their_did`.
#[tokio::test]
async fn repository_find_by_their_did_after_response() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (_, request) = svc
        .create_request(&oob, "did:peer:r".into(), None)
        .await
        .unwrap();
    let response =
        DidExchangeResponseMessage::new("did:peer:THEIR_UNIQUE".into(), request.thread_id().into());
    svc.process_response(&response, None, None).await.unwrap();

    let found = repo
        .find_by_their_did("did:peer:THEIR_UNIQUE")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
}

/// `find_by_out_of_band_id` returns every connection started from one
/// invitation — required for reusable / multi-use invitations.
#[tokio::test]
async fn repository_find_by_out_of_band_id_groups_multi_use() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Faber");
    let (_a, _) = svc
        .create_request(&oob, "did:peer:alice".into(), None)
        .await
        .unwrap();
    let (_b, _) = svc
        .create_request(&oob, "did:peer:bob".into(), None)
        .await
        .unwrap();
    let by_oob = repo
        .find_by_out_of_band_id(&oob.invitation.id)
        .await
        .unwrap();
    assert_eq!(by_oob.len(), 2);
}

// ─── WIRE-SHAPE / SERDE COMPAT ─────────────────────────────────────────────

/// DID Exchange agents emit the request message with `@type`, `@id`,
/// `label`, `did`, and `~thread` keys. Decode that wire shape directly
/// into our typed struct — failure here means we'd silently drop fields
/// against a real DIDComm agent.
#[test]
fn aries_didexchange_request_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/didexchange/1.1/request",
        "@id": "9b6c44a9-72e6-4f0a-9af0-69ec0e57b9a4",
        "label": "Faber",
        "did": "did:peer:2.Ez6LSn...etc",
        "~thread": {
            "thid": "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd",
            "pthid": "6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e"
        }
    }"#;
    let decoded: DidExchangeRequestMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.label, "Faber");
    assert_eq!(decoded.did, "did:peer:2.Ez6LSn...etc");
    assert_eq!(
        decoded.parent_thread_id(),
        Some("6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e")
    );
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
}

/// Wire shape for the response message. The presence of the
/// `did_doc~attach` field is optional per RFC 0023 (peer DID 4 can
/// self-contain the doc).
#[test]
fn aries_didexchange_response_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/didexchange/1.1/response",
        "@id": "0e96b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "did": "did:peer:2.Ez6LSnRESPONDER",
        "~thread": { "thid": "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd" }
    }"#;
    let decoded: DidExchangeResponseMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.did, "did:peer:2.Ez6LSnRESPONDER");
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
}

/// Wire shape for the complete message: `@type`, `@id`, `~thread.thid`,
/// `~thread.pthid` (invitation id). No payload fields.
#[test]
fn aries_didexchange_complete_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/didexchange/1.1/complete",
        "@id": "5e3b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "~thread": {
            "thid": "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd",
            "pthid": "6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e"
        }
    }"#;
    let decoded: DidExchangeCompleteMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
    assert_eq!(
        decoded.parent_thread_id(),
        Some("6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e")
    );
}

/// Our DidExchangeRequestMessage round-trips through serde, then decodes
/// back the same. Catches any future serde rename / structural drift.
#[test]
fn request_round_trip_preserves_thread_decorator() {
    let req =
        DidExchangeRequestMessage::new("Bob".into(), "did:peer:bob".into(), "invitation-1".into());
    let json = serde_json::to_string(&req).unwrap();
    let decoded: DidExchangeRequestMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.label, "Bob");
    assert_eq!(decoded.did, "did:peer:bob");
    assert_eq!(decoded.parent_thread_id(), Some("invitation-1"));
}

// ─── DOMAIN STATE-MACHINE EDGE COVERAGE ────────────────────────────────────

/// Every state's `valid_next_states()` list matches the RFC 0023 diagram.
/// This is the single source of truth — if it drifts, the service-level
/// transition checks become meaningless.
#[test]
fn state_machine_valid_transitions_lock_in_rfc0023() {
    use DidExchangeState::*;

    fn allows(from: DidExchangeState, to: DidExchangeState) -> bool {
        from.can_transition_to(to)
    }

    // Start can branch into either invitation direction.
    assert!(allows(Start, InvitationSent));
    assert!(allows(Start, InvitationReceived));
    assert!(!allows(Start, RequestSent));

    // From InvitationReceived (requester) → RequestSent (only).
    assert!(allows(InvitationReceived, RequestSent));
    assert!(allows(InvitationReceived, Abandoned));
    assert!(!allows(InvitationReceived, ResponseReceived));

    // From InvitationSent (responder) → RequestReceived (only).
    assert!(allows(InvitationSent, RequestReceived));
    assert!(allows(InvitationSent, Abandoned));
    assert!(!allows(InvitationSent, ResponseSent));

    // From RequestSent → ResponseReceived (only).
    assert!(allows(RequestSent, ResponseReceived));
    assert!(allows(RequestSent, Abandoned));

    // From RequestReceived → ResponseSent (only).
    assert!(allows(RequestReceived, ResponseSent));
    assert!(allows(RequestReceived, Abandoned));

    // From ResponseSent → Completed (responder).
    assert!(allows(ResponseSent, Completed));
    assert!(allows(ResponseSent, Abandoned));

    // From ResponseReceived → Completed (requester).
    assert!(allows(ResponseReceived, Completed));
    assert!(allows(ResponseReceived, Abandoned));

    // Terminal states allow no transitions.
    assert!(!allows(Completed, Abandoned));
    assert!(!allows(Abandoned, Completed));
    assert!(!allows(Completed, ResponseReceived));
}

/// Abandoned is terminal — once a connection moves there it's stuck and
/// cannot resume.
#[test]
fn abandoned_is_terminal_and_cannot_resume() {
    let st = DidExchangeState::Abandoned;
    assert!(st.is_terminal());
    assert!(!st.is_active());
    assert!(st.valid_next_states().is_empty());
}

/// Completed is terminal too — a connection never transitions away from it.
#[test]
fn completed_is_terminal() {
    let st = DidExchangeState::Completed;
    assert!(st.is_terminal());
    assert!(!st.is_active());
}

// ─── DELETE LIFECYCLE ─────────────────────────────────────────────────────

/// `delete` removes a connection from the repository.
#[tokio::test]
async fn delete_removes_record_from_repository() {
    let (svc, repo) = service();
    let oob = sample_oob_record("Alice");
    let (record, _) = svc
        .create_request(&oob, "did:peer:requester".into(), None)
        .await
        .unwrap();

    assert!(repo.find_by_id(&record.id).await.unwrap().is_some());
    svc.delete(&record.id).await.unwrap();
    assert!(repo.find_by_id(&record.id).await.unwrap().is_none());
}
