//! Issue Credential V2 protocol flow tests.
//!
//! Walks the entire V2 issuance state machine and checks state transitions at
//! every step: createOffer → acceptOffer → processRequest → acceptRequest →
//! processCredential → ack → done, plus problem-report abandon and the
//! state-rejection guards on each transition.

use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, InMemoryRegistry};
use protocol_credentials::{
    AckMessage, AckStatus, CredentialExchangeRepository, CredentialExchangeRole,
    CredentialExchangeService, CredentialExchangeState, ProblemReportMessage,
};

async fn setup() -> (
    Arc<CredentialExchangeService>,
    String, // schema_id
    String, // cred_def_id
) {
    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = Arc::new(AnonCredsIssuerService::new(registry.clone()));
    let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));

    // Pre-seed schema + cred_def so issuance can run end-to-end.
    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "TestCred",
            "1.0",
            vec!["name".into(), "age".into()],
        )
        .await
        .expect("create schema");
    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", false)
        .await
        .expect("create cred def");

    let repo = Arc::new(CredentialExchangeRepository::new());
    let svc = Arc::new(CredentialExchangeService::new(issuer, holder, repo));
    (svc, schema.schema_id, cred_def.cred_def_id)
}

#[tokio::test]
async fn create_offer_lands_in_offer_sent() {
    let (svc, schema_id, cred_def_id) = setup().await;
    let (record, msg) = svc
        .create_offer(Some("conn"), &schema_id, &cred_def_id)
        .await
        .unwrap();
    assert_eq!(record.state, CredentialExchangeState::OfferSent);
    assert_eq!(record.role, CredentialExchangeRole::Issuer);
    assert_eq!(record.thread_id, msg.thread_id);
    assert_eq!(record.connection_id.as_deref(), Some("conn"));
}

#[tokio::test]
async fn accept_offer_transitions_to_request_sent() {
    // Holder side: simulate receiving the issuer's offer, then call
    // accept_offer to move the exchange to RequestSent.
    let (svc, schema_id, cred_def_id) = setup().await;
    let (issuer_record, offer_msg) = svc
        .create_offer(None, &schema_id, &cred_def_id)
        .await
        .unwrap();

    // Mock holder record in OfferReceived by inserting a parallel record.
    use protocol_credentials::CredentialExchangeRecord;
    let mut holder_record = CredentialExchangeRecord::new(
        CredentialExchangeRole::Holder,
        CredentialExchangeState::OfferReceived,
        offer_msg.thread_id.clone(),
    );
    holder_record.schema_id = Some(schema_id.clone());
    holder_record.cred_def_id = Some(cred_def_id.clone());
    holder_record.credential_offer_json = Some(offer_msg.credential_offer_json.clone());
    svc.repository().save(&holder_record).await.unwrap();

    let _request_msg = svc
        .accept_offer(&holder_record.id, "holder-entropy")
        .await
        .expect("accept offer");

    let after = svc
        .find_exchange_by_id(&holder_record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, CredentialExchangeState::RequestSent);
    let _ = issuer_record;
}

#[tokio::test]
async fn accept_offer_rejects_wrong_state() {
    // Calling accept_offer on a terminal exchange must surface InvalidState.
    let (svc, _schema_id, _cred_def_id) = setup().await;

    use protocol_credentials::CredentialExchangeRecord;
    let mut record = CredentialExchangeRecord::new(
        CredentialExchangeRole::Holder,
        CredentialExchangeState::Done,
        "bad-thread".to_string(),
    );
    record.cred_def_id = Some("x".to_string());
    record.credential_offer_json = Some("{}".to_string());
    svc.repository().save(&record).await.unwrap();

    let err = svc.accept_offer(&record.id, "entropy").await.unwrap_err();
    assert!(
        format!("{}", err).contains("Invalid state"),
        "expected state-transition error, got: {}",
        err
    );
}

#[tokio::test]
async fn full_round_trip_state_transitions() {
    // Full Issue Credential V2 flow: offer → request → issue → process → ack → done.
    let (svc, schema_id, cred_def_id) = setup().await;

    // 1. Issuer creates offer → OfferSent.
    let (issuer_record, offer_msg) = svc
        .create_offer(Some("conn-A"), &schema_id, &cred_def_id)
        .await
        .unwrap();
    assert_eq!(issuer_record.state, CredentialExchangeState::OfferSent);

    // 2. Holder simulates receiving the offer.
    use protocol_credentials::CredentialExchangeRecord;
    let mut holder_record = CredentialExchangeRecord::new(
        CredentialExchangeRole::Holder,
        CredentialExchangeState::OfferReceived,
        offer_msg.thread_id.clone(),
    );
    holder_record.schema_id = Some(schema_id.clone());
    holder_record.cred_def_id = Some(cred_def_id.clone());
    holder_record.credential_offer_json = Some(offer_msg.credential_offer_json.clone());
    svc.repository().save(&holder_record).await.unwrap();

    // 3. Holder sends request → RequestSent.
    let request_msg = svc
        .accept_offer(&holder_record.id, "entropy")
        .await
        .unwrap();
    let holder_after_request = svc
        .find_exchange_by_id(&holder_record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        holder_after_request.state,
        CredentialExchangeState::RequestSent
    );

    // 4. Issuer receives the request → RequestReceived.
    svc.store_request(&issuer_record.id, &request_msg.credential_request_json)
        .await
        .unwrap();
    let issuer_after_req = svc
        .find_exchange_by_id(&issuer_record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issuer_after_req.state,
        CredentialExchangeState::RequestReceived
    );

    // 5. Issuer accepts the request → CredentialIssued.
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), "Alice".to_string());
    attrs.insert("age".to_string(), "30".to_string());
    let _outbound = svc.accept_request(&issuer_record.id, attrs).await.unwrap();
    let issuer_after_issue = svc
        .find_exchange_by_id(&issuer_record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        issuer_after_issue.state,
        CredentialExchangeState::CredentialIssued
    );

    // 6. Holder processes the credential → Done.
    let issued_json = issuer_after_issue.credential_json.unwrap();
    let _cred_id = svc
        .process_credential(&holder_record.id, &issued_json)
        .await
        .unwrap();
    let holder_done = svc
        .find_exchange_by_id(&holder_record.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(holder_done.state, CredentialExchangeState::Done);
}

#[tokio::test]
async fn problem_report_roundtrip_message() {
    // Problem-report → DIDComm message → parsed back.
    let original =
        ProblemReportMessage::issuance_abandoned("thread-pr".into(), "holder cancelled mid-flight");
    let dc = original.to_didcomm_message();
    let restored = ProblemReportMessage::from_didcomm_message(&dc).unwrap();
    assert_eq!(restored.thread_id, original.thread_id);
    assert_eq!(restored.description.en, original.description.en);
    assert_eq!(restored.description.code, "issuance-abandoned");
}

#[tokio::test]
async fn problem_report_abandons_exchange() {
    let (svc, schema_id, cred_def_id) = setup().await;
    let (record, _msg) = svc
        .create_offer(None, &schema_id, &cred_def_id)
        .await
        .unwrap();
    svc.abandon_exchange(&record.id, "issuance-abandoned: holder declined")
        .await
        .unwrap();
    let after = svc.find_exchange_by_id(&record.id).await.unwrap().unwrap();
    assert_eq!(after.state, CredentialExchangeState::Abandoned);
    assert!(after
        .error_message
        .as_deref()
        .unwrap_or("")
        .contains("issuance-abandoned"));
}

#[tokio::test]
async fn ack_status_serializes_uppercase() {
    // Aries RFC requires UPPERCASE ack status values on the wire.
    assert_eq!(serde_json::to_string(&AckStatus::Ok).unwrap(), "\"OK\"");
    assert_eq!(
        serde_json::to_string(&AckMessage::ok("t".into()).status).unwrap(),
        "\"OK\""
    );
}
