// AnonCreds-backed flow: only compiled when the `anoncreds` feature is on.
#![cfg(feature = "anoncreds")]

//! Integration tests for the propose-credential and problem-report
//! messages added to Issue Credential V2:
//!
//! * `propose-credential` — holder-initiated flow + issuer counter-offer
//! * `problem-report` — abandons the exchange on either side

use std::sync::Arc;

use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, InMemoryRegistry};
use protocol_credentials::{
    AckMessage, CredentialExchangeRepository, CredentialExchangeRole, CredentialExchangeService,
    CredentialExchangeState, OfferCredentialMessage, ProblemReportMessage,
    ProposeCredentialMessage,
};

fn make_service() -> Arc<CredentialExchangeService> {
    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = Arc::new(AnonCredsIssuerService::new(registry.clone()));
    let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));
    let repo = Arc::new(CredentialExchangeRepository::new());
    Arc::new(CredentialExchangeService::new(issuer, holder, repo))
}

#[tokio::test]
async fn propose_credential_creates_proposal_sent_state() {
    let svc = make_service();
    let (record, msg) = svc
        .create_proposal(Some("conn-1"), Some("schema:1"), Some("cred-def:1"), None)
        .await
        .expect("create proposal");
    assert_eq!(record.state, CredentialExchangeState::ProposalSent);
    assert_eq!(record.role, CredentialExchangeRole::Holder);
    assert_eq!(record.schema_id.as_deref(), Some("schema:1"));
    assert_eq!(record.cred_def_id.as_deref(), Some("cred-def:1"));
    assert_eq!(msg.thread_id, record.thread_id);
}

#[tokio::test]
async fn store_proposal_creates_proposal_received_state() {
    let svc = make_service();
    let msg = ProposeCredentialMessage::new(
        r#"{"schema_id":"schema:2","cred_def_id":"cred-def:2"}"#.to_string(),
    );
    let record = svc
        .store_proposal(Some("conn-2"), &msg)
        .await
        .expect("store proposal");
    assert_eq!(record.state, CredentialExchangeState::ProposalReceived);
    assert_eq!(record.role, CredentialExchangeRole::Issuer);
    assert_eq!(record.schema_id.as_deref(), Some("schema:2"));
    assert_eq!(record.cred_def_id.as_deref(), Some("cred-def:2"));
}

#[tokio::test]
async fn store_proposal_is_idempotent() {
    let svc = make_service();
    let msg = ProposeCredentialMessage::new(r#"{"schema_id":"s","cred_def_id":"c"}"#.to_string());
    let first = svc.store_proposal(None, &msg).await.unwrap();
    let second = svc.store_proposal(None, &msg).await.unwrap();
    assert_eq!(first.id, second.id, "idempotent on the same thread_id");
}

#[tokio::test]
async fn problem_report_message_roundtrip() {
    // Quick sanity: build a problem report, convert to DIDComm, parse back.
    let original =
        ProblemReportMessage::issuance_abandoned("thread-1".into(), "issuer rejected the request");
    let didcomm = original.to_didcomm_message();
    let parsed = ProblemReportMessage::from_didcomm_message(&didcomm).unwrap();
    assert_eq!(parsed.thread_id, original.thread_id);
    assert_eq!(parsed.description.code, original.description.code);
}

#[tokio::test]
async fn ack_message_still_works_alongside_new_messages() {
    let ack = AckMessage::ok("thread-x".into());
    let didcomm = ack.to_didcomm_message();
    assert_eq!(didcomm.msg_type, AckMessage::TYPE);
    let restored = AckMessage::from_didcomm_message(&didcomm).unwrap();
    assert_eq!(restored.thread_id, "thread-x");
}

#[tokio::test]
async fn accept_proposal_transitions_to_offer_sent() {
    let _svc = make_service();

    // Issuer-side seeding: schema + cred_def so create_credential_offer works.
    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = AnonCredsIssuerService::new(registry.clone());
    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "TestCred",
            "1.0",
            vec!["name".to_string()],
        )
        .await
        .expect("schema");
    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", false)
        .await
        .expect("cred def");

    // Rewire the service to use the seeded registry + issuer.
    let svc = {
        let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));
        let issuer = Arc::new(issuer);
        let repo = Arc::new(CredentialExchangeRepository::new());
        Arc::new(CredentialExchangeService::new(issuer, holder, repo))
    };

    let msg = ProposeCredentialMessage::new(format!(
        r#"{{"schema_id":"{}","cred_def_id":"{}"}}"#,
        schema.schema_id, cred_def.cred_def_id
    ));
    let record = svc.store_proposal(Some("conn-3"), &msg).await.unwrap();
    let offer_msg: OfferCredentialMessage = svc
        .accept_proposal(&record.id, &schema.schema_id, &cred_def.cred_def_id)
        .await
        .expect("accept proposal");
    assert_eq!(offer_msg.thread_id, record.thread_id, "offer reuses thread");

    let after = svc.find_exchange_by_id(&record.id).await.unwrap().unwrap();
    assert_eq!(after.state, CredentialExchangeState::OfferSent);
}
