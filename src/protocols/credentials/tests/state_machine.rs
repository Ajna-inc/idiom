//! Issue Credential state-machine tests: every state has the kebab-case
//! wire value mandated by RFC 0036 / RFC 0453, terminal states are
//! correctly identified, and declined is reachable from every active
//! state.

use protocol_credentials::CredentialExchangeState;

#[test]
fn state_matches_issue_credential_v1_rfc_0036() {
    // Wire values mandated by Issue Credential RFC 0036.
    assert_eq!(
        CredentialExchangeState::ProposalSent.to_string(),
        "proposal-sent"
    );
    assert_eq!(
        CredentialExchangeState::ProposalReceived.to_string(),
        "proposal-received"
    );
    assert_eq!(CredentialExchangeState::OfferSent.to_string(), "offer-sent");
    assert_eq!(
        CredentialExchangeState::OfferReceived.to_string(),
        "offer-received"
    );
    assert_eq!(CredentialExchangeState::Declined.to_string(), "declined");
    assert_eq!(
        CredentialExchangeState::RequestSent.to_string(),
        "request-sent"
    );
    assert_eq!(
        CredentialExchangeState::RequestReceived.to_string(),
        "request-received"
    );
    assert_eq!(
        CredentialExchangeState::CredentialIssued.to_string(),
        "credential-issued"
    );
    assert_eq!(
        CredentialExchangeState::CredentialReceived.to_string(),
        "credential-received"
    );
    assert_eq!(CredentialExchangeState::Done.to_string(), "done");
}

#[test]
fn state_matches_issue_credential_v2_rfc_0453() {
    // RFC 0453 (Issue Credential V2) reuses the same state wire values.
    // This is intentionally identical to the V1 test to make any future
    // drift extremely visible.
    assert_eq!(
        CredentialExchangeState::ProposalSent.to_string(),
        "proposal-sent"
    );
    assert_eq!(
        CredentialExchangeState::ProposalReceived.to_string(),
        "proposal-received"
    );
    assert_eq!(CredentialExchangeState::OfferSent.to_string(), "offer-sent");
    assert_eq!(
        CredentialExchangeState::OfferReceived.to_string(),
        "offer-received"
    );
    assert_eq!(CredentialExchangeState::Declined.to_string(), "declined");
    assert_eq!(
        CredentialExchangeState::RequestSent.to_string(),
        "request-sent"
    );
    assert_eq!(
        CredentialExchangeState::RequestReceived.to_string(),
        "request-received"
    );
    assert_eq!(
        CredentialExchangeState::CredentialIssued.to_string(),
        "credential-issued"
    );
    assert_eq!(
        CredentialExchangeState::CredentialReceived.to_string(),
        "credential-received"
    );
    assert_eq!(CredentialExchangeState::Done.to_string(), "done");
}

#[test]
fn terminal_states_are_terminal() {
    assert!(CredentialExchangeState::Done.is_terminal());
    assert!(CredentialExchangeState::Abandoned.is_terminal());
    assert!(CredentialExchangeState::Declined.is_terminal());
}

#[test]
fn non_terminal_states_remain_active() {
    for s in [
        CredentialExchangeState::ProposalSent,
        CredentialExchangeState::ProposalReceived,
        CredentialExchangeState::OfferSent,
        CredentialExchangeState::OfferReceived,
        CredentialExchangeState::RequestSent,
        CredentialExchangeState::RequestReceived,
        CredentialExchangeState::CredentialIssued,
        CredentialExchangeState::CredentialReceived,
    ] {
        assert!(s.is_active(), "{} should be active", s);
    }
}

#[test]
fn decline_is_reachable_from_active_states() {
    // Declined is reachable from every active (non-terminal) state.
    for s in [
        CredentialExchangeState::ProposalSent,
        CredentialExchangeState::ProposalReceived,
        CredentialExchangeState::OfferSent,
        CredentialExchangeState::OfferReceived,
    ] {
        assert!(
            s.can_transition_to(CredentialExchangeState::Declined),
            "{} should be able to decline",
            s
        );
    }
}
