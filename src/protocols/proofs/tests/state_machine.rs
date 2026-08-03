//! Present Proof state-machine tests: enforces RFC 0037 / RFC 0454
//! kebab-case wire values and the declined / terminal-state semantics.

use protocol_proofs::{ProblemReportMessage, ProofExchangeState};

#[test]
fn state_matches_present_proof_v1_rfc_0037() {
    assert_eq!(
        ProofExchangeState::ProposalSent.to_string(),
        "proposal-sent"
    );
    assert_eq!(
        ProofExchangeState::ProposalReceived.to_string(),
        "proposal-received"
    );
    assert_eq!(ProofExchangeState::RequestSent.to_string(), "request-sent");
    assert_eq!(
        ProofExchangeState::RequestReceived.to_string(),
        "request-received"
    );
    assert_eq!(
        ProofExchangeState::PresentationSent.to_string(),
        "presentation-sent"
    );
    assert_eq!(
        ProofExchangeState::PresentationReceived.to_string(),
        "presentation-received"
    );
    assert_eq!(ProofExchangeState::Declined.to_string(), "declined");
    assert_eq!(ProofExchangeState::Done.to_string(), "done");
}

#[test]
fn state_matches_present_proof_v2_rfc_0454() {
    // RFC 0454 (Present Proof V2) reuses the same wire values.
    assert_eq!(
        ProofExchangeState::ProposalSent.to_string(),
        "proposal-sent"
    );
    assert_eq!(
        ProofExchangeState::ProposalReceived.to_string(),
        "proposal-received"
    );
    assert_eq!(ProofExchangeState::RequestSent.to_string(), "request-sent");
    assert_eq!(
        ProofExchangeState::RequestReceived.to_string(),
        "request-received"
    );
    assert_eq!(
        ProofExchangeState::PresentationSent.to_string(),
        "presentation-sent"
    );
    assert_eq!(
        ProofExchangeState::PresentationReceived.to_string(),
        "presentation-received"
    );
    assert_eq!(ProofExchangeState::Declined.to_string(), "declined");
    assert_eq!(ProofExchangeState::Done.to_string(), "done");
}

#[test]
fn declined_and_abandoned_are_terminal() {
    assert!(ProofExchangeState::Done.is_terminal());
    assert!(ProofExchangeState::Abandoned.is_terminal());
    assert!(ProofExchangeState::Declined.is_terminal());
}

#[test]
fn declined_reachable_from_active_states() {
    for s in [
        ProofExchangeState::ProposalSent,
        ProofExchangeState::ProposalReceived,
        ProofExchangeState::RequestSent,
        ProofExchangeState::RequestReceived,
    ] {
        assert!(
            s.can_transition_to(ProofExchangeState::Declined),
            "{} should be able to decline",
            s
        );
    }
}

#[test]
fn problem_report_wire_roundtrip() {
    let original =
        ProblemReportMessage::verification_failed("thread-y".into(), "signature did not verify");
    let dc = original.to_didcomm_message();
    assert_eq!(dc.msg_type, ProblemReportMessage::TYPE);
    let restored = ProblemReportMessage::from_didcomm_message(&dc).unwrap();
    assert_eq!(restored.thread_id, "thread-y");
    assert_eq!(
        restored.description.code,
        "presentation-verification-failed"
    );
}
