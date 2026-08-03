use serde::{Deserialize, Serialize};
use std::fmt;

/// Issue Credential v3 protocol state machine
///
/// Represents the states in the credential exchange protocol:
/// - ProposalSent: Holder has sent a credential proposal
/// - ProposalReceived: Issuer has received a credential proposal
/// - OfferSent: Issuer has sent a credential offer
/// - OfferReceived: Holder has received a credential offer
/// - Declined: Receiver explicitly rejected the offer/proposal (terminal)
/// - RequestSent: Holder has sent a credential request
/// - RequestReceived: Issuer has received a credential request
/// - CredentialIssued: Issuer has issued the credential
/// - CredentialReceived: Holder has received the credential
/// - Done: Protocol complete
/// - Abandoned: Protocol abandoned/failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialExchangeState {
    ProposalSent,
    ProposalReceived,
    OfferSent,
    OfferReceived,
    /// Receiver explicitly rejected the offer/proposal (terminal).
    Declined,
    RequestSent,
    RequestReceived,
    CredentialIssued,
    CredentialReceived,
    Done,
    Abandoned,
}

impl CredentialExchangeState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            CredentialExchangeState::Done
                | CredentialExchangeState::Abandoned
                | CredentialExchangeState::Declined
        )
    }

    /// Check if this is an active state (not terminal)
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Get valid next states from current state
    pub fn valid_next_states(&self) -> &[CredentialExchangeState] {
        use CredentialExchangeState::*;
        match self {
            // Holder side: after proposing, issuer either offers or abandons
            ProposalSent => &[OfferReceived, Declined, Abandoned],
            // Issuer side: after receiving a proposal, send an offer or abandon
            ProposalReceived => &[OfferSent, Declined, Abandoned],
            OfferSent => &[RequestReceived, Declined, Abandoned],
            OfferReceived => &[RequestSent, Declined, Abandoned],
            RequestSent => &[CredentialReceived, Abandoned],
            RequestReceived => &[CredentialIssued, Abandoned],
            CredentialIssued => &[Done, Abandoned],
            CredentialReceived => &[Done, Abandoned],
            Done => &[],
            Abandoned => &[],
            Declined => &[],
        }
    }

    /// Check if transition to next state is valid
    pub fn can_transition_to(&self, next: CredentialExchangeState) -> bool {
        self.valid_next_states().contains(&next)
    }
}

impl fmt::Display for CredentialExchangeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CredentialExchangeState::ProposalSent => "proposal-sent",
            CredentialExchangeState::ProposalReceived => "proposal-received",
            CredentialExchangeState::OfferSent => "offer-sent",
            CredentialExchangeState::OfferReceived => "offer-received",
            CredentialExchangeState::Declined => "declined",
            CredentialExchangeState::RequestSent => "request-sent",
            CredentialExchangeState::RequestReceived => "request-received",
            CredentialExchangeState::CredentialIssued => "credential-issued",
            CredentialExchangeState::CredentialReceived => "credential-received",
            CredentialExchangeState::Done => "done",
            CredentialExchangeState::Abandoned => "abandoned",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization() {
        let state = CredentialExchangeState::OfferSent;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"OfferSent\"");

        let deserialized: CredentialExchangeState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_is_terminal() {
        assert!(!CredentialExchangeState::OfferSent.is_terminal());
        assert!(!CredentialExchangeState::RequestSent.is_terminal());
        assert!(!CredentialExchangeState::CredentialIssued.is_terminal());
        assert!(CredentialExchangeState::Done.is_terminal());
        assert!(CredentialExchangeState::Abandoned.is_terminal());
    }

    #[test]
    fn test_is_active() {
        assert!(CredentialExchangeState::OfferSent.is_active());
        assert!(CredentialExchangeState::OfferReceived.is_active());
        assert!(!CredentialExchangeState::Done.is_active());
        assert!(!CredentialExchangeState::Abandoned.is_active());
    }

    #[test]
    fn test_valid_transitions() {
        // Issuer flow
        assert!(CredentialExchangeState::OfferSent
            .can_transition_to(CredentialExchangeState::RequestReceived));
        assert!(CredentialExchangeState::RequestReceived
            .can_transition_to(CredentialExchangeState::CredentialIssued));
        assert!(CredentialExchangeState::CredentialIssued
            .can_transition_to(CredentialExchangeState::Done));

        // Holder flow
        assert!(CredentialExchangeState::OfferReceived
            .can_transition_to(CredentialExchangeState::RequestSent));
        assert!(CredentialExchangeState::RequestSent
            .can_transition_to(CredentialExchangeState::CredentialReceived));
        assert!(CredentialExchangeState::CredentialReceived
            .can_transition_to(CredentialExchangeState::Done));

        // Invalid transitions
        assert!(
            !CredentialExchangeState::OfferSent.can_transition_to(CredentialExchangeState::Done)
        );
        assert!(
            !CredentialExchangeState::Done.can_transition_to(CredentialExchangeState::Abandoned)
        );

        // Abandon is always valid from active states
        assert!(CredentialExchangeState::OfferSent
            .can_transition_to(CredentialExchangeState::Abandoned));
        assert!(CredentialExchangeState::RequestSent
            .can_transition_to(CredentialExchangeState::Abandoned));
    }

    #[test]
    fn test_display() {
        assert_eq!(CredentialExchangeState::OfferSent.to_string(), "offer-sent");
        assert_eq!(
            CredentialExchangeState::RequestReceived.to_string(),
            "request-received"
        );
        assert_eq!(
            CredentialExchangeState::CredentialIssued.to_string(),
            "credential-issued"
        );
        assert_eq!(CredentialExchangeState::Done.to_string(), "done");
    }

    #[test]
    fn test_all_states_serialize() {
        let states = vec![
            CredentialExchangeState::OfferSent,
            CredentialExchangeState::OfferReceived,
            CredentialExchangeState::RequestSent,
            CredentialExchangeState::RequestReceived,
            CredentialExchangeState::CredentialIssued,
            CredentialExchangeState::CredentialReceived,
            CredentialExchangeState::Done,
            CredentialExchangeState::Abandoned,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: CredentialExchangeState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }
}
