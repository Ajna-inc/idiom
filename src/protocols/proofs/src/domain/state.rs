use serde::{Deserialize, Serialize};
use std::fmt;

/// Present Proof protocol state machine
///
/// Represents the states in the Present Proof 3.0 protocol:
/// - ProposalSent: Prover has sent a presentation proposal
/// - ProposalReceived: Verifier has received a presentation proposal
/// - RequestSent: Verifier has sent a proof request
/// - RequestReceived: Prover has received a proof request
/// - PresentationSent: Prover has sent a presentation
/// - PresentationReceived: Verifier has received a presentation
/// - Declined: Receiver explicitly rejected the request/proposal (terminal)
/// - Done: Protocol complete (verified or acknowledged)
/// - Abandoned: Protocol abandoned/failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofExchangeState {
    ProposalSent,
    ProposalReceived,
    RequestSent,
    RequestReceived,
    PresentationSent,
    PresentationReceived,
    Declined,
    Done,
    Abandoned,
}

impl ProofExchangeState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProofExchangeState::Done | ProofExchangeState::Abandoned | ProofExchangeState::Declined
        )
    }

    /// Check if this is an active state (not terminal)
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Get valid next states from current state
    pub fn valid_next_states(&self) -> &[ProofExchangeState] {
        use ProofExchangeState::*;
        match self {
            ProposalSent => &[RequestReceived, Declined, Abandoned],
            ProposalReceived => &[RequestSent, Declined, Abandoned],
            RequestSent => &[PresentationReceived, Declined, Abandoned],
            RequestReceived => &[PresentationSent, Declined, Abandoned],
            PresentationSent => &[Done, Abandoned],
            PresentationReceived => &[Done, Abandoned],
            Done => &[],
            Abandoned => &[],
            Declined => &[],
        }
    }

    /// Check if transition to next state is valid
    pub fn can_transition_to(&self, next: ProofExchangeState) -> bool {
        self.valid_next_states().contains(&next)
    }
}

impl fmt::Display for ProofExchangeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProofExchangeState::ProposalSent => "proposal-sent",
            ProofExchangeState::ProposalReceived => "proposal-received",
            ProofExchangeState::RequestSent => "request-sent",
            ProofExchangeState::RequestReceived => "request-received",
            ProofExchangeState::PresentationSent => "presentation-sent",
            ProofExchangeState::PresentationReceived => "presentation-received",
            ProofExchangeState::Declined => "declined",
            ProofExchangeState::Done => "done",
            ProofExchangeState::Abandoned => "abandoned",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization() {
        let state = ProofExchangeState::RequestSent;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"RequestSent\"");

        let deserialized: ProofExchangeState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_is_terminal() {
        assert!(!ProofExchangeState::RequestSent.is_terminal());
        assert!(!ProofExchangeState::RequestReceived.is_terminal());
        assert!(!ProofExchangeState::PresentationSent.is_terminal());
        assert!(!ProofExchangeState::PresentationReceived.is_terminal());
        assert!(ProofExchangeState::Done.is_terminal());
        assert!(ProofExchangeState::Abandoned.is_terminal());
    }

    #[test]
    fn test_is_active() {
        assert!(ProofExchangeState::RequestSent.is_active());
        assert!(ProofExchangeState::RequestReceived.is_active());
        assert!(!ProofExchangeState::Done.is_active());
        assert!(!ProofExchangeState::Abandoned.is_active());
    }

    #[test]
    fn test_valid_transitions() {
        // From RequestSent
        assert!(ProofExchangeState::RequestSent
            .can_transition_to(ProofExchangeState::PresentationReceived));
        assert!(ProofExchangeState::RequestSent.can_transition_to(ProofExchangeState::Abandoned));
        assert!(!ProofExchangeState::RequestSent.can_transition_to(ProofExchangeState::Done));

        // From RequestReceived
        assert!(ProofExchangeState::RequestReceived
            .can_transition_to(ProofExchangeState::PresentationSent));
        assert!(
            ProofExchangeState::RequestReceived.can_transition_to(ProofExchangeState::Abandoned)
        );
        assert!(!ProofExchangeState::RequestReceived.can_transition_to(ProofExchangeState::Done));

        // From PresentationReceived
        assert!(
            ProofExchangeState::PresentationReceived.can_transition_to(ProofExchangeState::Done)
        );
        assert!(ProofExchangeState::PresentationReceived
            .can_transition_to(ProofExchangeState::Abandoned));

        // From Done (terminal)
        assert!(!ProofExchangeState::Done.can_transition_to(ProofExchangeState::Abandoned));
    }

    #[test]
    fn test_display() {
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
        assert_eq!(ProofExchangeState::Done.to_string(), "done");
        assert_eq!(ProofExchangeState::Abandoned.to_string(), "abandoned");
    }

    #[test]
    fn test_all_states_serialize() {
        let states = vec![
            ProofExchangeState::RequestSent,
            ProofExchangeState::RequestReceived,
            ProofExchangeState::PresentationSent,
            ProofExchangeState::PresentationReceived,
            ProofExchangeState::Done,
            ProofExchangeState::Abandoned,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: ProofExchangeState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }
}
