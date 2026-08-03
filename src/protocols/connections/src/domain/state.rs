use serde::{Deserialize, Serialize};
use std::fmt;

/// DID Exchange protocol state machine (RFC 0023)
///
/// Represents the 9 states in the DID Exchange protocol:
/// - Start: Initial state
/// - InvitationSent: Inviter has sent invitation (via OOB)
/// - InvitationReceived: Invitee has received invitation
/// - RequestSent: Requester has sent request
/// - RequestReceived: Responder has received request
/// - ResponseSent: Responder has sent response
/// - ResponseReceived: Requester has received response
/// - Completed: Protocol complete, connection active
/// - Abandoned: Protocol abandoned/failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidExchangeState {
    Start,
    InvitationSent,
    InvitationReceived,
    RequestSent,
    RequestReceived,
    ResponseSent,
    ResponseReceived,
    Completed,
    Abandoned,
}

impl DidExchangeState {
    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DidExchangeState::Completed | DidExchangeState::Abandoned
        )
    }

    /// Check if this is an active state (not terminal)
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Get valid next states from current state
    pub fn valid_next_states(&self) -> &[DidExchangeState] {
        use DidExchangeState::*;
        match self {
            Start => &[InvitationSent, InvitationReceived],
            InvitationSent => &[RequestReceived, Abandoned],
            InvitationReceived => &[RequestSent, Abandoned],
            RequestSent => &[ResponseReceived, Abandoned],
            RequestReceived => &[ResponseSent, Abandoned],
            ResponseSent => &[Completed, Abandoned],
            ResponseReceived => &[Completed, Abandoned],
            Completed => &[],
            Abandoned => &[],
        }
    }

    /// Check if transition to next state is valid
    pub fn can_transition_to(&self, next: DidExchangeState) -> bool {
        self.valid_next_states().contains(&next)
    }

    /// Map this DID Exchange (RFC 0023) state to the older Connection
    /// (RFC 0160) state values, for callers that still speak the legacy
    /// protocol.
    pub fn rfc0160_state(&self) -> ConnectionState {
        match self {
            DidExchangeState::Start | DidExchangeState::Abandoned => ConnectionState::Null,
            DidExchangeState::InvitationSent | DidExchangeState::InvitationReceived => {
                ConnectionState::Invited
            }
            DidExchangeState::RequestSent | DidExchangeState::RequestReceived => {
                ConnectionState::Requested
            }
            DidExchangeState::ResponseSent | DidExchangeState::ResponseReceived => {
                ConnectionState::Responded
            }
            DidExchangeState::Completed => ConnectionState::Complete,
        }
    }
}

/// Legacy Aries Connection (RFC 0160) state — a 5-state alternative to the
/// 9-state DidExchange machine. Included so idiom can interoperate with
/// implementations still emitting the old protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Null,
    Invited,
    Requested,
    Responded,
    Complete,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectionState::Null => "null",
            ConnectionState::Invited => "invited",
            ConnectionState::Requested => "requested",
            ConnectionState::Responded => "responded",
            ConnectionState::Complete => "complete",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for DidExchangeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DidExchangeState::Start => "start",
            DidExchangeState::InvitationSent => "invitation-sent",
            DidExchangeState::InvitationReceived => "invitation-received",
            DidExchangeState::RequestSent => "request-sent",
            DidExchangeState::RequestReceived => "request-received",
            DidExchangeState::ResponseSent => "response-sent",
            DidExchangeState::ResponseReceived => "response-received",
            DidExchangeState::Completed => "completed",
            DidExchangeState::Abandoned => "abandoned",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization() {
        let state = DidExchangeState::InvitationSent;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"InvitationSent\"");

        let deserialized: DidExchangeState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_is_terminal() {
        assert!(!DidExchangeState::Start.is_terminal());
        assert!(!DidExchangeState::InvitationSent.is_terminal());
        assert!(!DidExchangeState::RequestSent.is_terminal());
        assert!(DidExchangeState::Completed.is_terminal());
        assert!(DidExchangeState::Abandoned.is_terminal());
    }

    #[test]
    fn test_is_active() {
        assert!(DidExchangeState::Start.is_active());
        assert!(DidExchangeState::InvitationSent.is_active());
        assert!(!DidExchangeState::Completed.is_active());
        assert!(!DidExchangeState::Abandoned.is_active());
    }

    #[test]
    fn test_valid_transitions() {
        // From Start
        assert!(DidExchangeState::Start.can_transition_to(DidExchangeState::InvitationSent));
        assert!(DidExchangeState::Start.can_transition_to(DidExchangeState::InvitationReceived));
        assert!(!DidExchangeState::Start.can_transition_to(DidExchangeState::RequestSent));

        // From InvitationReceived
        assert!(
            DidExchangeState::InvitationReceived.can_transition_to(DidExchangeState::RequestSent)
        );
        assert!(DidExchangeState::InvitationReceived.can_transition_to(DidExchangeState::Abandoned));
        assert!(
            !DidExchangeState::InvitationReceived.can_transition_to(DidExchangeState::Completed)
        );

        // From Completed (terminal)
        assert!(!DidExchangeState::Completed.can_transition_to(DidExchangeState::Abandoned));
    }

    #[test]
    fn test_display() {
        assert_eq!(
            DidExchangeState::InvitationSent.to_string(),
            "invitation-sent"
        );
        assert_eq!(
            DidExchangeState::RequestReceived.to_string(),
            "request-received"
        );
        assert_eq!(DidExchangeState::Completed.to_string(), "completed");
    }

    #[test]
    fn test_all_states_serialize() {
        let states = vec![
            DidExchangeState::Start,
            DidExchangeState::InvitationSent,
            DidExchangeState::InvitationReceived,
            DidExchangeState::RequestSent,
            DidExchangeState::RequestReceived,
            DidExchangeState::ResponseSent,
            DidExchangeState::ResponseReceived,
            DidExchangeState::Completed,
            DidExchangeState::Abandoned,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: DidExchangeState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }
}
