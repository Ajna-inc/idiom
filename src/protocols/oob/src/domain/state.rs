use serde::{Deserialize, Serialize};

/// Out-of-Band state as defined in RFC 0434
///
/// State machine for Out-of-Band protocol:
/// - Sender: Initial → AwaitResponse → Done (if non-reusable) or stays in AwaitResponse (if reusable)
/// - Receiver: Initial → PrepareResponse → Done
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum OutOfBandState {
    /// Initial state before invitation is created or received
    #[default]
    Initial,

    /// Waiting for a response to the invitation (sender/inviter side)
    AwaitResponse,

    /// Preparing to respond to the invitation (receiver/invitee side)
    PrepareResponse,

    /// Invitation processing complete
    Done,
}

impl OutOfBandState {
    /// Returns true if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, OutOfBandState::Done)
    }

    /// Returns true if this state allows receiving connection requests
    pub fn can_receive_requests(&self) -> bool {
        matches!(self, OutOfBandState::AwaitResponse)
    }
}

impl std::fmt::Display for OutOfBandState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutOfBandState::Initial => write!(f, "initial"),
            OutOfBandState::AwaitResponse => write!(f, "await-response"),
            OutOfBandState::PrepareResponse => write!(f, "prepare-response"),
            OutOfBandState::Done => write!(f, "done"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization() {
        let state = OutOfBandState::AwaitResponse;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"await-response\"");

        let deserialized: OutOfBandState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_all_states_serialize() {
        let states = vec![
            OutOfBandState::Initial,
            OutOfBandState::AwaitResponse,
            OutOfBandState::PrepareResponse,
            OutOfBandState::Done,
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: OutOfBandState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }

    #[test]
    fn test_is_terminal() {
        assert!(!OutOfBandState::Initial.is_terminal());
        assert!(!OutOfBandState::AwaitResponse.is_terminal());
        assert!(!OutOfBandState::PrepareResponse.is_terminal());
        assert!(OutOfBandState::Done.is_terminal());
    }

    #[test]
    fn test_can_receive_requests() {
        assert!(!OutOfBandState::Initial.can_receive_requests());
        assert!(OutOfBandState::AwaitResponse.can_receive_requests());
        assert!(!OutOfBandState::PrepareResponse.can_receive_requests());
        assert!(!OutOfBandState::Done.can_receive_requests());
    }

    #[test]
    fn test_display() {
        assert_eq!(OutOfBandState::Initial.to_string(), "initial");
        assert_eq!(OutOfBandState::AwaitResponse.to_string(), "await-response");
        assert_eq!(
            OutOfBandState::PrepareResponse.to_string(),
            "prepare-response"
        );
        assert_eq!(OutOfBandState::Done.to_string(), "done");
    }
}
