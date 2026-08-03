//! Signing session state machine

use serde::{Deserialize, Serialize};

/// States a signing session can be in
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningSessionState {
    /// Session proposed, awaiting request or decline
    Proposed,
    /// Signing request sent to participants, awaiting consent
    Requested,
    /// Consent received from required participants, awaiting signatures
    Consented,
    /// Partial signatures being collected
    Signing,
    /// All required signatures collected, coordinator is combining
    Combining,
    /// Combined signature created, artifacts being distributed
    Distributing,
    /// Authorization token issued, session complete
    Completed,
    /// Session declined by a required participant
    Declined,
    /// Session failed due to error or timeout
    Failed,
    /// Session explicitly abandoned/cancelled
    Abandoned,
}

impl SigningSessionState {
    /// Check if a state transition is valid
    pub fn can_transition_to(&self, next: SigningSessionState) -> bool {
        use SigningSessionState::*;
        matches!(
            (*self, next),
            // Normal flow
            (Proposed, Requested)
                | (Requested, Consented)
                | (Consented, Signing)
                | (Signing, Combining)
                | (Combining, Distributing)
                | (Combining, Completed) // single-signer: skip distribute
                | (Distributing, Completed)
                // Decline from any active state
                | (Proposed, Declined)
                | (Requested, Declined)
                | (Consented, Declined)
                // Failure from any active state
                | (Proposed, Failed)
                | (Requested, Failed)
                | (Consented, Failed)
                | (Signing, Failed)
                | (Combining, Failed)
                | (Distributing, Failed)
                // Abandon from any active state
                | (Proposed, Abandoned)
                | (Requested, Abandoned)
                | (Consented, Abandoned)
                | (Signing, Abandoned)
        )
    }

    /// Whether this state is terminal (no further transitions possible)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SigningSessionState::Completed
                | SigningSessionState::Declined
                | SigningSessionState::Failed
                | SigningSessionState::Abandoned
        )
    }

    /// Whether this state is active (not terminal)
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }
}

impl std::fmt::Display for SigningSessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proposed => write!(f, "proposed"),
            Self::Requested => write!(f, "requested"),
            Self::Consented => write!(f, "consented"),
            Self::Signing => write!(f, "signing"),
            Self::Combining => write!(f, "combining"),
            Self::Distributing => write!(f, "distributing"),
            Self::Completed => write!(f, "completed"),
            Self::Declined => write!(f, "declined"),
            Self::Failed => write!(f, "failed"),
            Self::Abandoned => write!(f, "abandoned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        use SigningSessionState::*;
        assert!(Proposed.can_transition_to(Requested));
        assert!(Requested.can_transition_to(Consented));
        assert!(Consented.can_transition_to(Signing));
        assert!(Signing.can_transition_to(Combining));
        assert!(Combining.can_transition_to(Distributing));
        assert!(Combining.can_transition_to(Completed));
        assert!(Distributing.can_transition_to(Completed));
    }

    #[test]
    fn test_invalid_transitions() {
        use SigningSessionState::*;
        assert!(!Proposed.can_transition_to(Signing));
        assert!(!Completed.can_transition_to(Requested));
        assert!(!Declined.can_transition_to(Requested));
        assert!(!Failed.can_transition_to(Requested));
    }

    #[test]
    fn test_terminal_states() {
        use SigningSessionState::*;
        assert!(Completed.is_terminal());
        assert!(Declined.is_terminal());
        assert!(Failed.is_terminal());
        assert!(Abandoned.is_terminal());
        assert!(!Proposed.is_terminal());
        assert!(!Requested.is_terminal());
        assert!(!Signing.is_terminal());
    }

    #[test]
    fn test_decline_from_active_states() {
        use SigningSessionState::*;
        assert!(Proposed.can_transition_to(Declined));
        assert!(Requested.can_transition_to(Declined));
        assert!(Consented.can_transition_to(Declined));
    }

    #[test]
    fn test_failure_from_active_states() {
        use SigningSessionState::*;
        assert!(Proposed.can_transition_to(Failed));
        assert!(Requested.can_transition_to(Failed));
        assert!(Signing.can_transition_to(Failed));
        assert!(Combining.can_transition_to(Failed));
        assert!(Distributing.can_transition_to(Failed));
    }
}
