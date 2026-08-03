use serde::{Deserialize, Serialize};
use std::fmt;

/// State of a mediation record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MediationState {
    /// Mediation has been requested
    Requested,
    /// Mediation has been granted
    Granted,
    /// Mediation has been denied
    Denied,
}

impl MediationState {
    /// Check if mediation is active (granted)
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Check if mediation is pending (requested)
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Requested)
    }

    /// Check if mediation was denied
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }

    /// Check if this is a valid transition from the given state
    pub fn is_valid_transition_from(&self, from: &MediationState) -> bool {
        match (from, self) {
            // Same state is always valid (no-op)
            (a, b) if a == b => true,
            // From Requested, can go to Granted or Denied
            (Self::Requested, Self::Granted) => true,
            (Self::Requested, Self::Denied) => true,
            // Once Granted or Denied, cannot transition to other states
            (Self::Granted, _) => false,
            (Self::Denied, _) => false,
            _ => false,
        }
    }
}

impl fmt::Display for MediationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::Granted => write!(f, "granted"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_display() {
        assert_eq!(MediationState::Requested.to_string(), "requested");
        assert_eq!(MediationState::Granted.to_string(), "granted");
        assert_eq!(MediationState::Denied.to_string(), "denied");
    }

    #[test]
    fn test_state_checks() {
        assert!(MediationState::Requested.is_pending());
        assert!(!MediationState::Requested.is_active());
        assert!(!MediationState::Requested.is_denied());

        assert!(MediationState::Granted.is_active());
        assert!(!MediationState::Granted.is_pending());
        assert!(!MediationState::Granted.is_denied());

        assert!(MediationState::Denied.is_denied());
        assert!(!MediationState::Denied.is_active());
        assert!(!MediationState::Denied.is_pending());
    }

    #[test]
    fn test_state_transitions() {
        // Valid transitions from Requested
        assert!(MediationState::Granted.is_valid_transition_from(&MediationState::Requested));
        assert!(MediationState::Denied.is_valid_transition_from(&MediationState::Requested));

        // Invalid transitions from Granted
        assert!(!MediationState::Requested.is_valid_transition_from(&MediationState::Granted));
        assert!(!MediationState::Denied.is_valid_transition_from(&MediationState::Granted));

        // Invalid transitions from Denied
        assert!(!MediationState::Requested.is_valid_transition_from(&MediationState::Denied));
        assert!(!MediationState::Granted.is_valid_transition_from(&MediationState::Denied));

        // Same state is always valid
        assert!(MediationState::Requested.is_valid_transition_from(&MediationState::Requested));
        assert!(MediationState::Granted.is_valid_transition_from(&MediationState::Granted));
        assert!(MediationState::Denied.is_valid_transition_from(&MediationState::Denied));
    }

    #[test]
    fn test_state_serialization() {
        let state = MediationState::Requested;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"requested\"");

        let state = MediationState::Granted;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"granted\"");
    }
}
