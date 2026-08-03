use serde::{Deserialize, Serialize};
use std::fmt;

/// Role in the mediation protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediationRole {
    /// Client requesting mediation services
    Recipient,
    /// Server providing mediation services
    Mediator,
}

impl MediationRole {
    /// Check if this is the recipient role
    pub fn is_recipient(&self) -> bool {
        matches!(self, Self::Recipient)
    }

    /// Check if this is the mediator role
    pub fn is_mediator(&self) -> bool {
        matches!(self, Self::Mediator)
    }
}

impl fmt::Display for MediationRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recipient => write!(f, "recipient"),
            Self::Mediator => write!(f, "mediator"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_display() {
        assert_eq!(MediationRole::Recipient.to_string(), "recipient");
        assert_eq!(MediationRole::Mediator.to_string(), "mediator");
    }

    #[test]
    fn test_role_checks() {
        assert!(MediationRole::Recipient.is_recipient());
        assert!(!MediationRole::Recipient.is_mediator());
        assert!(MediationRole::Mediator.is_mediator());
        assert!(!MediationRole::Mediator.is_recipient());
    }

    #[test]
    fn test_role_serialization() {
        let role = MediationRole::Recipient;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"recipient\"");

        let role = MediationRole::Mediator;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"mediator\"");
    }
}
