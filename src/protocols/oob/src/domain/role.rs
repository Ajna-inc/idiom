use serde::{Deserialize, Serialize};

/// Role in the Out-of-Band protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutOfBandRole {
    /// Sender of the invitation (inviter)
    Sender,

    /// Receiver of the invitation (invitee)
    Receiver,
}

impl std::fmt::Display for OutOfBandRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutOfBandRole::Sender => write!(f, "sender"),
            OutOfBandRole::Receiver => write!(f, "receiver"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialization() {
        let role = OutOfBandRole::Sender;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"sender\"");

        let deserialized: OutOfBandRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, role);
    }

    #[test]
    fn test_all_roles_serialize() {
        let roles = vec![OutOfBandRole::Sender, OutOfBandRole::Receiver];

        for role in roles {
            let json = serde_json::to_string(&role).unwrap();
            let deserialized: OutOfBandRole = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, role);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(OutOfBandRole::Sender.to_string(), "sender");
        assert_eq!(OutOfBandRole::Receiver.to_string(), "receiver");
    }
}
