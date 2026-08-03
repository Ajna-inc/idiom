use serde::{Deserialize, Serialize};
use std::fmt;

/// DID Exchange protocol role (RFC 0023)
///
/// - Requester: The party that initiates the protocol (sends request)
/// - Responder: The party that responds to the request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidExchangeRole {
    Requester,
    Responder,
}

impl fmt::Display for DidExchangeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DidExchangeRole::Requester => "requester",
            DidExchangeRole::Responder => "responder",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialization() {
        let role = DidExchangeRole::Requester;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"requester\"");

        let deserialized: DidExchangeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, role);
    }

    #[test]
    fn test_display() {
        assert_eq!(DidExchangeRole::Requester.to_string(), "requester");
        assert_eq!(DidExchangeRole::Responder.to_string(), "responder");
    }

    #[test]
    fn test_all_roles_serialize() {
        let roles = vec![DidExchangeRole::Requester, DidExchangeRole::Responder];

        for role in roles {
            let json = serde_json::to_string(&role).unwrap();
            let deserialized: DidExchangeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, role);
        }
    }
}
