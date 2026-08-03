use serde::{Deserialize, Serialize};
use std::fmt;

/// Credential exchange protocol role
///
/// - Issuer: The party that creates and issues credentials
/// - Holder: The party that receives and stores credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialExchangeRole {
    Issuer,
    Holder,
}

impl fmt::Display for CredentialExchangeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CredentialExchangeRole::Issuer => "issuer",
            CredentialExchangeRole::Holder => "holder",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialization() {
        let role = CredentialExchangeRole::Issuer;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"issuer\"");

        let deserialized: CredentialExchangeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, role);
    }

    #[test]
    fn test_display() {
        assert_eq!(CredentialExchangeRole::Issuer.to_string(), "issuer");
        assert_eq!(CredentialExchangeRole::Holder.to_string(), "holder");
    }

    #[test]
    fn test_all_roles_serialize() {
        let roles = vec![
            CredentialExchangeRole::Issuer,
            CredentialExchangeRole::Holder,
        ];

        for role in roles {
            let json = serde_json::to_string(&role).unwrap();
            let deserialized: CredentialExchangeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, role);
        }
    }
}
