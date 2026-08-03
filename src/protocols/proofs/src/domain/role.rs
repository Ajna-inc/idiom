use serde::{Deserialize, Serialize};
use std::fmt;

/// Present Proof protocol role
///
/// - Prover: The party that holds credentials and creates presentations
/// - Verifier: The party that requests and verifies presentations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofExchangeRole {
    Prover,
    Verifier,
}

impl fmt::Display for ProofExchangeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProofExchangeRole::Prover => "prover",
            ProofExchangeRole::Verifier => "verifier",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialization() {
        let role = ProofExchangeRole::Prover;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"prover\"");

        let deserialized: ProofExchangeRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, role);
    }

    #[test]
    fn test_display() {
        assert_eq!(ProofExchangeRole::Prover.to_string(), "prover");
        assert_eq!(ProofExchangeRole::Verifier.to_string(), "verifier");
    }

    #[test]
    fn test_all_roles_serialize() {
        let roles = vec![ProofExchangeRole::Prover, ProofExchangeRole::Verifier];

        for role in roles {
            let json = serde_json::to_string(&role).unwrap();
            let deserialized: ProofExchangeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, role);
        }
    }
}
