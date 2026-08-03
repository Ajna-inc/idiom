use serde::{Deserialize, Serialize};

/// The original invitation type that an out-of-band invitation was derived from.
///
/// This is not part of the RFC, but allows identifying the source of the invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvitationType {
    /// Standard out-of-band invitation (RFC 0434)
    #[serde(rename = "out-of-band/1.x")]
    OutOfBand,

    /// Legacy connections protocol invitation (RFC 0160)
    #[serde(rename = "connections/1.x")]
    Connection,

    /// Connectionless exchange
    #[serde(rename = "connectionless")]
    Connectionless,
}

impl std::fmt::Display for InvitationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvitationType::OutOfBand => write!(f, "out-of-band/1.x"),
            InvitationType::Connection => write!(f, "connections/1.x"),
            InvitationType::Connectionless => write!(f, "connectionless"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_type_serialization() {
        let inv_type = InvitationType::OutOfBand;
        let json = serde_json::to_string(&inv_type).unwrap();
        assert_eq!(json, "\"out-of-band/1.x\"");

        let deserialized: InvitationType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, inv_type);
    }

    #[test]
    fn test_all_types_serialize() {
        let types = vec![
            InvitationType::OutOfBand,
            InvitationType::Connection,
            InvitationType::Connectionless,
        ];

        for inv_type in types {
            let json = serde_json::to_string(&inv_type).unwrap();
            let deserialized: InvitationType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, inv_type);
        }
    }
}
