use serde::{Deserialize, Serialize};

/// Mediation Request Message (RFC 0211)
///
/// Sent by the recipient to request mediation services from a mediator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediationRequestMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,
}

impl MediationRequestMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/coordinate-mediation/1.0/mediate-request";

    /// Create a new mediation request message
    pub fn new() -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

impl Default for MediationRequestMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_request() {
        let msg = MediationRequestMessage::new();
        assert_eq!(msg.msg_type, MediationRequestMessage::TYPE);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_serialization() {
        let msg = MediationRequestMessage::new().with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("mediate-request"));
        assert!(json.contains("test-id"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-request",
            "@id": "test-id"
        }"#;
        let msg: MediationRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
    }
}
