//! Status Request message for Message Pickup Protocol V2 (RFC 0685)

use serde::{Deserialize, Serialize};

/// Status Request Message (RFC 0685)
///
/// Sent by the recipient to query the mediator for the count of queued messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusRequestMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Optional recipient key to filter messages for
    #[serde(rename = "recipient_key", skip_serializing_if = "Option::is_none")]
    pub recipient_key: Option<String>,
}

impl StatusRequestMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/status-request";

    /// Create a new status request message
    pub fn new() -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            recipient_key: None,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Set recipient key filter
    pub fn with_recipient_key(mut self, recipient_key: String) -> Self {
        self.recipient_key = Some(recipient_key);
        self
    }
}

impl Default for StatusRequestMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_status_request() {
        let msg = StatusRequestMessage::new();
        assert_eq!(msg.msg_type, StatusRequestMessage::TYPE);
        assert!(!msg.id.is_empty());
        assert!(msg.recipient_key.is_none());
    }

    #[test]
    fn test_with_recipient_key() {
        let msg = StatusRequestMessage::new().with_recipient_key("did:key:z6Mkk...".to_string());
        assert!(msg.recipient_key.is_some());
    }

    #[test]
    fn test_serialization() {
        let msg = StatusRequestMessage::new().with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("status-request"));
        assert!(json.contains("test-id"));
        // recipient_key should not appear when None
        assert!(!json.contains("recipient_key"));
    }

    #[test]
    fn test_serialization_with_recipient_key() {
        let msg = StatusRequestMessage::new()
            .with_id("test-id".to_string())
            .with_recipient_key("did:key:z6Mkk...".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("recipient_key"));
        assert!(json.contains("did:key:z6Mkk"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/status-request",
            "@id": "test-id"
        }"#;
        let msg: StatusRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert!(msg.recipient_key.is_none());
    }

    #[test]
    fn test_deserialization_with_recipient_key() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/status-request",
            "@id": "test-id",
            "recipient_key": "did:key:z6Mkk..."
        }"#;
        let msg: StatusRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.recipient_key, Some("did:key:z6Mkk...".to_string()));
    }
}
