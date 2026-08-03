//! Delivery Request message for Message Pickup Protocol V2 (RFC 0685)

use serde::{Deserialize, Serialize};

/// Delivery Request Message (RFC 0685)
///
/// Sent by the recipient to request delivery of queued messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryRequestMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Maximum number of messages to deliver
    pub limit: u32,

    /// Optional recipient key to filter messages for
    #[serde(rename = "recipient_key", skip_serializing_if = "Option::is_none")]
    pub recipient_key: Option<String>,
}

impl DeliveryRequestMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/delivery-request";

    /// Create a new delivery request message
    pub fn new(limit: u32) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            limit,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_delivery_request() {
        let msg = DeliveryRequestMessage::new(10);
        assert_eq!(msg.msg_type, DeliveryRequestMessage::TYPE);
        assert_eq!(msg.limit, 10);
        assert!(!msg.id.is_empty());
    }

    #[test]
    fn test_with_recipient_key() {
        let msg =
            DeliveryRequestMessage::new(10).with_recipient_key("did:key:z6Mkk...".to_string());
        assert_eq!(msg.recipient_key, Some("did:key:z6Mkk...".to_string()));
    }

    #[test]
    fn test_serialization() {
        let msg = DeliveryRequestMessage::new(10).with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("delivery-request"));
        assert!(json.contains("\"limit\":10"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/delivery-request",
            "@id": "test-id",
            "limit": 10
        }"#;
        let msg: DeliveryRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.limit, 10);
    }

    #[test]
    fn test_deserialization_with_recipient_key() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/delivery-request",
            "@id": "test-id",
            "limit": 5,
            "recipient_key": "did:key:z6Mkk..."
        }"#;
        let msg: DeliveryRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.limit, 5);
        assert_eq!(msg.recipient_key, Some("did:key:z6Mkk...".to_string()));
    }
}
