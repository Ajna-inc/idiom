//! Delete Message Type
//!
//! DIDComm Delete Message protocol (https://didcomm.org/basicmessage/1.0/delete)
//! For deleting previously sent basic messages between agents

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Delete message protocol type URI
pub const DELETE_MESSAGE_TYPE: &str = "https://didcomm.org/basicmessage/1.0/delete";

/// DIDComm Delete Message
///
/// Requests that a previously sent message be deleted.
/// The `message_id` refers to the original BasicMessage `@id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeleteMessage {
    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Message type (always DELETE_MESSAGE_TYPE)
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// The ID of the original message being deleted
    pub message_id: String,

    /// When the delete was requested (ISO 8601 timestamp)
    pub deleted_time: String,
}

impl DeleteMessage {
    /// Create a new delete message
    ///
    /// # Arguments
    /// * `message_id` - The ID of the message to delete
    pub fn new(message_id: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            msg_type: DELETE_MESSAGE_TYPE.to_string(),
            message_id: message_id.into(),
            deleted_time: Utc::now().to_rfc3339(),
        }
    }

    /// Create a delete message with a specific ID
    pub fn with_id(id: impl Into<String>, message_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            msg_type: DELETE_MESSAGE_TYPE.to_string(),
            message_id: message_id.into(),
            deleted_time: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_delete_message() {
        let msg = DeleteMessage::new("msg-123");

        assert_eq!(msg.msg_type, DELETE_MESSAGE_TYPE);
        assert_eq!(msg.message_id, "msg-123");
        assert!(!msg.id.is_empty());
        assert!(!msg.deleted_time.is_empty());
    }

    #[test]
    fn test_create_delete_message_with_id() {
        let msg = DeleteMessage::with_id("del-1", "msg-123");

        assert_eq!(msg.id, "del-1");
        assert_eq!(msg.message_id, "msg-123");
    }

    #[test]
    fn test_serialization() {
        let msg = DeleteMessage::new("msg-123");
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("@id"));
        assert!(json.contains("@type"));
        assert!(json.contains("message_id"));
        assert!(json.contains("deleted_time"));
        assert!(json.contains("basicmessage/1.0/delete"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@id": "del-456",
            "@type": "https://didcomm.org/basicmessage/1.0/delete",
            "message_id": "msg-789",
            "deleted_time": "2026-01-01T00:00:00Z"
        }"#;

        let msg: DeleteMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "del-456");
        assert_eq!(msg.msg_type, DELETE_MESSAGE_TYPE);
        assert_eq!(msg.message_id, "msg-789");
        assert_eq!(msg.deleted_time, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_roundtrip() {
        let original = DeleteMessage::new("msg-abc");
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: DeleteMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }
}
