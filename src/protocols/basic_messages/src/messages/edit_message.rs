//! Edit Message Type
//!
//! DIDComm Edit Message protocol (https://didcomm.org/basicmessage/1.0/edit)
//! For editing previously sent basic messages between agents

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Edit message protocol type URI
pub const EDIT_MESSAGE_TYPE: &str = "https://didcomm.org/basicmessage/1.0/edit";

/// DIDComm Edit Message
///
/// Requests that a previously sent message's content be replaced.
/// The `message_id` refers to the original BasicMessage `@id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EditMessage {
    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Message type (always EDIT_MESSAGE_TYPE)
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// The ID of the original message being edited
    pub message_id: String,

    /// The new content to replace the original
    pub content: String,

    /// When the edit was sent (ISO 8601 timestamp)
    pub edited_time: String,
}

impl EditMessage {
    /// Create a new edit message
    ///
    /// # Arguments
    /// * `message_id` - The ID of the message to edit
    /// * `content` - The replacement content
    pub fn new(message_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            msg_type: EDIT_MESSAGE_TYPE.to_string(),
            message_id: message_id.into(),
            content: content.into(),
            edited_time: Utc::now().to_rfc3339(),
        }
    }

    /// Create an edit message with a specific ID
    pub fn with_id(
        id: impl Into<String>,
        message_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            msg_type: EDIT_MESSAGE_TYPE.to_string(),
            message_id: message_id.into(),
            content: content.into(),
            edited_time: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_edit_message() {
        let msg = EditMessage::new("msg-123", "Updated content");

        assert_eq!(msg.msg_type, EDIT_MESSAGE_TYPE);
        assert_eq!(msg.message_id, "msg-123");
        assert_eq!(msg.content, "Updated content");
        assert!(!msg.id.is_empty());
        assert!(!msg.edited_time.is_empty());
    }

    #[test]
    fn test_create_edit_message_with_id() {
        let msg = EditMessage::with_id("edit-1", "msg-123", "New content");

        assert_eq!(msg.id, "edit-1");
        assert_eq!(msg.message_id, "msg-123");
        assert_eq!(msg.content, "New content");
    }

    #[test]
    fn test_serialization() {
        let msg = EditMessage::new("msg-123", "Hello edited");
        let json = serde_json::to_string(&msg).unwrap();

        assert!(json.contains("@id"));
        assert!(json.contains("@type"));
        assert!(json.contains("message_id"));
        assert!(json.contains("content"));
        assert!(json.contains("edited_time"));
        assert!(json.contains("basicmessage/1.0/edit"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@id": "edit-456",
            "@type": "https://didcomm.org/basicmessage/1.0/edit",
            "message_id": "msg-789",
            "content": "Corrected text",
            "edited_time": "2026-01-01T00:00:00Z"
        }"#;

        let msg: EditMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "edit-456");
        assert_eq!(msg.msg_type, EDIT_MESSAGE_TYPE);
        assert_eq!(msg.message_id, "msg-789");
        assert_eq!(msg.content, "Corrected text");
        assert_eq!(msg.edited_time, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_roundtrip() {
        let original = EditMessage::new("msg-abc", "Round-trip test");
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: EditMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }
}
