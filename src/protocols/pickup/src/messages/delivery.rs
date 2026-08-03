//! Message Delivery message for Message Pickup Protocol V2 (RFC 0685)

use didcomm::core::models::{Attachment, Thread};
use serde::{Deserialize, Serialize};

/// Message Delivery Message (RFC 0685)
///
/// Response from mediator containing queued messages as attachments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDeliveryMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator for correlation (optional for initial delivery)
    #[serde(rename = "~thread", skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,

    /// Optional recipient key this delivery applies to
    #[serde(rename = "recipient_key", skip_serializing_if = "Option::is_none")]
    pub recipient_key: Option<String>,

    /// Attachments containing the queued messages
    /// Each attachment has id=message_id and data.base64=encrypted_message
    #[serde(rename = "~attach")]
    pub attachments: Vec<Attachment>,
}

impl MessageDeliveryMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/delivery";

    /// Create a new message delivery with a thread
    pub fn new(thread_id: String, attachments: Vec<Attachment>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Some(Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            }),
            recipient_key: None,
            attachments,
        }
    }

    /// Create without a thread (for live delivery)
    pub fn new_without_thread(attachments: Vec<Attachment>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: None,
            recipient_key: None,
            attachments,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Set recipient key
    pub fn with_recipient_key(mut self, recipient_key: String) -> Self {
        self.recipient_key = Some(recipient_key);
        self
    }

    /// Get the thread ID
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.as_ref()?.thid.as_deref()
    }

    /// Get message IDs from attachments
    pub fn message_ids(&self) -> Vec<String> {
        self.attachments
            .iter()
            .filter_map(|a| a.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm::core::models::AttachmentData;

    fn create_test_attachment(id: &str) -> Attachment {
        Attachment {
            id: Some(id.to_string()),
            description: None,
            filename: None,
            media_type: None,
            format: None,
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Base64 {
                base64: "dGVzdA==".to_string(),
            },
        }
    }

    #[test]
    fn test_new_delivery() {
        let attachments = vec![create_test_attachment("msg-1")];
        let msg = MessageDeliveryMessage::new("thread-123".to_string(), attachments);
        assert_eq!(msg.msg_type, MessageDeliveryMessage::TYPE);
        assert_eq!(msg.thread_id(), Some("thread-123"));
        assert_eq!(msg.attachments.len(), 1);
    }

    #[test]
    fn test_message_ids() {
        let attachments = vec![
            create_test_attachment("msg-1"),
            create_test_attachment("msg-2"),
        ];
        let msg = MessageDeliveryMessage::new("thread-123".to_string(), attachments);
        let ids = msg.message_ids();
        assert_eq!(ids, vec!["msg-1", "msg-2"]);
    }

    #[test]
    fn test_serialization() {
        let attachments = vec![create_test_attachment("msg-1")];
        let msg = MessageDeliveryMessage::new("thread-123".to_string(), attachments)
            .with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("delivery"));
        assert!(json.contains("~attach"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/delivery",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            },
            "~attach": [
                {
                    "id": "msg-1",
                    "data": {
                        "base64": "dGVzdA=="
                    }
                }
            ]
        }"#;
        let msg: MessageDeliveryMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.thread_id(), Some("thread-123"));
        assert_eq!(msg.attachments.len(), 1);
    }
}
