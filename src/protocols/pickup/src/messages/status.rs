//! Status message for Message Pickup Protocol V2 (RFC 0685)

use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// Status Message (RFC 0685)
///
/// Response from mediator indicating the count of queued messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator for correlation
    #[serde(rename = "~thread")]
    pub thread: Thread,

    /// Number of messages waiting in queue
    #[serde(rename = "message_count")]
    pub message_count: u64,

    /// Optional recipient key this status applies to
    #[serde(rename = "recipient_key", skip_serializing_if = "Option::is_none")]
    pub recipient_key: Option<String>,

    /// Seconds since oldest message was queued (optional)
    #[serde(
        rename = "longest_waited_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub longest_waited_seconds: Option<u64>,

    /// Total message byte count (optional)
    #[serde(rename = "total_bytes", skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,

    /// Whether live delivery is enabled (optional)
    #[serde(rename = "live_delivery", skip_serializing_if = "Option::is_none")]
    pub live_delivery: Option<bool>,
}

impl StatusMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/status";

    /// Create a new status message
    pub fn new(thread_id: String, message_count: u64) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            },
            message_count,
            recipient_key: None,
            longest_waited_seconds: None,
            total_bytes: None,
            live_delivery: None,
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

    /// Set longest waited seconds
    pub fn with_longest_waited_seconds(mut self, seconds: u64) -> Self {
        self.longest_waited_seconds = Some(seconds);
        self
    }

    /// Set total bytes
    pub fn with_total_bytes(mut self, bytes: u64) -> Self {
        self.total_bytes = Some(bytes);
        self
    }

    /// Set live delivery flag
    pub fn with_live_delivery(mut self, enabled: bool) -> Self {
        self.live_delivery = Some(enabled);
        self
    }

    /// Get the thread ID
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.thid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_status() {
        let msg = StatusMessage::new("thread-123".to_string(), 5);
        assert_eq!(msg.msg_type, StatusMessage::TYPE);
        assert_eq!(msg.message_count, 5);
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[test]
    fn test_with_optional_fields() {
        let msg = StatusMessage::new("thread-123".to_string(), 5)
            .with_recipient_key("did:key:z6Mkk...".to_string())
            .with_longest_waited_seconds(120)
            .with_total_bytes(4096)
            .with_live_delivery(false);

        assert_eq!(msg.recipient_key, Some("did:key:z6Mkk...".to_string()));
        assert_eq!(msg.longest_waited_seconds, Some(120));
        assert_eq!(msg.total_bytes, Some(4096));
        assert_eq!(msg.live_delivery, Some(false));
    }

    #[test]
    fn test_serialization() {
        let msg = StatusMessage::new("thread-123".to_string(), 5).with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("status"));
        assert!(json.contains("message_count"));
        assert!(json.contains("5"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/status",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            },
            "message_count": 5,
            "longest_waited_seconds": 120
        }"#;
        let msg: StatusMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.message_count, 5);
        assert_eq!(msg.longest_waited_seconds, Some(120));
    }
}
