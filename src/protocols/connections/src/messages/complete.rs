use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// DID Exchange Complete Message (RFC 0023)
///
/// Sent by the requester to finalize the DID Exchange protocol.
/// Acknowledges receipt of the response and completes the connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidExchangeCompleteMessage {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Thread decorator with both thread ID and parent thread ID
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

impl DidExchangeCompleteMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/didexchange/1.1/complete";

    /// Create a new complete message
    ///
    /// # Arguments
    /// * `request_thread_id` - The thread ID from the request message
    /// * `parent_thread_id` - The parent thread ID (invitation ID)
    pub fn new(request_thread_id: String, parent_thread_id: String) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(request_thread_id),
                pthid: Some(parent_thread_id),
                sender_order: None,
                received_orders: None,
            },
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Get the thread ID (points to request)
    ///
    /// Returns the thread ID from ~thread.thid, or the message @id if thid is not present
    pub fn thread_id(&self) -> &str {
        self.thread.thid.as_deref().unwrap_or(&self.id)
    }

    /// Get the parent thread ID (invitation ID)
    pub fn parent_thread_id(&self) -> Option<&str> {
        self.thread.pthid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_creation() {
        let complete = DidExchangeCompleteMessage::new(
            "request-thread-123".to_string(),
            "invitation-456".to_string(),
        );

        assert_eq!(complete.msg_type, DidExchangeCompleteMessage::TYPE);
        assert_eq!(complete.thread_id(), "request-thread-123");
        assert_eq!(complete.parent_thread_id(), Some("invitation-456"));
    }

    #[test]
    fn test_complete_with_custom_id() {
        let complete = DidExchangeCompleteMessage::new("thread-1".to_string(), "inv-1".to_string())
            .with_id("custom-complete-id".to_string());

        assert_eq!(complete.id, "custom-complete-id");
    }

    #[test]
    fn test_complete_serialization() {
        let complete = DidExchangeCompleteMessage::new(
            "request-thread-abc".to_string(),
            "invitation-xyz".to_string(),
        );

        let json = serde_json::to_string(&complete).unwrap();
        assert!(json.contains("@type"));
        assert!(json.contains("@id"));
        assert!(json.contains("~thread"));
        assert!(json.contains("thid"));
        assert!(json.contains("pthid"));

        let deserialized: DidExchangeCompleteMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.thread_id(), complete.thread_id());
        assert_eq!(deserialized.parent_thread_id(), complete.parent_thread_id());
    }

    #[test]
    fn test_complete_thread_structure() {
        let complete =
            DidExchangeCompleteMessage::new("thread-123".to_string(), "parent-456".to_string());

        // Complete message has both thread IDs
        assert_eq!(complete.thread_id(), "thread-123");
        assert_eq!(complete.parent_thread_id(), Some("parent-456"));
    }

    #[test]
    fn test_aries_ts_compatibility() {
        let json = r#"{
            "@type": "https://didcomm.org/didexchange/1.1/complete",
            "@id": "msg-3",
            "~thread": {
                "thid": "request-thread-1",
                "pthid": "invitation-1"
            }
        }"#;

        let complete: DidExchangeCompleteMessage = serde_json::from_str(json).unwrap();
        assert_eq!(complete.thread_id(), "request-thread-1");
        assert_eq!(complete.parent_thread_id(), Some("invitation-1"));
    }

    #[test]
    fn test_complete_minimal_structure() {
        // Complete message is minimal - just type, id, and thread
        let complete = DidExchangeCompleteMessage::new("thread-1".to_string(), "inv-1".to_string());

        let json = serde_json::to_value(&complete).unwrap();
        let obj = json.as_object().unwrap();

        // Should only have 3 fields
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("@type"));
        assert!(obj.contains_key("@id"));
        assert!(obj.contains_key("~thread"));
    }

    #[test]
    fn test_complete_thread_validation() {
        let complete = DidExchangeCompleteMessage::new(
            "request-abc".to_string(),
            "invitation-xyz".to_string(),
        );

        // Thread ID should reference the request
        assert_eq!(complete.thread.thid, Some("request-abc".to_string()));
        // Parent thread ID should reference the invitation
        assert_eq!(complete.thread.pthid, Some("invitation-xyz".to_string()));
    }
}
