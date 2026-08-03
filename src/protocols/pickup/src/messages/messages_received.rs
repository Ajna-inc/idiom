//! Messages Received message for Message Pickup Protocol V2 (RFC 0685)

use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// Messages Received Message (RFC 0685)
///
/// Sent by the recipient to acknowledge receipt of delivered messages.
/// The mediator should remove these messages from the queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessagesReceivedMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator for correlation
    #[serde(rename = "~thread", skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,

    /// List of message IDs that were successfully received
    #[serde(rename = "message_id_list")]
    pub message_id_list: Vec<String>,
}

impl MessagesReceivedMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/messagepickup/2.0/messages-received";

    /// Create a new messages received acknowledgment
    pub fn new(message_id_list: Vec<String>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: None,
            message_id_list,
        }
    }

    /// Create with a thread (for correlation with delivery-request)
    pub fn new_with_thread(thread_id: String, message_id_list: Vec<String>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Some(Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            }),
            message_id_list,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Set thread
    pub fn with_thread(mut self, thread_id: String) -> Self {
        self.thread = Some(Thread {
            thid: Some(thread_id),
            pthid: None,
            sender_order: None,
            received_orders: None,
        });
        self
    }

    /// Get the thread ID
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.as_ref()?.thid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_messages_received() {
        let msg = MessagesReceivedMessage::new(vec!["msg-1".to_string(), "msg-2".to_string()]);
        assert_eq!(msg.msg_type, MessagesReceivedMessage::TYPE);
        assert_eq!(msg.message_id_list.len(), 2);
        assert!(msg.thread.is_none());
    }

    #[test]
    fn test_with_thread() {
        let msg = MessagesReceivedMessage::new_with_thread(
            "thread-123".to_string(),
            vec!["msg-1".to_string()],
        );
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[test]
    fn test_serialization() {
        let msg =
            MessagesReceivedMessage::new(vec!["msg-1".to_string()]).with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("messages-received"));
        assert!(json.contains("message_id_list"));
        assert!(json.contains("msg-1"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/messages-received",
            "@id": "test-id",
            "message_id_list": ["msg-1", "msg-2"]
        }"#;
        let msg: MessagesReceivedMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.message_id_list, vec!["msg-1", "msg-2"]);
    }

    #[test]
    fn test_deserialization_with_thread() {
        let json = r#"{
            "@type": "https://didcomm.org/messagepickup/2.0/messages-received",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            },
            "message_id_list": ["msg-1"]
        }"#;
        let msg: MessagesReceivedMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }
}
