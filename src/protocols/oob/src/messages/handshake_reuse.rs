use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Thread decorator for messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    /// Thread ID
    #[serde(rename = "thid")]
    pub thread_id: String,

    /// Parent thread ID (links to invitation)
    #[serde(rename = "pthid", skip_serializing_if = "Option::is_none")]
    pub parent_thread_id: Option<String>,
}

/// Handshake Reuse message (RFC 0434)
///
/// Sent by the receiver to reuse an existing connection instead of creating a new one
///
/// # Message Type
/// `https://didcomm.org/out-of-band/1.1/handshake-reuse`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeReuseMessage {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Thread information
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

impl HandshakeReuseMessage {
    /// Message type constant
    pub const MESSAGE_TYPE: &'static str = "https://didcomm.org/out-of-band/1.1/handshake-reuse";

    /// Create a new handshake reuse message
    pub fn new(parent_thread_id: String) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            thread: Thread {
                thread_id: Uuid::new_v4().to_string(),
                parent_thread_id: Some(parent_thread_id),
            },
        }
    }
}

/// Handshake Reuse Accepted message (RFC 0434)
///
/// Sent by the sender to acknowledge the handshake reuse
///
/// # Message Type
/// `https://didcomm.org/out-of-band/1.1/handshake-reuse-accepted`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeReuseAcceptedMessage {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Thread information
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

impl HandshakeReuseAcceptedMessage {
    /// Message type constant
    pub const MESSAGE_TYPE: &'static str =
        "https://didcomm.org/out-of-band/1.1/handshake-reuse-accepted";

    /// Create a new handshake reuse accepted message
    pub fn new(thread_id: String, parent_thread_id: String) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            thread: Thread {
                thread_id,
                parent_thread_id: Some(parent_thread_id),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_reuse_creation() {
        let message = HandshakeReuseMessage::new("parent-123".to_string());

        assert_eq!(message.msg_type, HandshakeReuseMessage::MESSAGE_TYPE);
        assert!(!message.id.is_empty());
        assert_eq!(
            message.thread.parent_thread_id,
            Some("parent-123".to_string())
        );
    }

    #[test]
    fn test_handshake_reuse_serialization() {
        let message = HandshakeReuseMessage::new("parent-123".to_string());
        let json = serde_json::to_string(&message).unwrap();

        // Verify field names
        assert!(json.contains("\"@type\""));
        assert!(json.contains("\"@id\""));
        assert!(json.contains("\"~thread\""));
        assert!(json.contains("\"thid\""));
        assert!(json.contains("\"pthid\""));

        // Deserialize
        let deserialized: HandshakeReuseMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, message.id);
        assert_eq!(
            deserialized.thread.parent_thread_id,
            message.thread.parent_thread_id
        );
    }

    #[test]
    fn test_handshake_reuse_accepted_creation() {
        let message =
            HandshakeReuseAcceptedMessage::new("thread-123".to_string(), "parent-456".to_string());

        assert_eq!(
            message.msg_type,
            HandshakeReuseAcceptedMessage::MESSAGE_TYPE
        );
        assert!(!message.id.is_empty());
        assert_eq!(message.thread.thread_id, "thread-123");
        assert_eq!(
            message.thread.parent_thread_id,
            Some("parent-456".to_string())
        );
    }

    #[test]
    fn test_handshake_reuse_accepted_serialization() {
        let message =
            HandshakeReuseAcceptedMessage::new("thread-123".to_string(), "parent-456".to_string());
        let json = serde_json::to_string(&message).unwrap();

        // Verify field names
        assert!(json.contains("\"@type\""));
        assert!(json.contains("\"@id\""));
        assert!(json.contains("\"~thread\""));

        // Deserialize
        let deserialized: HandshakeReuseAcceptedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.thread.thread_id, message.thread.thread_id);
    }
}
