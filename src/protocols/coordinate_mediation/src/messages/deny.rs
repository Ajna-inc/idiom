use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// Mediation Deny Message (RFC 0211)
///
/// Sent by the mediator to deny a mediation request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediationDenyMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator
    #[serde(rename = "~thread")]
    pub thread: Thread,
}

impl MediationDenyMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/coordinate-mediation/1.0/mediate-deny";

    /// Create a new deny message
    pub fn new(thread_id: String) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(thread_id),
                pthid: None,
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

    /// Get the thread ID
    pub fn thread_id(&self) -> Option<&str> {
        self.thread.thid.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_deny() {
        let msg = MediationDenyMessage::new("thread-123".to_string());
        assert_eq!(msg.msg_type, MediationDenyMessage::TYPE);
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[test]
    fn test_serialization() {
        let msg =
            MediationDenyMessage::new("thread-123".to_string()).with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("mediate-deny"));
        assert!(json.contains("test-id"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-deny",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            }
        }"#;
        let msg: MediationDenyMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }
}
