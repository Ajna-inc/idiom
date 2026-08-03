use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// Mediation Grant Message (RFC 0211)
///
/// Sent by the mediator to grant mediation and provide routing information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediationGrantMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator
    #[serde(rename = "~thread")]
    pub thread: Thread,

    /// Mediator's endpoint
    pub endpoint: String,

    /// Routing keys
    pub routing_keys: Vec<String>,
}

impl MediationGrantMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/coordinate-mediation/1.0/mediate-grant";

    /// Create a new grant message
    pub fn new(thread_id: String, endpoint: String, routing_keys: Vec<String>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            },
            endpoint,
            routing_keys,
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
    fn test_new_grant() {
        let msg = MediationGrantMessage::new(
            "thread-123".to_string(),
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );
        assert_eq!(msg.msg_type, MediationGrantMessage::TYPE);
        assert_eq!(msg.endpoint, "https://mediator.example.com");
        assert_eq!(msg.routing_keys.len(), 1);
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[test]
    fn test_serialization() {
        let msg = MediationGrantMessage::new(
            "thread-123".to_string(),
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        )
        .with_id("test-id".to_string());

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("mediate-grant"));
        assert!(json.contains("https://mediator.example.com"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/coordinate-mediation/1.0/mediate-grant",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            },
            "endpoint": "https://mediator.example.com",
            "routing_keys": ["did:key:z6Mkk..."]
        }"#;
        let msg: MediationGrantMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.endpoint, "https://mediator.example.com");
    }
}
