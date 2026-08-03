use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// DID Exchange Request Message (RFC 0023)
///
/// Sent by the requester (invitee) to initiate the DID Exchange protocol.
/// Must include parentThreadId pointing to the out-of-band invitation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidExchangeRequestMessage {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// Label for the connection (human-readable name)
    pub label: String,

    /// DID of the requester
    pub did: String,

    /// Thread decorator with parent thread ID (invitation ID)
    #[serde(rename = "~thread")]
    pub thread: Thread,

    /// Optional DID Document attachment
    #[serde(rename = "did_doc~attach", skip_serializing_if = "Option::is_none")]
    pub did_doc_attach: Option<Value>,
}

impl DidExchangeRequestMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/didexchange/1.1/request";

    /// Create a new request message
    pub fn new(label: String, did: String, parent_thread_id: String) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            label,
            did,
            thread: Thread {
                thid: Some(uuid::Uuid::new_v4().to_string()),
                pthid: Some(parent_thread_id),
                sender_order: None,
                received_orders: None,
            },
            did_doc_attach: None,
        }
    }

    /// Create with custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Add DID Document attachment
    pub fn with_did_doc_attach(mut self, did_doc: Value) -> Self {
        self.did_doc_attach = Some(did_doc);
        self
    }

    /// Get the parent thread ID (invitation ID)
    pub fn parent_thread_id(&self) -> Option<&str> {
        self.thread.pthid.as_deref()
    }

    /// Get the thread ID
    ///
    /// Returns the thread ID from ~thread.thid, or the message @id if thid is not present
    pub fn thread_id(&self) -> &str {
        self.thread.thid.as_deref().unwrap_or(&self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let request = DidExchangeRequestMessage::new(
            "Alice Agent".to_string(),
            "did:peer:123".to_string(),
            "invitation-456".to_string(),
        );

        assert_eq!(request.msg_type, DidExchangeRequestMessage::TYPE);
        assert_eq!(request.label, "Alice Agent");
        assert_eq!(request.did, "did:peer:123");
        assert_eq!(request.parent_thread_id(), Some("invitation-456"));
        assert!(request.did_doc_attach.is_none());
    }

    #[test]
    fn test_request_with_did_doc() {
        let did_doc = serde_json::json!({
            "id": "did:peer:123",
            "verificationMethod": []
        });

        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:123".to_string(),
            "inv-1".to_string(),
        )
        .with_did_doc_attach(did_doc.clone());

        assert_eq!(request.did_doc_attach, Some(did_doc));
    }

    #[test]
    fn test_request_serialization() {
        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:123".to_string(),
            "inv-1".to_string(),
        );

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("@type"));
        assert!(json.contains("@id"));
        assert!(json.contains("~thread"));
        assert!(json.contains("pthid"));

        let deserialized: DidExchangeRequestMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.label, request.label);
        assert_eq!(deserialized.did, request.did);
        assert_eq!(deserialized.parent_thread_id(), request.parent_thread_id());
    }

    #[test]
    fn test_request_thread_ids() {
        let request = DidExchangeRequestMessage::new(
            "Test".to_string(),
            "did:test:1".to_string(),
            "parent-123".to_string(),
        );

        assert_eq!(request.parent_thread_id(), Some("parent-123"));
        assert!(!request.thread_id().is_empty());
        assert_ne!(request.thread_id(), "parent-123");
    }

    #[test]
    fn test_aries_ts_compatibility() {
        let json = r#"{
            "@type": "https://didcomm.org/didexchange/1.1/request",
            "@id": "msg-1",
            "label": "Alice",
            "did": "did:peer:123",
            "~thread": {
                "thid": "thread-1",
                "pthid": "invitation-1"
            }
        }"#;

        let request: DidExchangeRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(request.label, "Alice");
        assert_eq!(request.parent_thread_id(), Some("invitation-1"));
        assert_eq!(request.thread_id(), "thread-1");
    }
}
