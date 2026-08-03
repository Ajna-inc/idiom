use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// DID Exchange Response Message (RFC 0023)
///
/// Sent by the responder (inviter) in response to a request message.
/// Contains the responder's DID and optional DID document attachment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidExchangeResponseMessage {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id")]
    pub id: String,

    /// DID of the responder
    pub did: String,

    /// Thread decorator pointing to request message
    #[serde(rename = "~thread")]
    pub thread: Thread,

    /// Optional DID Document attachment
    #[serde(rename = "did_doc~attach", skip_serializing_if = "Option::is_none")]
    pub did_doc_attach: Option<Value>,

    /// Optional DID rotation attachment (for rotating from temp DID to permanent DID)
    #[serde(rename = "did_rotate~attach", skip_serializing_if = "Option::is_none")]
    pub did_rotate_attach: Option<Value>,
}

impl DidExchangeResponseMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/didexchange/1.1/response";

    /// Create a new response message
    pub fn new(did: String, request_thread_id: String) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            did,
            thread: Thread {
                thid: Some(request_thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            },
            did_doc_attach: None,
            did_rotate_attach: None,
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

    /// Add DID rotation attachment
    pub fn with_did_rotate_attach(mut self, did_rotate: Value) -> Self {
        self.did_rotate_attach = Some(did_rotate);
        self
    }

    /// Get the thread ID (points to request)
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
    fn test_response_creation() {
        let response = DidExchangeResponseMessage::new(
            "did:peer:456".to_string(),
            "request-thread-123".to_string(),
        );

        assert_eq!(response.msg_type, DidExchangeResponseMessage::TYPE);
        assert_eq!(response.did, "did:peer:456");
        assert_eq!(response.thread_id(), "request-thread-123");
        assert!(response.did_doc_attach.is_none());
        assert!(response.did_rotate_attach.is_none());
    }

    #[test]
    fn test_response_with_did_doc() {
        let did_doc = serde_json::json!({
            "id": "did:peer:456",
            "verificationMethod": []
        });

        let response =
            DidExchangeResponseMessage::new("did:peer:456".to_string(), "thread-1".to_string())
                .with_did_doc_attach(did_doc.clone());

        assert_eq!(response.did_doc_attach, Some(did_doc));
    }

    #[test]
    fn test_response_with_rotation() {
        let rotation = serde_json::json!({
            "from": "did:peer:temp123",
            "to": "did:peer:perm456"
        });

        let response =
            DidExchangeResponseMessage::new("did:peer:perm456".to_string(), "thread-1".to_string())
                .with_did_rotate_attach(rotation.clone());

        assert_eq!(response.did_rotate_attach, Some(rotation));
    }

    #[test]
    fn test_response_serialization() {
        let response =
            DidExchangeResponseMessage::new("did:peer:456".to_string(), "thread-123".to_string());

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("@type"));
        assert!(json.contains("@id"));
        assert!(json.contains("~thread"));
        assert!(json.contains("thid"));

        let deserialized: DidExchangeResponseMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.did, response.did);
        assert_eq!(deserialized.thread_id(), response.thread_id());
    }

    #[test]
    fn test_response_thread_structure() {
        let response = DidExchangeResponseMessage::new(
            "did:test:1".to_string(),
            "request-thread-abc".to_string(),
        );

        // Response thread ID should match request thread ID
        assert_eq!(response.thread_id(), "request-thread-abc");
        // Response should not have parent thread ID
        assert!(response.thread.pthid.is_none());
    }

    #[test]
    fn test_aries_ts_compatibility() {
        let json = r#"{
            "@type": "https://didcomm.org/didexchange/1.1/response",
            "@id": "msg-2",
            "did": "did:peer:456",
            "~thread": {
                "thid": "request-thread-1"
            }
        }"#;

        let response: DidExchangeResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(response.did, "did:peer:456");
        assert_eq!(response.thread_id(), "request-thread-1");
    }

    #[test]
    fn test_response_full_flow() {
        let did_doc = serde_json::json!({
            "id": "did:peer:responder",
            "verificationMethod": [{
                "id": "did:peer:responder#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:peer:responder"
            }]
        });

        let response = DidExchangeResponseMessage::new(
            "did:peer:responder".to_string(),
            "request-thread-xyz".to_string(),
        )
        .with_id("custom-response-id".to_string())
        .with_did_doc_attach(did_doc.clone());

        assert_eq!(response.id, "custom-response-id");
        assert_eq!(response.did, "did:peer:responder");
        assert_eq!(response.thread_id(), "request-thread-xyz");
        assert_eq!(response.did_doc_attach, Some(did_doc));
    }
}
