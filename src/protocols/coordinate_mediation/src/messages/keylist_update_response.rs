use crate::domain::{KeylistAction, KeylistResult};
use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};

/// A single keylist update result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeylistUpdated {
    /// The recipient key that was updated
    pub recipient_key: String,

    /// The action that was performed
    pub action: KeylistAction,

    /// The result of the update
    pub result: KeylistResult,
}

impl KeylistUpdated {
    /// Create a new keylist updated entry
    pub fn new(recipient_key: String, action: KeylistAction, result: KeylistResult) -> Self {
        Self {
            recipient_key,
            action,
            result,
        }
    }

    /// Create a successful update result
    pub fn success(recipient_key: String, action: KeylistAction) -> Self {
        Self::new(recipient_key, action, KeylistResult::Success)
    }

    /// Create a client error result
    pub fn client_error(recipient_key: String, action: KeylistAction) -> Self {
        Self::new(recipient_key, action, KeylistResult::ClientError)
    }

    /// Create a server error result
    pub fn server_error(recipient_key: String, action: KeylistAction) -> Self {
        Self::new(recipient_key, action, KeylistResult::ServerError)
    }

    /// Create a no-change result
    pub fn no_change(recipient_key: String, action: KeylistAction) -> Self {
        Self::new(recipient_key, action, KeylistResult::NoChange)
    }
}

/// Keylist Update Response Message (RFC 0211)
///
/// Sent by the mediator to confirm keylist updates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeylistUpdateResponseMessage {
    /// Message type
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,

    /// Message ID
    #[serde(rename = "@id", alias = "id")]
    pub id: String,

    /// Thread decorator
    #[serde(rename = "~thread")]
    pub thread: Thread,

    /// List of update results
    pub updated: Vec<KeylistUpdated>,
}

impl KeylistUpdateResponseMessage {
    /// Message type constant
    pub const TYPE: &'static str =
        "https://didcomm.org/coordinate-mediation/1.0/keylist-update-response";

    /// Create a new keylist update response message
    pub fn new(thread_id: String, updated: Vec<KeylistUpdated>) -> Self {
        Self {
            msg_type: Self::TYPE.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            thread: Thread {
                thid: Some(thread_id),
                pthid: None,
                sender_order: None,
                received_orders: None,
            },
            updated,
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

    /// Add an updated entry
    pub fn add_updated(mut self, updated: KeylistUpdated) -> Self {
        self.updated.push(updated);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylist_updated_helpers() {
        let success = KeylistUpdated::success("did:key:z6Mkk...".to_string(), KeylistAction::Add);
        assert_eq!(success.result, KeylistResult::Success);

        let error =
            KeylistUpdated::client_error("did:key:z6Mkk...".to_string(), KeylistAction::Add);
        assert_eq!(error.result, KeylistResult::ClientError);
    }

    #[test]
    fn test_new_response() {
        let updated = vec![KeylistUpdated::success(
            "did:key:z6Mkk...".to_string(),
            KeylistAction::Add,
        )];
        let msg = KeylistUpdateResponseMessage::new("thread-123".to_string(), updated);
        assert_eq!(msg.msg_type, KeylistUpdateResponseMessage::TYPE);
        assert_eq!(msg.updated.len(), 1);
        assert_eq!(msg.thread_id(), Some("thread-123"));
    }

    #[test]
    fn test_serialization() {
        let updated = vec![KeylistUpdated::success(
            "did:key:z6Mkk...".to_string(),
            KeylistAction::Add,
        )];
        let msg = KeylistUpdateResponseMessage::new("thread-123".to_string(), updated)
            .with_id("test-id".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("keylist-update-response"));
        assert!(json.contains("success"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "@type": "https://didcomm.org/coordinate-mediation/1.0/keylist-update-response",
            "@id": "test-id",
            "~thread": {
                "thid": "thread-123"
            },
            "updated": [
                {
                    "recipient_key": "did:key:z6Mkk...",
                    "action": "add",
                    "result": "success"
                }
            ]
        }"#;
        let msg: KeylistUpdateResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "test-id");
        assert_eq!(msg.updated.len(), 1);
    }
}
