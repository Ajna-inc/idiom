use didcomm::core::Message as DidcommMessage;
use serde::{Deserialize, Serialize};

/// Ack message (Issue Credential v3)
///
/// Sent by the holder to acknowledge receipt and processing of the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckMessage {
    /// Message ID
    pub id: String,

    /// Thread ID for correlation (matches the exchange thread_id)
    pub thread_id: String,

    /// Status of the ack
    pub status: AckStatus,
}

/// Ack status values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AckStatus {
    Ok,
    Fail,
    Pending,
}

impl AckMessage {
    /// Message type constant (Aries Issue-Credential 2.0)
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/2.0/ack";

    /// Create a new ack message
    pub fn new(thread_id: String, status: AckStatus) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            status,
        }
    }

    /// Create an OK ack
    pub fn ok(thread_id: String) -> Self {
        Self::new(thread_id, AckStatus::Ok)
    }

    /// Convert to a DIDComm Message
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let body = serde_json::json!({
            "status": self.status,
        });

        DidcommMessage::builder(Self::TYPE)
            .id(&self.id)
            .body(body)
            .thread(&self.thread_id)
            .build()
    }

    /// Create from an inbound DIDComm Message
    pub fn from_didcomm_message(message: &DidcommMessage) -> Result<Self, crate::CredentialError> {
        let thread_id = message.thread_id().to_string();

        let status: AckStatus = message
            .body
            .get("status")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(AckStatus::Ok);

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_creation() {
        let msg = AckMessage::ok("thread-123".to_string());

        assert_eq!(msg.thread_id, "thread-123");
        assert_eq!(msg.status, AckStatus::Ok);
    }

    #[test]
    fn test_ack_to_didcomm() {
        let msg = AckMessage::ok("thread-123".to_string());
        let didcomm = msg.to_didcomm_message();

        assert_eq!(didcomm.msg_type, AckMessage::TYPE);
        assert_eq!(didcomm.thread_id(), "thread-123");
    }

    #[test]
    fn test_ack_roundtrip() {
        let original = AckMessage::ok("thread-abc".to_string());
        let didcomm = original.to_didcomm_message();
        let restored = AckMessage::from_didcomm_message(&didcomm).unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.thread_id, original.thread_id);
        assert_eq!(restored.status, original.status);
    }

    #[test]
    fn test_ack_status_serialization() {
        let ok = serde_json::to_string(&AckStatus::Ok).unwrap();
        assert_eq!(ok, "\"OK\"");

        let fail = serde_json::to_string(&AckStatus::Fail).unwrap();
        assert_eq!(fail, "\"FAIL\"");

        let pending = serde_json::to_string(&AckStatus::Pending).unwrap();
        assert_eq!(pending, "\"PENDING\"");
    }
}
