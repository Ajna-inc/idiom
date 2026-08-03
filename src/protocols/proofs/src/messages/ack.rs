use didcomm::core::{Message as DidcommMessage, Thread};
use serde::{Deserialize, Serialize};

/// Present Proof 3.0 Ack Message
///
/// Sent by the Verifier after successfully verifying a presentation,
/// or by the Prover to acknowledge the final state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckMessage {
    /// Message ID
    pub id: String,

    /// Thread ID (references the proof exchange thread)
    pub thread_id: String,

    /// Acknowledgment status
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
    /// Message type constant (Aries Present-Proof 2.0, for interoperable peers)
    pub const TYPE: &'static str = "https://didcomm.org/present-proof/2.0/ack";

    /// Create a new ack message
    pub fn new(thread_id: String, status: AckStatus) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            status,
        }
    }

    /// Set custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Convert to a DIDComm Message. `@type`/`@id`/`~thread` are embedded in the
    /// body so the peer (prover) reads the Aries `@type` from the decrypted
    /// body — same reasoning as the credential issue message.
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let body = serde_json::json!({
            "@type": Self::TYPE,
            "@id": self.id,
            "~thread": { "thid": self.thread_id },
            "status": self.status,
        });

        let mut msg = DidcommMessage::new(self.id.clone(), Self::TYPE.to_string(), body);

        msg.thread = Some(Thread {
            thid: Some(self.thread_id.clone()),
            pthid: None,
            sender_order: None,
            received_orders: None,
        });

        msg
    }

    /// Parse from a DIDComm Message
    pub fn from_didcomm_message(msg: &DidcommMessage) -> Result<Self, String> {
        let thread_id = msg
            .thread
            .as_ref()
            .and_then(|t| t.thid.as_deref())
            .unwrap_or(&msg.id)
            .to_string();

        let status = msg
            .body
            .get("status")
            .and_then(|v| serde_json::from_value::<AckStatus>(v.clone()).ok())
            .unwrap_or(AckStatus::Ok);

        Ok(Self {
            id: msg.id.clone(),
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
        let ack = AckMessage::new("thread-123".to_string(), AckStatus::Ok);

        assert!(!ack.id.is_empty());
        assert_eq!(ack.thread_id, "thread-123");
        assert_eq!(ack.status, AckStatus::Ok);
    }

    #[test]
    fn test_to_didcomm_message() {
        let ack = AckMessage::new("thread-abc".to_string(), AckStatus::Ok);
        let msg = ack.to_didcomm_message();

        assert_eq!(msg.msg_type, AckMessage::TYPE);
        assert_eq!(msg.id, ack.id);
        assert!(msg.thread.is_some());
        assert_eq!(
            msg.thread.as_ref().unwrap().thid,
            Some("thread-abc".to_string())
        );
        assert!(msg.attachments.is_none());
    }

    #[test]
    fn test_roundtrip() {
        let original = AckMessage::new("thread-xyz".to_string(), AckStatus::Fail);

        let msg = original.to_didcomm_message();
        let parsed = AckMessage::from_didcomm_message(&msg).unwrap();

        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.thread_id, original.thread_id);
        assert_eq!(parsed.status, original.status);
    }

    #[test]
    fn test_ack_status_serialization() {
        let ok_json = serde_json::to_string(&AckStatus::Ok).unwrap();
        assert_eq!(ok_json, "\"OK\"");

        let fail_json = serde_json::to_string(&AckStatus::Fail).unwrap();
        assert_eq!(fail_json, "\"FAIL\"");

        let pending_json = serde_json::to_string(&AckStatus::Pending).unwrap();
        assert_eq!(pending_json, "\"PENDING\"");
    }
}
