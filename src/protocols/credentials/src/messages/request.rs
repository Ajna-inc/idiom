use crate::messages::offer::extract_attachment_json;
use crate::messages::{formats, AttachmentFormatDescriptor};
use didcomm::core::{Attachment, AttachmentData, Message as DidcommMessage};
use serde::{Deserialize, Serialize};

/// Request Credential message (Issue Credential v3)
///
/// Sent by the holder in response to an offer, containing the AnonCreds
/// credential request as a JSON attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCredentialMessage {
    /// Message ID
    pub id: String,

    /// Thread ID for correlation (matches the offer thread_id)
    pub thread_id: String,

    /// Attachment format descriptors
    pub formats: Vec<AttachmentFormatDescriptor>,

    /// Optional comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Serialized credential request JSON
    pub credential_request_json: String,
}

impl RequestCredentialMessage {
    /// Message type constant (Aries Issue-Credential 2.0)
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/2.0/request-credential";

    /// Create a new request credential message
    pub fn new(thread_id: String, credential_request_json: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let attach_id = uuid::Uuid::new_v4().to_string();

        Self {
            id,
            thread_id,
            formats: vec![AttachmentFormatDescriptor {
                attach_id,
                format: formats::ANONCREDS_CREDENTIAL_REQUEST.to_string(),
            }],
            comment: None,
            credential_request_json,
        }
    }

    /// Set an optional comment
    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Convert to a DIDComm Message
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let attach_id = &self.formats[0].attach_id;

        let body = serde_json::json!({
            "formats": self.formats,
            "comment": self.comment,
        });

        let request_value: serde_json::Value =
            serde_json::from_str(&self.credential_request_json).unwrap_or_default();

        let attachment = Attachment {
            id: Some(attach_id.clone()),
            description: None,
            filename: None,
            media_type: Some("application/json".to_string()),
            format: Some(formats::ANONCREDS_CREDENTIAL_REQUEST.to_string()),
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Json {
                json: request_value,
            },
        };

        DidcommMessage::builder(Self::TYPE)
            .id(&self.id)
            .body(body)
            .thread(&self.thread_id)
            .add_attachment(attachment)
            .build()
    }

    /// Create from an inbound DIDComm Message
    pub fn from_didcomm_message(message: &DidcommMessage) -> Result<Self, crate::CredentialError> {
        let thread_id = message.thread_id().to_string();

        let formats: Vec<AttachmentFormatDescriptor> = message
            .body
            .get("formats")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // 2.0: `requests~attach` in the (v1-flattened) body; fall back to v3.
        let credential_request_json =
            crate::messages::extract_v2_attach(&message.body, "requests~attach")
                .map(Ok)
                .unwrap_or_else(|| extract_attachment_json(message))?;

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            formats,
            comment,
            credential_request_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let request_json = r#"{"prover_did":"did:example:holder"}"#;
        let msg = RequestCredentialMessage::new("thread-123".to_string(), request_json.to_string());

        assert_eq!(msg.thread_id, "thread-123");
        assert_eq!(msg.formats.len(), 1);
        assert_eq!(msg.formats[0].format, formats::ANONCREDS_CREDENTIAL_REQUEST);
        assert_eq!(msg.credential_request_json, request_json);
    }

    #[test]
    fn test_request_to_didcomm() {
        let msg = RequestCredentialMessage::new(
            "thread-123".to_string(),
            r#"{"prover_did":"did:example:holder"}"#.to_string(),
        );
        let didcomm = msg.to_didcomm_message();

        assert_eq!(didcomm.msg_type, RequestCredentialMessage::TYPE);
        assert_eq!(didcomm.thread_id(), "thread-123");
        assert!(didcomm.attachments.is_some());
    }

    #[test]
    fn test_request_roundtrip() {
        let request_json = r#"{"prover_did":"did:example:holder","nonce":"12345"}"#;
        let original =
            RequestCredentialMessage::new("thread-abc".to_string(), request_json.to_string());

        let didcomm = original.to_didcomm_message();
        let restored = RequestCredentialMessage::from_didcomm_message(&didcomm).unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.thread_id, original.thread_id);

        let original_value: serde_json::Value =
            serde_json::from_str(&original.credential_request_json).unwrap();
        let restored_value: serde_json::Value =
            serde_json::from_str(&restored.credential_request_json).unwrap();
        assert_eq!(original_value, restored_value);
    }
}
