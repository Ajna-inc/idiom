use didcomm::core::{Attachment, AttachmentData, Message as DidcommMessage, Thread};
use serde::{Deserialize, Serialize};

use super::ANONCREDS_PROOF;

/// Present Proof 3.0 Presentation Message
///
/// Sent by the Prover in response to a request-presentation message.
/// Contains the AnonCreds presentation (proof) as an attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationMessage {
    /// Message ID
    pub id: String,

    /// Thread ID (references the request-presentation)
    pub thread_id: String,

    /// Optional comment from the prover
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Serialized presentation JSON (AnonCreds Presentation)
    pub presentation_json: String,
}

impl PresentationMessage {
    /// Message type constant (Aries Present-Proof 2.0, for interoperable peers)
    pub const TYPE: &'static str = "https://didcomm.org/present-proof/2.0/presentation";

    /// Create a new presentation message
    pub fn new(thread_id: String, presentation_json: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            comment: None,
            presentation_json,
        }
    }

    /// Set a comment on the presentation
    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Set custom message ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Convert to a DIDComm Message
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let body = serde_json::json!({
            "comment": self.comment,
        });

        let attachment = Attachment {
            id: Some(uuid::Uuid::new_v4().to_string()),
            description: None,
            filename: None,
            media_type: Some("application/json".to_string()),
            format: Some(ANONCREDS_PROOF.to_string()),
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Json {
                json: serde_json::from_str(&self.presentation_json)
                    .unwrap_or_else(|_| serde_json::Value::String(self.presentation_json.clone())),
            },
        };

        let mut msg = DidcommMessage::new(self.id.clone(), Self::TYPE.to_string(), body);

        msg.thread = Some(Thread {
            thid: Some(self.thread_id.clone()),
            pthid: None,
            sender_order: None,
            received_orders: None,
        });

        msg.attachments = Some(vec![attachment]);

        msg
    }

    /// Parse from a DIDComm Message
    pub fn from_didcomm_message(msg: &DidcommMessage) -> Result<Self, String> {
        let comment = msg
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let thread_id = msg
            .thread
            .as_ref()
            .and_then(|t| t.thid.as_deref())
            .unwrap_or(&msg.id)
            .to_string();

        // Aries 2.0: the proof lives in the v1-flattened body decorator
        // `presentations~attach`. Prefer that; fall back to the v3 `attachments`.
        if let Some(presentation_json) = super::extract_v2_attach(&msg.body, "presentations~attach")
        {
            return Ok(Self {
                id: msg.id.clone(),
                thread_id,
                comment,
                presentation_json,
            });
        }

        // Extract presentation from attachment
        let attachments = msg
            .attachments
            .as_ref()
            .ok_or_else(|| "Missing attachments in presentation message".to_string())?;

        let presentation_attachment = attachments
            .iter()
            .find(|a| a.format.as_deref() == Some(ANONCREDS_PROOF))
            .or_else(|| attachments.first())
            .ok_or_else(|| "No presentation attachment found".to_string())?;

        let presentation_json = match &presentation_attachment.data {
            AttachmentData::Json { json } => serde_json::to_string(json)
                .map_err(|e| format!("Failed to serialize presentation: {}", e))?,
            AttachmentData::Base64 { base64 } => {
                let decoded = super::request_presentation::base64_decode(base64)
                    .map_err(|e| format!("Failed to decode base64 attachment: {}", e))?;
                String::from_utf8(decoded)
                    .map_err(|e| format!("Invalid UTF-8 in presentation: {}", e))?
            }
            AttachmentData::Links { .. } => {
                return Err("Links attachments are not supported for presentations".to_string());
            }
        };

        Ok(Self {
            id: msg.id.clone(),
            thread_id,
            comment,
            presentation_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presentation_creation() {
        let presentation = PresentationMessage::new(
            "thread-123".to_string(),
            r#"{"proof":{},"requested_proof":{},"identifiers":[]}"#.to_string(),
        );

        assert!(!presentation.id.is_empty());
        assert_eq!(presentation.thread_id, "thread-123");
        assert!(presentation.comment.is_none());
    }

    #[test]
    fn test_presentation_with_comment() {
        let presentation = PresentationMessage::new("thread-1".to_string(), "{}".to_string())
            .with_comment("Here is my proof".to_string());

        assert_eq!(presentation.comment, Some("Here is my proof".to_string()));
    }

    #[test]
    fn test_to_didcomm_message() {
        let presentation =
            PresentationMessage::new("thread-abc".to_string(), r#"{"proof":{}}"#.to_string());
        let msg = presentation.to_didcomm_message();

        assert_eq!(msg.msg_type, PresentationMessage::TYPE);
        assert_eq!(msg.id, presentation.id);
        assert!(msg.attachments.is_some());
        assert_eq!(msg.attachments.as_ref().unwrap().len(), 1);

        // Verify thread is set
        assert!(msg.thread.is_some());
        assert_eq!(
            msg.thread.as_ref().unwrap().thid,
            Some("thread-abc".to_string())
        );

        let attachment = &msg.attachments.as_ref().unwrap()[0];
        assert_eq!(attachment.format.as_deref(), Some(ANONCREDS_PROOF));
    }

    #[test]
    fn test_roundtrip() {
        let original = PresentationMessage::new(
            "thread-xyz".to_string(),
            r#"{"proof":{"proofs":[]}}"#.to_string(),
        )
        .with_comment("Proof of identity".to_string());

        let msg = original.to_didcomm_message();
        let parsed = PresentationMessage::from_didcomm_message(&msg).unwrap();

        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.thread_id, original.thread_id);
        assert_eq!(parsed.comment, original.comment);
    }
}
