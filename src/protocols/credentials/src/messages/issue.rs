use crate::messages::offer::extract_attachment_json;
use crate::messages::{formats, AttachmentFormatDescriptor};
use didcomm::core::Message as DidcommMessage;
use serde::{Deserialize, Serialize};

/// Issue Credential message (Issue Credential v3)
///
/// Sent by the issuer after receiving a credential request, containing
/// the AnonCreds credential as a JSON attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCredentialMessage {
    /// Message ID
    pub id: String,

    /// Thread ID for correlation (matches the offer/request thread_id)
    pub thread_id: String,

    /// Attachment format descriptors
    pub formats: Vec<AttachmentFormatDescriptor>,

    /// Optional comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Serialized credential JSON
    pub credential_json: String,
}

impl IssueCredentialMessage {
    /// Message type constant (Aries Issue-Credential 2.0, for interoperable peers)
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/2.0/issue-credential";

    /// Create a new issue credential message
    pub fn new(thread_id: String, credential_json: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let attach_id = uuid::Uuid::new_v4().to_string();

        Self {
            id,
            thread_id,
            formats: vec![AttachmentFormatDescriptor {
                attach_id,
                format: formats::ANONCREDS_CREDENTIAL.to_string(),
            }],
            comment: None,
            credential_json,
        }
    }

    /// Create an issue message with an explicit attachment format id (e.g. a
    /// W3C / JWT / SD-JWT `*@v1.0` credential id). AnonCreds [`Self::new`] is
    /// `new_with_format(thread_id, json, ANONCREDS_CREDENTIAL)`.
    pub fn new_with_format(
        thread_id: String,
        credential_json: String,
        format_id: &str,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let attach_id = uuid::Uuid::new_v4().to_string();
        Self {
            id,
            thread_id,
            formats: vec![AttachmentFormatDescriptor {
                attach_id,
                format: format_id.to_string(),
            }],
            comment: None,
            credential_json,
        }
    }

    /// The negotiated attachment format id (first descriptor).
    pub fn format_id(&self) -> Option<&str> {
        self.formats.first().map(|f| f.format.as_str())
    }

    /// Set an optional comment
    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Convert to a DIDComm Message. The `credentials~attach` decorator is put
    /// in the message BODY so the envelope service's v1 flattening yields the
    /// Aries 2.0 wire shape (`{"@type", "formats", "credentials~attach"}`).
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let attach_id = &self.formats[0].attach_id;

        // Embed the full Aries 2.0 message (`@type`, `@id`, `~thread`, formats,
        // credentials~attach) in the BODY, mirroring the offer's
        // `to_aries_v2_value`. The peer reads the Aries message — including
        // `@type` — from the decrypted body; omitting `@type` makes it reject the
        // message as "Invalid message type: undefined".
        let body = serde_json::json!({
            "@type": Self::TYPE,
            "@id": self.id,
            "~thread": { "thid": self.thread_id },
            "formats": self.formats,
            "comment": self.comment,
            "credentials~attach": [
                crate::messages::v2_attachment(
                    attach_id,
                    self.format_id().unwrap_or(formats::ANONCREDS_CREDENTIAL),
                    &self.credential_json,
                )
            ],
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

        // 2.0: `credentials~attach` lives in the (v1-flattened) body; fall back
        // to the v3 `attachments` field.
        let credential_json =
            crate::messages::extract_v2_attach(&message.body, "credentials~attach")
                .map(Ok)
                .unwrap_or_else(|| extract_attachment_json(message))?;

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            formats,
            comment,
            credential_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_creation() {
        let cred_json = r#"{"schema_id":"schema:1","values":{}}"#;
        let msg = IssueCredentialMessage::new("thread-123".to_string(), cred_json.to_string());

        assert_eq!(msg.thread_id, "thread-123");
        assert_eq!(msg.formats.len(), 1);
        assert_eq!(msg.formats[0].format, formats::ANONCREDS_CREDENTIAL);
        assert_eq!(msg.credential_json, cred_json);
    }

    #[test]
    fn test_issue_to_didcomm() {
        let msg = IssueCredentialMessage::new(
            "thread-123".to_string(),
            r#"{"schema_id":"schema:1"}"#.to_string(),
        );
        let didcomm = msg.to_didcomm_message();

        assert_eq!(didcomm.msg_type, IssueCredentialMessage::TYPE);
        assert_eq!(didcomm.thread_id(), "thread-123");
        // The credential is intentionally carried as the Aries 2.0
        // `credentials~attach` decorator inside the message BODY (so v1
        // flattening produces the interoperable wire shape), NOT in the DIDComm
        // v3 `attachments` field. The stale assertion checked `attachments`,
        // which is always None for this builder. Assert the credential attachment
        // is present in the body instead, and that it round-trips.
        assert!(didcomm.attachments.is_none());
        let attach = didcomm
            .body
            .get("credentials~attach")
            .and_then(|v| v.as_array())
            .expect("credentials~attach must be present in the body");
        assert_eq!(attach.len(), 1);
    }

    #[test]
    fn test_issue_roundtrip() {
        let cred_json = r#"{"schema_id":"schema:1","cred_def_id":"cred:1","values":{}}"#;
        let original = IssueCredentialMessage::new("thread-abc".to_string(), cred_json.to_string());

        let didcomm = original.to_didcomm_message();
        let restored = IssueCredentialMessage::from_didcomm_message(&didcomm).unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.thread_id, original.thread_id);

        let original_value: serde_json::Value =
            serde_json::from_str(&original.credential_json).unwrap();
        let restored_value: serde_json::Value =
            serde_json::from_str(&restored.credential_json).unwrap();
        assert_eq!(original_value, restored_value);
    }
}
