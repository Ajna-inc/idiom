use crate::messages::{formats, AttachmentFormatDescriptor};
use didcomm::core::{Attachment, AttachmentData, Message as DidcommMessage};
use serde::{Deserialize, Serialize};

/// Propose Credential message (Issue Credential v3, Aries RFC 0453).
///
/// Sent by the holder to *initiate* a credential exchange by proposing
/// what they would like to receive. The issuer responds with an
/// offer-credential (potentially adjusted) or with a problem-report to
/// decline.
///
/// Wire type: `https://didcomm.org/issue-credential/3.0/propose-credential`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeCredentialMessage {
    /// Message ID — this is also the thread_id for a freshly initiated exchange.
    pub id: String,

    /// Thread ID for correlation
    pub thread_id: String,

    /// Attachment format descriptors (one per `proposal_attachments` entry)
    pub formats: Vec<AttachmentFormatDescriptor>,

    /// Optional human-readable comment so a UI can show why the holder is proposing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Optional machine-readable goal code (e.g. "credential.issue")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,

    /// Optional human-readable goal description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,

    /// AnonCreds-shaped credential proposal JSON.
    ///
    /// Typical contents: `schema_id`, `cred_def_id`, and (optionally)
    /// a list of preview attribute values the holder is offering to disclose.
    pub credential_proposal_json: String,
}

impl ProposeCredentialMessage {
    /// Message type constant
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/3.0/propose-credential";

    /// Build a proposal whose `id` doubles as the new thread root.
    pub fn new(credential_proposal_json: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let attach_id = uuid::Uuid::new_v4().to_string();

        Self {
            id: id.clone(),
            thread_id: id,
            formats: vec![AttachmentFormatDescriptor {
                attach_id,
                format: formats::ANONCREDS_CREDENTIAL_OFFER.to_string(),
            }],
            comment: None,
            goal_code: None,
            goal: None,
            credential_proposal_json,
        }
    }

    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_goal_code(mut self, goal_code: String) -> Self {
        self.goal_code = Some(goal_code);
        self
    }

    pub fn with_goal(mut self, goal: String) -> Self {
        self.goal = Some(goal);
        self
    }

    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let attach_id = &self.formats[0].attach_id;

        let mut body = serde_json::Map::new();
        body.insert("formats".into(), serde_json::json!(self.formats));
        if let Some(ref c) = self.comment {
            body.insert("comment".into(), serde_json::json!(c));
        }
        if let Some(ref g) = self.goal_code {
            body.insert("goal_code".into(), serde_json::json!(g));
        }
        if let Some(ref g) = self.goal {
            body.insert("goal".into(), serde_json::json!(g));
        }

        let proposal_value: serde_json::Value =
            serde_json::from_str(&self.credential_proposal_json).unwrap_or_default();

        let attachment = Attachment {
            id: Some(attach_id.clone()),
            description: None,
            filename: None,
            media_type: Some("application/json".to_string()),
            format: Some(formats::ANONCREDS_CREDENTIAL_OFFER.to_string()),
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Json {
                json: proposal_value,
            },
        };

        DidcommMessage::builder(Self::TYPE)
            .id(&self.id)
            .body(serde_json::Value::Object(body))
            .thread(&self.thread_id)
            .add_attachment(attachment)
            .build()
    }

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
        let goal_code = message
            .body
            .get("goal_code")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let goal = message
            .body
            .get("goal")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let credential_proposal_json = crate::messages::extract_attachment_json_pub(message)?;

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            formats,
            comment,
            goal_code,
            goal,
            credential_proposal_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_propose_creation() {
        let proposal = r#"{"schema_id":"schema:1","cred_def_id":"cred:1"}"#;
        let msg = ProposeCredentialMessage::new(proposal.to_string())
            .with_comment("Please consider".into())
            .with_goal_code("credential.issue".into());
        assert_eq!(msg.formats.len(), 1);
        assert_eq!(msg.comment.as_deref(), Some("Please consider"));
        assert_eq!(msg.goal_code.as_deref(), Some("credential.issue"));
    }

    #[test]
    fn test_propose_to_didcomm_and_back() {
        let proposal = r#"{"schema_id":"schema:abc"}"#;
        let original = ProposeCredentialMessage::new(proposal.to_string());
        let didcomm = original.to_didcomm_message();
        assert_eq!(didcomm.msg_type, ProposeCredentialMessage::TYPE);

        let restored = ProposeCredentialMessage::from_didcomm_message(&didcomm).unwrap();
        let original_value: serde_json::Value =
            serde_json::from_str(&original.credential_proposal_json).unwrap();
        let restored_value: serde_json::Value =
            serde_json::from_str(&restored.credential_proposal_json).unwrap();
        assert_eq!(original_value, restored_value);
        assert_eq!(restored.thread_id, original.thread_id);
    }
}
