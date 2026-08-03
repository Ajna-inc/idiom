use didcomm::core::Message as DidcommMessage;
use serde::{Deserialize, Serialize};

/// Problem-report message for Issue Credential v3.
///
/// Sent by either party to signal an abnormal end of the protocol.
/// Follows Aries RFC 0035 (report-problem).
///
/// See: <https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemReportMessage {
    /// Message ID
    pub id: String,

    /// Thread ID — correlates to the failing credential exchange
    pub thread_id: String,

    /// Required: structured error description
    pub description: ProblemDescription,

    /// Identifiers of items the receiver had trouble interpreting (e.g. attachment ids)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_items: Option<Vec<String>>,

    /// Who should retry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_retries: Option<WhoRetries>,

    /// Suggestion for a fix in human-readable form
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<FixHint>,

    /// Scope of the impact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,

    /// Where in the stack the problem was first noticed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_: Option<Where>,

    /// RFC 3339 timestamp of when the problem was first noticed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noticed_time: Option<String>,

    /// URL for tracking this problem
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_uri: Option<String>,

    /// URL for escalating this problem
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_uri: Option<String>,
}

/// Structured description: machine-readable `code` + human English text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDescription {
    pub code: String,
    pub en: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixHint {
    pub en: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WhoRetries {
    You,
    Me,
    Both,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    Message,
    Thread,
    Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Where {
    Cloud,
    Edge,
    Wire,
    Agency,
}

/// Standard problem codes for Issue Credential v3, per Aries RFC 0036.
pub mod codes {
    /// Issuance flow abandoned by either party.
    pub const ISSUANCE_ABANDONED: &str = "issuance-abandoned";
}

impl ProblemReportMessage {
    /// Message type constant.
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/3.0/problem-report";

    /// Build a minimal problem-report message tied to `thread_id` with
    /// the given machine code and English explanation.
    pub fn new(thread_id: String, code: impl Into<String>, en: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            description: ProblemDescription {
                code: code.into(),
                en: en.into(),
            },
            problem_items: None,
            who_retries: None,
            fix_hint: None,
            impact: None,
            where_: None,
            noticed_time: None,
            tracking_uri: None,
            escalation_uri: None,
        }
    }

    /// Shortcut: issuance-abandoned problem report.
    pub fn issuance_abandoned(thread_id: String, en: impl Into<String>) -> Self {
        Self::new(thread_id, codes::ISSUANCE_ABANDONED, en)
    }

    /// Convert to a DIDComm Message (body uses snake_case per RFC 0035).
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let mut body = serde_json::Map::new();
        body.insert(
            "description".to_string(),
            serde_json::to_value(&self.description).unwrap_or(serde_json::Value::Null),
        );
        if let Some(ref v) = self.problem_items {
            body.insert("problem_items".to_string(), serde_json::json!(v));
        }
        if let Some(v) = self.who_retries {
            body.insert(
                "who_retries".to_string(),
                serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(ref v) = self.fix_hint {
            body.insert(
                "fix_hint".to_string(),
                serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(v) = self.impact {
            body.insert(
                "impact".to_string(),
                serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(v) = self.where_ {
            body.insert(
                "where".to_string(),
                serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(ref v) = self.noticed_time {
            body.insert("noticed_time".to_string(), serde_json::json!(v));
        }
        if let Some(ref v) = self.tracking_uri {
            body.insert("tracking_uri".to_string(), serde_json::json!(v));
        }
        if let Some(ref v) = self.escalation_uri {
            body.insert("escalation_uri".to_string(), serde_json::json!(v));
        }

        DidcommMessage::builder(Self::TYPE)
            .id(&self.id)
            .body(serde_json::Value::Object(body))
            .thread(&self.thread_id)
            .build()
    }

    /// Parse from an inbound DIDComm Message.
    pub fn from_didcomm_message(message: &DidcommMessage) -> Result<Self, crate::CredentialError> {
        let thread_id = message.thread_id().to_string();

        let description = message
            .body
            .get("description")
            .and_then(|v| serde_json::from_value::<ProblemDescription>(v.clone()).ok())
            .ok_or_else(|| {
                crate::CredentialError::Protocol(
                    "problem-report missing required description".into(),
                )
            })?;

        let problem_items = message
            .body
            .get("problem_items")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok());

        let who_retries = message
            .body
            .get("who_retries")
            .and_then(|v| serde_json::from_value::<WhoRetries>(v.clone()).ok());

        let fix_hint = message
            .body
            .get("fix_hint")
            .and_then(|v| serde_json::from_value::<FixHint>(v.clone()).ok());

        let impact = message
            .body
            .get("impact")
            .and_then(|v| serde_json::from_value::<Impact>(v.clone()).ok());

        let where_ = message
            .body
            .get("where")
            .and_then(|v| serde_json::from_value::<Where>(v.clone()).ok());

        let noticed_time = message
            .body
            .get("noticed_time")
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        let tracking_uri = message
            .body
            .get("tracking_uri")
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        let escalation_uri = message
            .body
            .get("escalation_uri")
            .and_then(|v| v.as_str().map(|s| s.to_string()));

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            description,
            problem_items,
            who_retries,
            fix_hint,
            impact,
            where_,
            noticed_time,
            tracking_uri,
            escalation_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_report_creation() {
        let msg = ProblemReportMessage::issuance_abandoned(
            "thread-123".into(),
            "Issuer rejected the request",
        );
        assert_eq!(msg.thread_id, "thread-123");
        assert_eq!(msg.description.code, codes::ISSUANCE_ABANDONED);
        assert_eq!(msg.description.en, "Issuer rejected the request");
    }

    #[test]
    fn test_problem_report_to_didcomm() {
        let msg =
            ProblemReportMessage::issuance_abandoned("thread-123".into(), "Out of credentials");
        let didcomm = msg.to_didcomm_message();
        assert_eq!(didcomm.msg_type, ProblemReportMessage::TYPE);
        assert_eq!(didcomm.thread_id(), "thread-123");
        let desc = didcomm.body.get("description").unwrap();
        assert_eq!(desc.get("code").unwrap(), "issuance-abandoned");
    }

    #[test]
    fn test_problem_report_roundtrip() {
        let mut original =
            ProblemReportMessage::issuance_abandoned("thread-abc".into(), "Holder cancelled");
        original.who_retries = Some(WhoRetries::None);
        original.impact = Some(Impact::Thread);

        let didcomm = original.to_didcomm_message();
        let restored = ProblemReportMessage::from_didcomm_message(&didcomm).unwrap();

        assert_eq!(restored.thread_id, original.thread_id);
        assert_eq!(restored.description.code, original.description.code);
        assert_eq!(restored.who_retries, Some(WhoRetries::None));
        assert_eq!(restored.impact, Some(Impact::Thread));
    }

    #[test]
    fn test_problem_report_missing_description() {
        let bad = DidcommMessage::builder(ProblemReportMessage::TYPE)
            .id("test")
            .body(serde_json::json!({}))
            .thread("thread-1")
            .build();
        let result = ProblemReportMessage::from_didcomm_message(&bad);
        assert!(result.is_err());
    }
}
