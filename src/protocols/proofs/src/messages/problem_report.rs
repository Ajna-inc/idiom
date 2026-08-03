use didcomm::core::{Message as DidcommMessage, Thread};
use serde::{Deserialize, Serialize};

/// Problem-report message for Present Proof v3.
///
/// Sent by either party to abandon the proof exchange. Follows
/// Aries RFC 0035 (report-problem).
///
/// See: <https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemReportMessage {
    pub id: String,

    pub thread_id: String,

    pub description: ProblemDescription,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_items: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub who_retries: Option<WhoRetries>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<FixHint>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_: Option<Where>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub noticed_time: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_uri: Option<String>,
}

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

/// Standard problem codes for Present Proof v3 (RFC 0037).
pub mod codes {
    pub const ABANDONED: &str = "abandoned";
    pub const PRESENTATION_VERIFICATION_FAILED: &str = "presentation-verification-failed";
    pub const PRESENTATION_REJECTED: &str = "presentation-rejected";
}

impl ProblemReportMessage {
    pub const TYPE: &'static str = "https://didcomm.org/present-proof/3.0/problem-report";

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

    pub fn abandoned(thread_id: String, en: impl Into<String>) -> Self {
        Self::new(thread_id, codes::ABANDONED, en)
    }

    pub fn verification_failed(thread_id: String, en: impl Into<String>) -> Self {
        Self::new(thread_id, codes::PRESENTATION_VERIFICATION_FAILED, en)
    }

    pub fn rejected(thread_id: String, en: impl Into<String>) -> Self {
        Self::new(thread_id, codes::PRESENTATION_REJECTED, en)
    }

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

        let mut msg = DidcommMessage::new(
            self.id.clone(),
            Self::TYPE.to_string(),
            serde_json::Value::Object(body),
        );
        msg.thread = Some(Thread {
            thid: Some(self.thread_id.clone()),
            ..Default::default()
        });
        msg
    }

    pub fn from_didcomm_message(message: &DidcommMessage) -> Result<Self, crate::ProofError> {
        let thread_id = message.thread_id().to_string();

        let description = message
            .body
            .get("description")
            .and_then(|v| serde_json::from_value::<ProblemDescription>(v.clone()).ok())
            .ok_or_else(|| {
                crate::ProofError::Protocol("problem-report missing required description".into())
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
    fn test_creation_and_roundtrip() {
        let original = ProblemReportMessage::verification_failed(
            "thread-1".into(),
            "Signature did not verify",
        );
        let didcomm = original.to_didcomm_message();
        assert_eq!(didcomm.msg_type, ProblemReportMessage::TYPE);
        let restored = ProblemReportMessage::from_didcomm_message(&didcomm).unwrap();
        assert_eq!(restored.thread_id, "thread-1");
        assert_eq!(
            restored.description.code,
            codes::PRESENTATION_VERIFICATION_FAILED
        );
        assert_eq!(restored.description.en, "Signature did not verify");
    }

    #[test]
    fn test_missing_description_errors() {
        let bad = DidcommMessage::new(
            "x".into(),
            ProblemReportMessage::TYPE.into(),
            serde_json::json!({}),
        );
        assert!(ProblemReportMessage::from_didcomm_message(&bad).is_err());
    }
}
