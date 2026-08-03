use didcomm::core::models::Thread;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROBLEM_REPORT_TYPE: &str =
    "https://didcomm.org/push-notifications-fcm/1.0/problem-report";

/// Problem-report — sent either direction when something fails.
/// Problem-report message shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProblemReportMessage {
    #[serde(rename = "@type", alias = "type")]
    pub msg_type: String,
    #[serde(rename = "@id", alias = "id")]
    pub id: String,
    #[serde(rename = "~thread", skip_serializing_if = "Option::is_none")]
    pub thread: Option<Thread>,
    /// Machine-readable description code (e.g. `set-device-info-failed`).
    pub description: ProblemDescription,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProblemDescription {
    pub en: String,
    pub code: String,
}

impl ProblemReportMessage {
    pub fn new(thread_id: Option<String>, code: impl Into<String>, en: impl Into<String>) -> Self {
        Self {
            msg_type: PROBLEM_REPORT_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            thread: thread_id.map(|t| Thread {
                thid: Some(t),
                pthid: None,
                sender_order: None,
                received_orders: None,
            }),
            description: ProblemDescription {
                en: en.into(),
                code: code.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = ProblemReportMessage::new(
            Some("thr-1".to_string()),
            "set-device-info-failed",
            "could not persist token",
        );
        let j = serde_json::to_string(&m).unwrap();
        let back: ProblemReportMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
        assert_eq!(back.description.code, "set-device-info-failed");
    }
}
