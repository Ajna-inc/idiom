use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemReportMessage {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}

impl ProblemReportMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/problem-report";
}
