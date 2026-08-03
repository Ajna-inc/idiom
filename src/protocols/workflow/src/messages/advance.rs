use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceMessage {
    pub instance_id: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
}

impl AdvanceMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/advance";
}
