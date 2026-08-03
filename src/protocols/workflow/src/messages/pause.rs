use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseMessage {
    pub instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PauseMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/pause";
}
