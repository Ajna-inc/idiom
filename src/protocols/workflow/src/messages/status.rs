use serde::{Deserialize, Serialize};

/// Status request message — pull-based status query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequestMessage {
    pub instance_id: String,
    #[serde(default)]
    pub include_actions: bool,
    #[serde(default)]
    pub include_ui: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
}

impl StatusRequestMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/status-request";
}

/// Status response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusMessage {
    pub instance_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default)]
    pub allowed_events: Vec<String>,
    #[serde(default)]
    pub action_menu: Vec<serde_json::Value>,
    #[serde(default = "default_json_object")]
    pub artifacts: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<serde_json::Value>,
}

fn default_json_object() -> serde_json::Value {
    serde_json::json!({})
}

impl StatusMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/status";
}
