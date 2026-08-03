use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Runtime state of a workflow instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstanceData {
    pub instance_id: String,
    pub template_id: String,
    pub template_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub participants: HashMap<String, Participant>,
    /// Current FSM state name (references StateDef.name in template).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Workflow-specific data (mutable context object).
    #[serde(default = "default_json_object")]
    pub context: serde_json::Value,
    /// Action outputs accumulated over the instance lifecycle.
    #[serde(default = "default_json_object")]
    pub artifacts: serde_json::Value,
    pub status: InstanceStatus,
    #[serde(default)]
    pub history: Vec<InstanceHistoryItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplicity_key_value: Option<String>,
    #[serde(default)]
    pub idempotency_keys: Vec<String>,
}

fn default_json_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Active,
    Paused,
    Canceled,
    Completed,
    Error,
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceStatus::Active => write!(f, "active"),
            InstanceStatus::Paused => write!(f, "paused"),
            InstanceStatus::Canceled => write!(f, "canceled"),
            InstanceStatus::Completed => write!(f, "completed"),
            InstanceStatus::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceHistoryItem {
    pub ts: String,
    pub event: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub did: String,
}
