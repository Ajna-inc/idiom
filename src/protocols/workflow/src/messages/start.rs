use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::domain::instance::Participant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartMessage {
    pub template_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participants: Option<HashMap<String, Participant>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_discover: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_hash: Option<String>,
}

impl StartMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/start";
}
