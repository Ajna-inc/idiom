use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::policy::InstancePolicy;

/// A declarative workflow definition — the "blueprint" for workflow instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub template_id: String,
    pub version: String,
    pub title: String,
    pub instance_policy: InstancePolicy,
    #[serde(default)]
    pub sections: Vec<SectionDef>,
    pub states: Vec<StateDef>,
    pub transitions: Vec<TransitionDef>,
    #[serde(default)]
    pub catalog: Catalog,
    #[serde(default)]
    pub actions: Vec<ActionDef>,
    #[serde(default)]
    pub display_hints: Option<DisplayHints>,
}

impl WorkflowTemplate {
    /// Find the start state in this template.
    pub fn start_state(&self) -> Option<&StateDef> {
        self.states
            .iter()
            .find(|s| s.state_type == StateType::Start)
    }

    /// Find a state by name.
    pub fn find_state(&self, name: &str) -> Option<&StateDef> {
        self.states.iter().find(|s| s.name == name)
    }

    /// Find an action definition by key.
    pub fn find_action(&self, key: &str) -> Option<&ActionDef> {
        self.actions.iter().find(|a| a.key == key)
    }

    /// Get transitions from a given state for a specific event.
    pub fn transitions_from(&self, state: &str, event: &str) -> Vec<&TransitionDef> {
        self.transitions
            .iter()
            .filter(|t| t.from == state && t.on == event)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDef {
    pub name: String,
    #[serde(rename = "type")]
    pub state_type: StateType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateType {
    Start,
    Normal,
    Final,
}

impl std::fmt::Display for StateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateType::Start => write!(f, "start"),
            StateType::Normal => write!(f, "normal"),
            StateType::Final => write!(f, "final"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionDef {
    pub from: String,
    pub to: String,
    pub on: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDef {
    pub key: String,
    #[serde(rename = "typeURI")]
    pub type_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<String>,
    #[serde(rename = "staticInput", skip_serializing_if = "Option::is_none")]
    pub static_input: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub credential_profiles: HashMap<String, CredentialProfile>,
    #[serde(default)]
    pub proof_profiles: HashMap<String, ProofProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_def_id: Option<String>,
    #[serde(default)]
    pub attribute_plan: HashMap<String, AttributeSpec>,
    pub to_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_def_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    #[serde(default)]
    pub requested_attributes: Vec<String>,
    #[serde(default)]
    pub requested_predicates: Vec<RequestedPredicate>,
    pub to_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedPredicate {
    pub name: String,
    pub p_type: String,
    pub p_value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source")]
pub enum AttributeSpec {
    #[serde(rename = "context")]
    Context {
        path: String,
        #[serde(default)]
        required: bool,
    },
    #[serde(rename = "static")]
    Static {
        value: serde_json::Value,
        #[serde(default)]
        required: bool,
    },
    #[serde(rename = "compute")]
    Compute {
        expr: String,
        #[serde(default)]
        required: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayHints {
    #[serde(default)]
    pub states: HashMap<String, Vec<UiItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiItem {
    #[serde(rename = "type")]
    pub item_type: String,
    #[serde(flatten)]
    pub properties: serde_json::Value,
}
