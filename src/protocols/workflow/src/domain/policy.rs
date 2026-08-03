use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstancePolicy {
    pub mode: PolicyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplicity_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    SingletonPerConnection,
    MultiPerConnection,
}
