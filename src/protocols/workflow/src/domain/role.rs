use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowRole {
    Coordinator,
    Processor,
}

impl std::fmt::Display for WorkflowRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowRole::Coordinator => write!(f, "coordinator"),
            WorkflowRole::Processor => write!(f, "processor"),
        }
    }
}
