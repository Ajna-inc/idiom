use serde::{Deserialize, Serialize};

use super::discover::PagingParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowsResponseMessage {
    pub workflows: Vec<WorkflowSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paging: Option<PagingParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSummary {
    pub template_id: String,
    pub versions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl WorkflowsResponseMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/workflows";
}
