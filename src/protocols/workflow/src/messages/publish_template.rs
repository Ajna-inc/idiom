use serde::{Deserialize, Serialize};

use crate::domain::template::WorkflowTemplate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishTemplateMessage {
    pub template: WorkflowTemplate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl PublishTemplateMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/publish-template";
}
