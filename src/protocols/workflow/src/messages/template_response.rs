use serde::{Deserialize, Serialize};

use crate::domain::template::WorkflowTemplate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResponseMessage {
    pub template: WorkflowTemplate,
}

impl TemplateResponseMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/template";
}
