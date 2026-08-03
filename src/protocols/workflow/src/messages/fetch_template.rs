use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchTemplateMessage {
    pub template_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_version: Option<String>,
    #[serde(default)]
    pub prefer_hash: bool,
}

impl FetchTemplateMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/fetch-template";
}
