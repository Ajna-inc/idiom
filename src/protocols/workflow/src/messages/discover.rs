use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<DiscoverFilters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paging: Option<PagingParams>,
    #[serde(default)]
    pub include_hash: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagingParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl DiscoverMessage {
    pub const TYPE: &'static str = "https://didcomm.org/workflow/1.0/discover";
}
