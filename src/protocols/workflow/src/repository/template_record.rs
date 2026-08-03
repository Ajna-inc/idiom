use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::template::WorkflowTemplate;

pub const WORKFLOW_TEMPLATE_CATEGORY: &str = "workflow_template";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplateRecord {
    pub id: String,
    pub template_id: String,
    pub version: String,
    pub title: String,
    pub hash: String,
    pub template: WorkflowTemplate,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkflowTemplateRecord {
    pub fn new(template: WorkflowTemplate) -> Self {
        let hash = compute_template_hash(&template);
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            template_id: template.template_id.clone(),
            version: template.version.clone(),
            title: template.title.clone(),
            hash,
            template,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Compute SHA-256 hash of a template's canonical JSON representation.
pub fn compute_template_hash(template: &WorkflowTemplate) -> String {
    let json = serde_json::to_string(template).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}
