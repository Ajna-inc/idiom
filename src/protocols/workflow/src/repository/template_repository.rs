use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::template_record::WorkflowTemplateRecord;
use crate::error::Result;
use crate::WorkflowError;

#[async_trait]
pub trait WorkflowTemplateRepositoryTrait: Send + Sync {
    async fn save(&self, record: &WorkflowTemplateRecord) -> Result<()>;
    async fn update(&self, record: &WorkflowTemplateRecord) -> Result<()>;
    async fn find_by_template_id_and_version(
        &self,
        template_id: &str,
        version: Option<&str>,
    ) -> Result<Option<WorkflowTemplateRecord>>;
    async fn find_all(&self) -> Result<Vec<WorkflowTemplateRecord>>;
    async fn delete(&self, id: &str) -> Result<()>;
}

/// In-memory implementation of the template repository.
pub struct WorkflowTemplateRepository {
    records: Arc<RwLock<HashMap<String, WorkflowTemplateRecord>>>,
}

impl WorkflowTemplateRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for WorkflowTemplateRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WorkflowTemplateRepositoryTrait for WorkflowTemplateRepository {
    async fn save(&self, record: &WorkflowTemplateRecord) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &WorkflowTemplateRecord) -> Result<()> {
        let mut records = self.records.write().await;
        if !records.contains_key(&record.id) {
            return Err(WorkflowError::TemplateNotFound(record.id.clone()));
        }
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_template_id_and_version(
        &self,
        template_id: &str,
        version: Option<&str>,
    ) -> Result<Option<WorkflowTemplateRecord>> {
        let records = self.records.read().await;
        let mut matches: Vec<&WorkflowTemplateRecord> = records
            .values()
            .filter(|r| r.template_id == template_id)
            .collect();

        if let Some(version) = version {
            return Ok(matches.into_iter().find(|r| r.version == version).cloned());
        }

        // No version specified — return the latest by version string (lexicographic).
        matches.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(matches.first().cloned().cloned())
    }

    async fn find_all(&self) -> Result<Vec<WorkflowTemplateRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records.remove(id);
        Ok(())
    }
}
