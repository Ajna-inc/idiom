use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::instance_record::WorkflowInstanceRecord;
use crate::error::Result;
use crate::WorkflowError;

#[async_trait]
pub trait WorkflowInstanceRepositoryTrait: Send + Sync {
    async fn save(&self, record: &WorkflowInstanceRecord) -> Result<()>;
    async fn update(&self, record: &WorkflowInstanceRecord) -> Result<()>;
    async fn find_by_instance_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkflowInstanceRecord>>;
    async fn find_by_template_and_connection(
        &self,
        template_id: &str,
        connection_id: Option<&str>,
    ) -> Result<Vec<WorkflowInstanceRecord>>;
    async fn find_by_connection(&self, connection_id: &str) -> Result<Vec<WorkflowInstanceRecord>>;
    async fn find_latest_by_connection(
        &self,
        connection_id: &str,
    ) -> Result<Option<WorkflowInstanceRecord>>;
    async fn find_all(&self) -> Result<Vec<WorkflowInstanceRecord>>;
    async fn delete(&self, id: &str) -> Result<()>;
}

/// In-memory implementation of the instance repository.
pub struct WorkflowInstanceRepository {
    records: Arc<RwLock<HashMap<String, WorkflowInstanceRecord>>>,
}

impl WorkflowInstanceRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for WorkflowInstanceRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WorkflowInstanceRepositoryTrait for WorkflowInstanceRepository {
    async fn save(&self, record: &WorkflowInstanceRecord) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &WorkflowInstanceRecord) -> Result<()> {
        let mut records = self.records.write().await;
        if !records.contains_key(&record.id) {
            return Err(WorkflowError::InstanceNotFound(record.id.clone()));
        }
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_instance_id(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkflowInstanceRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.data.instance_id == instance_id)
            .cloned())
    }

    async fn find_by_template_and_connection(
        &self,
        template_id: &str,
        connection_id: Option<&str>,
    ) -> Result<Vec<WorkflowInstanceRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| {
                r.data.template_id == template_id
                    && r.data.connection_id.as_deref() == connection_id
            })
            .cloned()
            .collect())
    }

    async fn find_by_connection(&self, connection_id: &str) -> Result<Vec<WorkflowInstanceRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.data.connection_id.as_deref() == Some(connection_id))
            .cloned()
            .collect())
    }

    async fn find_latest_by_connection(
        &self,
        connection_id: &str,
    ) -> Result<Option<WorkflowInstanceRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.data.connection_id.as_deref() == Some(connection_id))
            .max_by_key(|r| r.created_at)
            .cloned())
    }

    async fn find_all(&self) -> Result<Vec<WorkflowInstanceRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records.remove(id);
        Ok(())
    }
}
