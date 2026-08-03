use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::command_record::{CommandStatus, CommandType, WorkflowCommandRecord};
use crate::error::Result;

#[async_trait]
pub trait WorkflowCommandRepositoryTrait: Send + Sync {
    async fn save(&self, record: &WorkflowCommandRecord) -> Result<()>;
    async fn update(&self, record: &WorkflowCommandRecord) -> Result<()>;
    async fn find_pending(&self) -> Result<Vec<WorkflowCommandRecord>>;
    async fn find_by_thid(&self, thid: &str) -> Result<Vec<WorkflowCommandRecord>>;
    async fn find_by_cmd_and_thid_pending(
        &self,
        cmd: CommandType,
        thid: &str,
    ) -> Result<Option<WorkflowCommandRecord>>;
    async fn find_pending_starts_by_template(
        &self,
        template_id: &str,
    ) -> Result<Vec<WorkflowCommandRecord>>;
    async fn delete_completed_before(&self, before: DateTime<Utc>) -> Result<usize>;
    async fn delete(&self, id: &str) -> Result<()>;
}

/// In-memory implementation of the command repository.
pub struct WorkflowCommandRepository {
    records: Arc<RwLock<HashMap<String, WorkflowCommandRecord>>>,
}

impl WorkflowCommandRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for WorkflowCommandRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WorkflowCommandRepositoryTrait for WorkflowCommandRepository {
    async fn save(&self, record: &WorkflowCommandRecord) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &WorkflowCommandRecord) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_pending(&self) -> Result<Vec<WorkflowCommandRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.status == CommandStatus::Pending)
            .cloned()
            .collect())
    }

    async fn find_by_thid(&self, thid: &str) -> Result<Vec<WorkflowCommandRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.thid == thid)
            .cloned()
            .collect())
    }

    async fn find_by_cmd_and_thid_pending(
        &self,
        cmd: CommandType,
        thid: &str,
    ) -> Result<Option<WorkflowCommandRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| {
                r.cmd == cmd
                    && r.thid == thid
                    && (r.status == CommandStatus::Pending || r.status == CommandStatus::Processing)
            })
            .cloned())
    }

    async fn find_pending_starts_by_template(
        &self,
        template_id: &str,
    ) -> Result<Vec<WorkflowCommandRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| {
                r.cmd == CommandType::Start
                    && r.status == CommandStatus::Pending
                    && r.payload
                        .get("template_id")
                        .and_then(|v| v.as_str())
                        .map(|tid| tid == template_id)
                        .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    async fn delete_completed_before(&self, before: DateTime<Utc>) -> Result<usize> {
        let mut records = self.records.write().await;
        let to_delete: Vec<String> = records
            .values()
            .filter(|r| {
                (r.status == CommandStatus::Completed || r.status == CommandStatus::Failed)
                    && r.created_at < before
            })
            .map(|r| r.id.clone())
            .collect();
        let count = to_delete.len();
        for id in to_delete {
            records.remove(&id);
        }
        Ok(count)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records.remove(id);
        Ok(())
    }
}
