//! Basic Message Repository
//!
//! Storage and retrieval of basic message records

use crate::repository::basic_message_record::{BasicMessageRecord, BasicMessageRole};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

pub type Result<T> = std::result::Result<T, BasicMessageError>;

/// Errors that can occur in basic message repository operations
#[derive(Debug, Error)]
pub enum BasicMessageError {
    #[error("Basic message not found: {0}")]
    NotFound(String),

    #[error("Basic message already exists: {0}")]
    AlreadyExists(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Query for finding basic messages
#[derive(Debug, Clone, Default)]
pub struct BasicMessageQuery {
    /// Filter by connection ID
    pub connection_id: Option<String>,

    /// Filter by role (sender/receiver)
    pub role: Option<BasicMessageRole>,

    /// Filter by thread ID
    pub thread_id: Option<String>,

    /// Filter by parent thread ID
    pub parent_thread_id: Option<String>,
}

/// Trait for basic message repository operations
#[async_trait]
pub trait BasicMessageRepositoryTrait: Send + Sync {
    /// Save a new basic message record
    async fn save(&self, record: &BasicMessageRecord) -> Result<()>;

    /// Update an existing basic message record
    async fn update(&self, record: &BasicMessageRecord) -> Result<()>;

    /// Find basic message by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<BasicMessageRecord>>;

    /// Find basic messages by connection ID
    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Vec<BasicMessageRecord>>;

    /// Find basic message by thread ID
    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<BasicMessageRecord>>;

    /// Find basic messages by query
    async fn find_by_query(&self, query: BasicMessageQuery) -> Result<Vec<BasicMessageRecord>>;

    /// Delete basic message by ID
    async fn delete_by_id(&self, id: &str) -> Result<()>;

    /// Get all basic messages
    async fn get_all(&self) -> Result<Vec<BasicMessageRecord>>;
}

/// In-memory basic message repository
pub struct BasicMessageRepository {
    records: Arc<RwLock<HashMap<String, BasicMessageRecord>>>,
}

impl BasicMessageRepository {
    /// Create a new basic message repository
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for BasicMessageRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BasicMessageRepositoryTrait for BasicMessageRepository {
    async fn save(&self, record: &BasicMessageRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(BasicMessageError::AlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &BasicMessageRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(BasicMessageError::NotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<BasicMessageRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Vec<BasicMessageRecord>> {
        let records = self.records.read().await;
        let results = records
            .values()
            .filter(|r| r.connection_id == connection_id)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<BasicMessageRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.thread_id.as_deref() == Some(thread_id))
            .cloned())
    }

    async fn find_by_query(&self, query: BasicMessageQuery) -> Result<Vec<BasicMessageRecord>> {
        let records = self.records.read().await;
        let mut results: Vec<BasicMessageRecord> = records.values().cloned().collect();

        // Filter by connection ID
        if let Some(connection_id) = query.connection_id {
            results.retain(|r| r.connection_id == connection_id);
        }

        // Filter by role
        if let Some(role) = query.role {
            results.retain(|r| r.role == role);
        }

        // Filter by thread ID
        if let Some(thread_id) = query.thread_id {
            results.retain(|r| r.thread_id.as_deref() == Some(&thread_id));
        }

        // Filter by parent thread ID
        if let Some(parent_thread_id) = query.parent_thread_id {
            results.retain(|r| r.parent_thread_id.as_deref() == Some(&parent_thread_id));
        }

        Ok(results)
    }

    async fn delete_by_id(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;

        if records.remove(id).is_none() {
            return Err(BasicMessageError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<BasicMessageRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(id: &str, connection_id: &str) -> BasicMessageRecord {
        BasicMessageRecord::new(
            id,
            connection_id,
            BasicMessageRole::Sender,
            "Test message",
            "2024-01-01T00:00:00Z",
        )
    }

    #[tokio::test]
    async fn test_save_and_find() {
        let repo = BasicMessageRepository::new();
        let record = create_test_record("msg-1", "conn-1");

        repo.save(&record).await.unwrap();
        let found = repo.find_by_id("msg-1").await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "msg-1");
    }

    #[tokio::test]
    async fn test_save_duplicate() {
        let repo = BasicMessageRepository::new();
        let record = create_test_record("msg-1", "conn-1");

        repo.save(&record).await.unwrap();
        let result = repo.save(&record).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(BasicMessageError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_find_by_connection_id() {
        let repo = BasicMessageRepository::new();

        repo.save(&create_test_record("msg-1", "conn-1"))
            .await
            .unwrap();
        repo.save(&create_test_record("msg-2", "conn-1"))
            .await
            .unwrap();
        repo.save(&create_test_record("msg-3", "conn-2"))
            .await
            .unwrap();

        let results = repo.find_by_connection_id("conn-1").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_query_by_role() {
        let repo = BasicMessageRepository::new();

        let mut record1 = create_test_record("msg-1", "conn-1");
        record1.role = BasicMessageRole::Sender;
        repo.save(&record1).await.unwrap();

        let mut record2 = create_test_record("msg-2", "conn-1");
        record2.role = BasicMessageRole::Receiver;
        repo.save(&record2).await.unwrap();

        let query = BasicMessageQuery {
            connection_id: Some("conn-1".to_string()),
            role: Some(BasicMessageRole::Sender),
            ..Default::default()
        };

        let results = repo.find_by_query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "msg-1");
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = BasicMessageRepository::new();
        let record = create_test_record("msg-1", "conn-1");

        repo.save(&record).await.unwrap();
        repo.delete_by_id("msg-1").await.unwrap();

        let found = repo.find_by_id("msg-1").await.unwrap();
        assert!(found.is_none());
    }
}
