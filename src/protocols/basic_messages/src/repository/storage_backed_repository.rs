//! Storage-backed basic message repository
//!
//! Persists basic message records using the StorageProvider trait,
//! enabling messages to survive across restarts.

use crate::repository::basic_message_record::{
    BasicMessageRecord, BasicMessageRole, BasicMessageTags,
};
use crate::repository::{
    BasicMessageError, BasicMessageQuery, BasicMessageRepositoryTrait, Result,
};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage category for basic message records
const BASIC_MESSAGE_CATEGORY: &str = "basic_message";

/// Storage-backed basic message repository that persists to Askar storage.
///
/// This implementation:
/// - Persists all messages to durable storage (SQLite via Askar)
/// - Maintains an in-memory cache for fast lookups
/// - Loads existing messages on startup
/// - Survives across process restarts
pub struct StorageBackedBasicMessageRepository {
    /// Storage provider for persistence
    storage: Arc<dyn StorageProvider>,
    /// In-memory cache (populated from storage on first access)
    cache: Arc<RwLock<Option<HashMap<String, BasicMessageRecord>>>>,
}

impl StorageBackedBasicMessageRepository {
    /// Create a new storage-backed basic message repository
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Ensure cache is populated from storage
    async fn ensure_cache(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        if cache.is_none() {
            // Load all messages from storage
            let query = Query::new();
            let records = self
                .storage
                .find_all(BASIC_MESSAGE_CATEGORY, &query)
                .await
                .map_err(|e| {
                    BasicMessageError::Storage(format!("Failed to load messages: {}", e))
                })?;

            let mut map = HashMap::new();
            for record in records {
                if let Ok(mut msg) = serde_json::from_slice::<BasicMessageRecord>(&record.value) {
                    // Reconstruct tags from record fields
                    let role_str = match msg.role {
                        BasicMessageRole::Sender => "sender".to_string(),
                        BasicMessageRole::Receiver => "receiver".to_string(),
                    };
                    msg.tags = BasicMessageTags {
                        connection_id: Some(msg.connection_id.clone()),
                        role: Some(role_str),
                        thread_id: msg.thread_id.clone(),
                        parent_thread_id: msg.parent_thread_id.clone(),
                    };

                    map.insert(msg.id.clone(), msg);
                }
            }

            if !map.is_empty() {
                tracing::info!("Loaded {} basic messages from storage", map.len());
            }

            *cache = Some(map);
        }
        Ok(())
    }

    /// Get read access to the cache
    async fn with_cache<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&HashMap<String, BasicMessageRecord>) -> T,
    {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(f(cache.as_ref().unwrap()))
    }

    /// Convert BasicMessageRecord to storage Record
    fn to_storage_record(msg: &BasicMessageRecord) -> Result<Record> {
        let value = serde_json::to_vec(msg).map_err(|e| {
            BasicMessageError::Storage(format!("Failed to serialize message: {}", e))
        })?;

        let mut tags = HashMap::new();
        tags.insert("connection_id".to_string(), msg.connection_id.clone());
        tags.insert("sent_time".to_string(), msg.sent_time.clone());

        let role_str = match msg.role {
            BasicMessageRole::Sender => "sender",
            BasicMessageRole::Receiver => "receiver",
        };
        tags.insert("role".to_string(), role_str.to_string());

        if let Some(thread_id) = &msg.thread_id {
            tags.insert("thread_id".to_string(), thread_id.clone());
        }

        if let Some(parent_thread_id) = &msg.parent_thread_id {
            tags.insert("parent_thread_id".to_string(), parent_thread_id.clone());
        }

        Ok(Record {
            category: BASIC_MESSAGE_CATEGORY.to_string(),
            name: msg.id.clone(),
            value,
            tags,
        })
    }
}

#[async_trait]
impl BasicMessageRepositoryTrait for StorageBackedBasicMessageRepository {
    async fn save(&self, record: &BasicMessageRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if already exists
        {
            let cache = self.cache.read().await;
            if cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(BasicMessageError::AlreadyExists(record.id.clone()));
            }
        }

        // Save to storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage
            .save(&storage_record)
            .await
            .map_err(|e| BasicMessageError::Storage(format!("Failed to save message: {}", e)))?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());

        tracing::debug!(
            "Saved basic message {} for connection {}",
            record.id,
            record.connection_id
        );

        Ok(())
    }

    async fn update(&self, record: &BasicMessageRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(BasicMessageError::NotFound(record.id.clone()));
            }
        }

        // Update in storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage
            .update(&storage_record)
            .await
            .map_err(|e| BasicMessageError::Storage(format!("Failed to update message: {}", e)))?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());

        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<BasicMessageRecord>> {
        self.with_cache(|cache| cache.get(id).cloned()).await
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Vec<BasicMessageRecord>> {
        self.with_cache(|cache| {
            let mut results: Vec<_> = cache
                .values()
                .filter(|r| r.connection_id == connection_id)
                .cloned()
                .collect();

            // Sort by sent_time for chronological order
            results.sort_by(|a, b| a.sent_time.cmp(&b.sent_time));
            results
        })
        .await
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<BasicMessageRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .find(|r| r.thread_id.as_deref() == Some(thread_id))
                .cloned()
        })
        .await
    }

    async fn find_by_query(&self, query: BasicMessageQuery) -> Result<Vec<BasicMessageRecord>> {
        self.with_cache(|cache| {
            let mut results: Vec<BasicMessageRecord> = cache.values().cloned().collect();

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

            // Sort by sent_time
            results.sort_by(|a, b| a.sent_time.cmp(&b.sent_time));
            results
        })
        .await
    }

    async fn delete_by_id(&self, id: &str) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(id) {
                return Err(BasicMessageError::NotFound(id.to_string()));
            }
        }

        // Delete from storage
        self.storage
            .delete(BASIC_MESSAGE_CATEGORY, id)
            .await
            .map_err(|e| BasicMessageError::Storage(format!("Failed to delete message: {}", e)))?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.as_mut().unwrap().remove(id);

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<BasicMessageRecord>> {
        self.with_cache(|cache| {
            let mut results: Vec<_> = cache.values().cloned().collect();
            results.sort_by(|a, b| a.sent_time.cmp(&b.sent_time));
            results
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::traits::Query;
    use std::sync::Mutex;

    /// Mock storage provider for testing
    struct MockStorageProvider {
        records: Mutex<HashMap<String, Record>>,
    }

    impl MockStorageProvider {
        fn new() -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageProvider for MockStorageProvider {
        async fn save(&self, record: &Record) -> agent_core::Result<()> {
            let mut records = self.records.lock().unwrap();
            let key = format!("{}:{}", record.category, record.name);
            records.insert(key, record.clone());
            Ok(())
        }

        async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
            let records = self.records.lock().unwrap();
            let key = format!("{}:{}", category, name);
            Ok(records.get(&key).cloned())
        }

        async fn find_all(
            &self,
            category: &str,
            _query: &Query,
        ) -> agent_core::Result<Vec<Record>> {
            let records = self.records.lock().unwrap();
            let prefix = format!("{}:", category);
            Ok(records
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        }

        async fn update(&self, record: &Record) -> agent_core::Result<()> {
            self.save(record).await
        }

        async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
            let mut records = self.records.lock().unwrap();
            let key = format!("{}:{}", category, name);
            records.remove(&key);
            Ok(())
        }

        async fn delete_all(&self, category: &str) -> agent_core::Result<()> {
            let mut records = self.records.lock().unwrap();
            let prefix = format!("{}:", category);
            records.retain(|k, _| !k.starts_with(&prefix));
            Ok(())
        }
    }

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
        let storage = Arc::new(MockStorageProvider::new());
        let repo = StorageBackedBasicMessageRepository::new(storage);
        let record = create_test_record("msg-1", "conn-1");

        repo.save(&record).await.unwrap();
        let found = repo.find_by_id("msg-1").await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "msg-1");
    }

    #[tokio::test]
    async fn test_persistence() {
        let storage = Arc::new(MockStorageProvider::new());

        // First repo instance saves data
        {
            let repo = StorageBackedBasicMessageRepository::new(storage.clone());
            repo.save(&create_test_record("msg-1", "conn-1"))
                .await
                .unwrap();
        }

        // Second repo instance (simulating restart) should find data
        {
            let repo = StorageBackedBasicMessageRepository::new(storage.clone());
            let found = repo.find_by_id("msg-1").await.unwrap();
            assert!(found.is_some());
            assert_eq!(found.unwrap().id, "msg-1");
        }
    }

    #[tokio::test]
    async fn test_find_by_connection_id() {
        let storage = Arc::new(MockStorageProvider::new());
        let repo = StorageBackedBasicMessageRepository::new(storage);

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
    async fn test_delete() {
        let storage = Arc::new(MockStorageProvider::new());
        let repo = StorageBackedBasicMessageRepository::new(storage);
        let record = create_test_record("msg-1", "conn-1");

        repo.save(&record).await.unwrap();
        repo.delete_by_id("msg-1").await.unwrap();

        let found = repo.find_by_id("msg-1").await.unwrap();
        assert!(found.is_none());
    }
}
