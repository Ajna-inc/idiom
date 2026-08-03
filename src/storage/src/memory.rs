//! Pure Rust in-memory storage provider for WASM compatibility
//!
//! This crate provides a WASM-compatible storage implementation that keeps
//! all data in memory. It's suitable for:
//! - Browser environments (data persists only during session)
//! - Testing and development
//! - As a base for host-injected storage adapters
//!
//! For persistent storage in WASM, use the `JsStorageAdapter` which wraps
//! host-provided storage (IndexedDB, AsyncStorage, etc.).

use agent_core::traits::{Query, Record, StorageProvider};
use agent_core::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors specific to memory storage
#[derive(Debug, Error)]
pub enum MemoryStorageError {
    #[error("Record not found: {category}/{name}")]
    NotFound { category: String, name: String },

    #[error("Record already exists: {category}/{name}")]
    AlreadyExists { category: String, name: String },
}

/// In-memory storage provider
///
/// Thread-safe storage that keeps all records in memory using a nested HashMap.
/// Categories form the outer map, and record names form the inner map.
///
/// # Example
///
/// ```rust,no_run
/// use storage::memory::MemoryStorage;
/// use agent_core::traits::{StorageProvider, Record};
///
/// # async fn example() -> agent_core::Result<()> {
/// let storage = MemoryStorage::new();
///
/// // Save a record
/// let record = Record::new("connections", "conn-1", b"data".to_vec());
/// storage.save(&record).await?;
///
/// // Retrieve it
/// let found = storage.find("connections", "conn-1").await?;
/// assert!(found.is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    /// Nested map: category -> (name -> record)
    data: Arc<RwLock<HashMap<String, HashMap<String, Record>>>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// Create a new empty in-memory storage
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create from existing data (useful for testing or migration)
    pub fn from_data(data: HashMap<String, HashMap<String, Record>>) -> Self {
        Self {
            data: Arc::new(RwLock::new(data)),
        }
    }

    /// Get a snapshot of all data (useful for serialization/backup)
    pub async fn snapshot(&self) -> HashMap<String, HashMap<String, Record>> {
        self.data.read().await.clone()
    }

    /// Clear all data
    pub async fn clear(&self) {
        self.data.write().await.clear();
    }

    /// Get total record count across all categories
    pub async fn total_count(&self) -> usize {
        let data = self.data.read().await;
        data.values().map(|cat| cat.len()).sum()
    }

    /// Get all category names
    pub async fn categories(&self) -> Vec<String> {
        self.data.read().await.keys().cloned().collect()
    }
}

// Native: use Send-requiring async_trait
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: use non-Send async_trait
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl StorageProvider for MemoryStorage {
    async fn save(&self, record: &Record) -> Result<()> {
        let mut data = self.data.write().await;

        let category_map = data.entry(record.category.clone()).or_default();

        // Check if record already exists
        if category_map.contains_key(&record.name) {
            return Err(agent_core::AgentError::Storage(format!(
                "Record already exists: {}/{}",
                record.category, record.name
            )));
        }

        category_map.insert(record.name.clone(), record.clone());
        Ok(())
    }

    async fn find(&self, category: &str, name: &str) -> Result<Option<Record>> {
        let data = self.data.read().await;

        Ok(data.get(category).and_then(|cat| cat.get(name)).cloned())
    }

    async fn find_all(&self, category: &str, query: &Query) -> Result<Vec<Record>> {
        let data = self.data.read().await;

        let Some(category_map) = data.get(category) else {
            return Ok(Vec::new());
        };

        let mut results: Vec<Record> = category_map
            .values()
            .filter(|record| {
                // Check if all query tags match
                query
                    .tags
                    .iter()
                    .all(|(key, value)| record.tags.get(key).map(|v| v == value).unwrap_or(false))
            })
            .cloned()
            .collect();

        // Apply skip
        if let Some(skip) = query.skip {
            if skip < results.len() {
                results = results.into_iter().skip(skip).collect();
            } else {
                return Ok(Vec::new());
            }
        }

        // Apply limit
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn update(&self, record: &Record) -> Result<()> {
        let mut data = self.data.write().await;

        // Match the askar/kanon backends: `update` only replaces an existing
        // record; a missing one is an error. Callers that want upsert use the
        // `update`→`save` fallback (see the workspaces repos / oid4vci issuer),
        // which relies on this error to trigger the insert.
        match data
            .get_mut(&record.category)
            .and_then(|cat| cat.get_mut(&record.name))
        {
            Some(existing) => {
                *existing = record.clone();
                Ok(())
            }
            None => Err(agent_core::AgentError::Storage(format!(
                "Record not found: {}/{}",
                record.category, record.name
            ))),
        }
    }

    async fn delete(&self, category: &str, name: &str) -> Result<()> {
        let mut data = self.data.write().await;

        if let Some(category_map) = data.get_mut(category) {
            category_map.remove(name);
        }

        Ok(())
    }

    async fn delete_all(&self, category: &str) -> Result<()> {
        let mut data = self.data.write().await;
        data.remove(category);
        Ok(())
    }

    async fn count(&self, category: &str, query: &Query) -> Result<usize> {
        let data = self.data.read().await;

        let Some(category_map) = data.get(category) else {
            return Ok(0);
        };

        // If no tag filters, just count all records in category
        if query.tags.is_empty() {
            return Ok(category_map.len());
        }

        // Otherwise filter and count
        let count = category_map
            .values()
            .filter(|record| {
                query
                    .tags
                    .iter()
                    .all(|(key, value)| record.tags.get(key).map(|v| v == value).unwrap_or(false))
            })
            .count();

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_save_and_find() {
        let storage = MemoryStorage::new();

        let record =
            Record::new("connections", "conn-1", b"test data".to_vec()).add_tag("state", "active");

        storage.save(&record).await.unwrap();

        let found = storage.find("connections", "conn-1").await.unwrap();
        assert!(found.is_some());

        let found = found.unwrap();
        assert_eq!(found.name, "conn-1");
        assert_eq!(found.value, b"test data");
        assert_eq!(found.tags.get("state"), Some(&"active".to_string()));
    }

    #[tokio::test]
    async fn test_save_duplicate_fails() {
        let storage = MemoryStorage::new();

        let record = Record::new("connections", "conn-1", b"data".to_vec());
        storage.save(&record).await.unwrap();

        // Saving again should fail
        let result = storage.save(&record).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_find_not_found() {
        let storage = MemoryStorage::new();

        let found = storage.find("connections", "nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_all_with_tags() {
        let storage = MemoryStorage::new();

        // Add records with different states
        storage
            .save(&Record::new("connections", "conn-1", vec![]).add_tag("state", "active"))
            .await
            .unwrap();
        storage
            .save(&Record::new("connections", "conn-2", vec![]).add_tag("state", "active"))
            .await
            .unwrap();
        storage
            .save(&Record::new("connections", "conn-3", vec![]).add_tag("state", "pending"))
            .await
            .unwrap();

        // Query active connections
        let query = Query::new().with_tag("state", "active");
        let results = storage.find_all("connections", &query).await.unwrap();

        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_find_all_with_limit_and_skip() {
        let storage = MemoryStorage::new();

        for i in 0..10 {
            storage
                .save(&Record::new("items", format!("item-{}", i), vec![]))
                .await
                .unwrap();
        }

        let query = Query::new().with_skip(3).with_limit(4);
        let results = storage.find_all("items", &query).await.unwrap();

        assert_eq!(results.len(), 4);
    }

    #[tokio::test]
    async fn test_update() {
        let storage = MemoryStorage::new();

        let record = Record::new("connections", "conn-1", b"original".to_vec());
        storage.save(&record).await.unwrap();

        let updated = Record::new("connections", "conn-1", b"updated".to_vec());
        storage.update(&updated).await.unwrap();

        let found = storage
            .find("connections", "conn-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.value, b"updated");
    }

    #[tokio::test]
    async fn test_update_missing_errors() {
        // Normalized to match askar/kanon: updating a record that was never
        // saved is an error, not a silent upsert.
        let storage = MemoryStorage::new();
        let ghost = Record::new("connections", "ghost", b"x".to_vec());
        assert!(storage.update(&ghost).await.is_err());
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = MemoryStorage::new();

        let record = Record::new("connections", "conn-1", vec![]);
        storage.save(&record).await.unwrap();

        storage.delete("connections", "conn-1").await.unwrap();

        let found = storage.find("connections", "conn-1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_all() {
        let storage = MemoryStorage::new();

        storage
            .save(&Record::new("connections", "conn-1", vec![]))
            .await
            .unwrap();
        storage
            .save(&Record::new("connections", "conn-2", vec![]))
            .await
            .unwrap();

        storage.delete_all("connections").await.unwrap();

        let query = Query::new();
        let results = storage.find_all("connections", &query).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_count() {
        let storage = MemoryStorage::new();

        storage
            .save(&Record::new("items", "item-1", vec![]).add_tag("type", "a"))
            .await
            .unwrap();
        storage
            .save(&Record::new("items", "item-2", vec![]).add_tag("type", "a"))
            .await
            .unwrap();
        storage
            .save(&Record::new("items", "item-3", vec![]).add_tag("type", "b"))
            .await
            .unwrap();

        // Count all
        let count = storage.count("items", &Query::new()).await.unwrap();
        assert_eq!(count, 3);

        // Count with filter
        let count = storage
            .count("items", &Query::new().with_tag("type", "a"))
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_snapshot_and_restore() {
        let storage = MemoryStorage::new();

        storage
            .save(&Record::new("test", "record-1", b"data".to_vec()))
            .await
            .unwrap();

        let snapshot = storage.snapshot().await;

        // Create new storage from snapshot
        let restored = MemoryStorage::from_data(snapshot);

        let found = restored.find("test", "record-1").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_clear() {
        let storage = MemoryStorage::new();

        storage
            .save(&Record::new("cat1", "rec1", vec![]))
            .await
            .unwrap();
        storage
            .save(&Record::new("cat2", "rec2", vec![]))
            .await
            .unwrap();

        storage.clear().await;

        assert_eq!(storage.total_count().await, 0);
    }

    #[tokio::test]
    async fn test_categories() {
        let storage = MemoryStorage::new();

        storage
            .save(&Record::new("connections", "c1", vec![]))
            .await
            .unwrap();
        storage
            .save(&Record::new("credentials", "cr1", vec![]))
            .await
            .unwrap();
        storage
            .save(&Record::new("dids", "d1", vec![]))
            .await
            .unwrap();

        let categories = storage.categories().await;
        assert_eq!(categories.len(), 3);
        assert!(categories.contains(&"connections".to_string()));
        assert!(categories.contains(&"credentials".to_string()));
        assert!(categories.contains(&"dids".to_string()));
    }
}
