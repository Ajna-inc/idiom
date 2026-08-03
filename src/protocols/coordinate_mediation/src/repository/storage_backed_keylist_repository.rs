//! Storage-backed keylist repository
//!
//! Persists keylist records using the StorageProvider trait,
//! enabling keylist entries to survive across restarts.

use crate::repository::keylist_record::KeylistRecord;
use crate::repository::KeylistRepositoryTrait;
use crate::{MediationError, Result};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage category for keylist records
const KEYLIST_CATEGORY: &str = "keylist";

/// Storage-backed keylist repository that persists to Askar storage.
///
/// This implementation:
/// - Persists all keylist records to durable storage (SQLite via Askar)
/// - Maintains an in-memory cache for fast lookups
/// - Loads existing records on startup
/// - Survives across process restarts
pub struct StorageBackedKeylistRepository {
    /// Storage provider for persistence
    storage: Arc<dyn StorageProvider>,
    /// In-memory cache (populated from storage on first access)
    cache: Arc<RwLock<Option<HashMap<String, KeylistRecord>>>>,
    /// Secondary index: recipient_key → record_id (O(1) lookup)
    by_recipient_key: Arc<RwLock<HashMap<String, String>>>,
}

impl StorageBackedKeylistRepository {
    /// Create a new storage-backed keylist repository
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            cache: Arc::new(RwLock::new(None)),
            by_recipient_key: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Ensure cache is populated from storage
    async fn ensure_cache(&self) -> Result<()> {
        // Fast path: read lock (non-blocking for concurrent operations)
        {
            let cache = self.cache.read().await;
            if cache.is_some() {
                return Ok(());
            }
        }
        // Slow path: write lock only when uninitialized
        let mut cache = self.cache.write().await;
        if cache.is_some() {
            return Ok(()); // Another task loaded while we waited
        }
        {
            let query = Query::new();
            let records = self
                .storage
                .find_all(KEYLIST_CATEGORY, &query)
                .await
                .map_err(|e| {
                    MediationError::Storage(format!("Failed to load keylist records: {}", e))
                })?;

            let mut map = HashMap::new();
            for record in records {
                if let Ok(kl_record) = serde_json::from_slice::<KeylistRecord>(&record.value) {
                    map.insert(kl_record.id.clone(), kl_record);
                }
            }

            tracing::info!(
                "[KeylistRepo] Loaded {} keylist records from storage",
                map.len()
            );

            // Build secondary index: recipient_key → record_id
            let mut rk_idx = self.by_recipient_key.write().await;
            rk_idx.clear();
            for (id, record) in &map {
                rk_idx.insert(record.recipient_key.clone(), id.clone());
            }

            *cache = Some(map);
        }
        Ok(())
    }

    /// Persist a record to storage
    async fn persist(&self, record: &KeylistRecord) -> Result<()> {
        let value = serde_json::to_vec(record).map_err(|e| {
            MediationError::Storage(format!("Failed to serialize keylist record: {}", e))
        })?;

        let mut tags = HashMap::new();
        tags.insert("mediation_id".to_string(), record.mediation_id.clone());
        tags.insert("recipient_key".to_string(), record.recipient_key.clone());

        let storage_record = Record::new(KEYLIST_CATEGORY, &record.id, value).with_tags(tags);

        self.storage.save(&storage_record).await.map_err(|e| {
            MediationError::Storage(format!("Failed to store keylist record: {}", e))
        })?;

        Ok(())
    }

    /// Delete a record from storage
    async fn delete_from_storage(&self, id: &str) -> Result<()> {
        self.storage
            .delete(KEYLIST_CATEGORY, id)
            .await
            .map_err(|e| {
                MediationError::Storage(format!("Failed to delete keylist record: {}", e))
            })?;
        Ok(())
    }
}

#[async_trait]
impl KeylistRepositoryTrait for StorageBackedKeylistRepository {
    async fn save(&self, record: &KeylistRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Persist to storage first
        self.persist(record).await?;

        // Update cache + recipient_key index
        let mut cache = self.cache.write().await;
        let map = cache.as_mut().unwrap();
        map.insert(record.id.clone(), record.clone());
        self.by_recipient_key
            .write()
            .await
            .insert(record.recipient_key.clone(), record.id.clone());
        Ok(())
    }

    async fn find_by_mediation_id(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .unwrap()
            .values()
            .filter(|r| r.mediation_id == mediation_id)
            .cloned()
            .collect())
    }

    async fn find_by_recipient_key(
        &self,
        mediation_id: &str,
        recipient_key: &str,
    ) -> Result<Option<KeylistRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .unwrap()
            .values()
            .find(|r| r.mediation_id == mediation_id && r.recipient_key == recipient_key)
            .cloned())
    }

    async fn delete_by_recipient_key(&self, mediation_id: &str, recipient_key: &str) -> Result<()> {
        self.ensure_cache().await?;

        // Find the record ID to delete
        let id_to_delete = {
            let cache = self.cache.read().await;
            cache
                .as_ref()
                .unwrap()
                .values()
                .find(|r| r.mediation_id == mediation_id && r.recipient_key == recipient_key)
                .map(|r| r.id.clone())
        };

        if let Some(id) = id_to_delete {
            // Delete from storage first
            self.delete_from_storage(&id).await?;

            // Then update cache
            let mut cache = self.cache.write().await;
            let map = cache.as_mut().unwrap();
            map.remove(&id);
        }

        Ok(())
    }

    async fn delete_by_mediation_id(&self, mediation_id: &str) -> Result<()> {
        self.ensure_cache().await?;

        // Find all record IDs to delete
        let ids_to_delete: Vec<String> = {
            let cache = self.cache.read().await;
            cache
                .as_ref()
                .unwrap()
                .values()
                .filter(|r| r.mediation_id == mediation_id)
                .map(|r| r.id.clone())
                .collect()
        };

        // Delete from storage first
        for id in &ids_to_delete {
            self.delete_from_storage(id).await?;
        }

        // Then update cache
        let mut cache = self.cache.write().await;
        let map = cache.as_mut().unwrap();
        for id in &ids_to_delete {
            map.remove(id);
        }

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<KeylistRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache.as_ref().unwrap().values().cloned().collect())
    }

    async fn find_mediation_for_recipient_key(
        &self,
        recipient_key: &str,
    ) -> Result<Option<KeylistRecord>> {
        // O(1) indexed lookup via secondary index
        self.ensure_cache().await?;
        {
            let record_id = self
                .by_recipient_key
                .read()
                .await
                .get(recipient_key)
                .cloned();
            if let Some(ref id) = record_id {
                let cache = self.cache.read().await;
                if let Some(record) = cache.as_ref().and_then(|c| c.get(id).cloned()) {
                    return Ok(Some(record));
                }
            }
        }

        // Cache miss: tag-based storage query (catches keys registered
        // after the cache was populated, e.g., by another mediator instance).
        let query = Query::new().with_tag("recipient_key", recipient_key);
        let records = self
            .storage
            .find_all(KEYLIST_CATEGORY, &query)
            .await
            .map_err(|e| {
                MediationError::Storage(format!("Failed to query keylist by recipient key: {}", e))
            })?;

        if let Some(record) = records.into_iter().next() {
            let kl_record = serde_json::from_slice::<KeylistRecord>(&record.value)
                .map_err(|e| MediationError::Storage(format!("Failed to deserialize: {}", e)))?;
            // Update cache with new entry
            let mut cache = self.cache.write().await;
            if let Some(ref mut cache_map) = *cache {
                cache_map.insert(kl_record.id.clone(), kl_record.clone());
            }
            Ok(Some(kl_record))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    // Storage-backed tests require a real StorageProvider (Askar).
    // Unit tests for the keylist trait are in keylist_repository.rs.
    // Integration tests should be added with a test storage backend.
}
