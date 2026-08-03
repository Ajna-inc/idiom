//! Storage-backed mediation repository
//!
//! Persists mediation records using the StorageProvider trait,
//! enabling mediation grants to survive across restarts.

use crate::repository::mediation_record::MediationRecord;
use crate::repository::MediationRepositoryTrait;
use crate::{MediationError, MediationRole, MediationState, Result};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage category for mediation records
const MEDIATION_CATEGORY: &str = "mediation";

/// Storage-backed mediation repository that persists to Askar storage.
///
/// This implementation:
/// - Persists all mediation records to durable storage (SQLite via Askar)
/// - Maintains an in-memory cache for fast lookups
/// - Loads existing records on startup
/// - Survives across process restarts
pub struct StorageBackedMediationRepository {
    /// Storage provider for persistence
    storage: Arc<dyn StorageProvider>,
    /// In-memory cache (populated from storage on first access)
    cache: Arc<RwLock<Option<HashMap<String, MediationRecord>>>>,
}

impl StorageBackedMediationRepository {
    /// Create a new storage-backed mediation repository
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
            // Load all mediation records from storage
            let query = Query::new();
            let records = self
                .storage
                .find_all(MEDIATION_CATEGORY, &query)
                .await
                .map_err(|e| {
                    MediationError::Storage(format!("Failed to load mediation records: {}", e))
                })?;

            let mut map = HashMap::new();
            for record in records {
                if let Ok(med_record) = serde_json::from_slice::<MediationRecord>(&record.value) {
                    map.insert(med_record.id.clone(), med_record);
                }
            }

            tracing::debug!("Loaded {} mediation records from storage", map.len());
            *cache = Some(map);
        }
        Ok(())
    }

    /// Persist a record to storage
    async fn persist(&self, record: &MediationRecord) -> Result<()> {
        let value = serde_json::to_vec(record).map_err(|e| {
            MediationError::Storage(format!("Failed to serialize mediation record: {}", e))
        })?;

        // Build tags for querying
        let mut tags = HashMap::new();
        tags.insert("connection_id".to_string(), record.connection_id.clone());
        tags.insert("state".to_string(), record.state.to_string());
        tags.insert("role".to_string(), record.role.to_string());

        let storage_record = Record::new(MEDIATION_CATEGORY, &record.id, value).with_tags(tags);

        self.storage.save(&storage_record).await.map_err(|e| {
            MediationError::Storage(format!("Failed to store mediation record: {}", e))
        })?;

        Ok(())
    }

    /// Update a record in storage
    async fn update_in_storage(&self, record: &MediationRecord) -> Result<()> {
        let value = serde_json::to_vec(record).map_err(|e| {
            MediationError::Storage(format!("Failed to serialize mediation record: {}", e))
        })?;

        // Build tags for querying
        let mut tags = HashMap::new();
        tags.insert("connection_id".to_string(), record.connection_id.clone());
        tags.insert("state".to_string(), record.state.to_string());
        tags.insert("role".to_string(), record.role.to_string());

        let storage_record = Record::new(MEDIATION_CATEGORY, &record.id, value).with_tags(tags);

        self.storage.update(&storage_record).await.map_err(|e| {
            MediationError::Storage(format!("Failed to update mediation record: {}", e))
        })?;

        Ok(())
    }

    /// Delete a record from storage
    async fn delete_from_storage(&self, id: &str) -> Result<()> {
        self.storage
            .delete(MEDIATION_CATEGORY, id)
            .await
            .map_err(|e| {
                MediationError::Storage(format!("Failed to delete mediation record: {}", e))
            })?;
        Ok(())
    }
}

#[async_trait]
impl MediationRepositoryTrait for StorageBackedMediationRepository {
    async fn save(&self, record: &MediationRecord) -> Result<()> {
        self.ensure_cache().await?;

        let mut cache = self.cache.write().await;
        let map = cache.as_mut().unwrap();

        if map.contains_key(&record.id) {
            return Err(MediationError::AlreadyExists(record.id.clone()));
        }

        // Persist to storage first
        self.persist(record).await?;

        // Then update cache
        map.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &MediationRecord) -> Result<()> {
        self.ensure_cache().await?;

        let mut cache = self.cache.write().await;
        let map = cache.as_mut().unwrap();

        if !map.contains_key(&record.id) {
            return Err(MediationError::NotFound(record.id.clone()));
        }

        // Update in storage first
        self.update_in_storage(record).await?;

        // Then update cache
        map.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<MediationRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache.as_ref().unwrap().get(id).cloned())
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Option<MediationRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .unwrap()
            .values()
            .find(|r| r.connection_id == connection_id)
            .cloned())
    }

    async fn find_by_state(&self, state: MediationState) -> Result<Vec<MediationRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .unwrap()
            .values()
            .filter(|r| r.state == state)
            .cloned()
            .collect())
    }

    async fn find_by_role(&self, role: MediationRole) -> Result<Vec<MediationRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .unwrap()
            .values()
            .filter(|r| r.role == role)
            .cloned()
            .collect())
    }

    async fn find_all_granted(&self) -> Result<Vec<MediationRecord>> {
        self.find_by_state(MediationState::Granted).await
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.ensure_cache().await?;

        let mut cache = self.cache.write().await;
        let map = cache.as_mut().unwrap();

        if !map.contains_key(id) {
            return Err(MediationError::NotFound(id.to_string()));
        }

        // Delete from storage first
        self.delete_from_storage(id).await?;

        // Then remove from cache
        map.remove(id);
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<MediationRecord>> {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache.as_ref().unwrap().values().cloned().collect())
    }
}
