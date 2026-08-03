//! Storage-backed connection repository
//!
//! Persists connection records using the StorageProvider trait,
//! enabling connections to survive across restarts.

use crate::domain::{DidExchangeRole, DidExchangeState};
use crate::repository::connection_record::{ConnectionRecord, ConnectionTags};
use crate::repository::ConnectionRepositoryTrait;
use crate::{ConnectionError, Result};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage category for connection records
const CONNECTION_CATEGORY: &str = "connection";

/// Storage-backed connection repository that persists to Askar storage.
///
/// This implementation:
/// - Persists all connections to durable storage (SQLite via Askar)
/// - Maintains an in-memory cache for fast lookups
/// - Loads existing connections on startup
/// - Survives across process restarts
pub struct StorageBackedConnectionRepository {
    /// Storage provider for persistence
    storage: Arc<dyn StorageProvider>,
    /// In-memory cache (populated from storage on first access)
    cache: Arc<RwLock<Option<HashMap<String, ConnectionRecord>>>>,
    /// Secondary index: auth_key_base58 → connection_id (O(1) lookup)
    auth_key_index: Arc<RwLock<HashMap<String, String>>>,
    /// Secondary index: ka_key_base58 → connection_id (O(1) lookup)
    ka_key_index: Arc<RwLock<HashMap<String, String>>>,
    /// Secondary index: their_did → connection_id (O(1) lookup for room fan-out)
    their_did_index: Arc<RwLock<HashMap<String, String>>>,
}

impl StorageBackedConnectionRepository {
    /// Create a new storage-backed connection repository
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            cache: Arc::new(RwLock::new(None)),
            auth_key_index: Arc::new(RwLock::new(HashMap::new())),
            ka_key_index: Arc::new(RwLock::new(HashMap::new())),
            their_did_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update the verkey indexes when a record is added/updated
    fn index_record(
        auth_idx: &mut HashMap<String, String>,
        ka_idx: &mut HashMap<String, String>,
        did_idx: &mut HashMap<String, String>,
        record: &ConnectionRecord,
    ) {
        if let Some(ref key) = record.their_authentication_key_base58 {
            auth_idx.insert(key.clone(), record.id.clone());
        }
        if let Some(ref key) = record.their_key_agreement_key_base58 {
            ka_idx.insert(key.clone(), record.id.clone());
        }
        if let Some(ref did) = record.their_did {
            did_idx.insert(did.clone(), record.id.clone());
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
            return Ok(());
        }
        {
            // Load all connections from storage
            let query = Query::new();
            let records = self
                .storage
                .find_all(CONNECTION_CATEGORY, &query)
                .await
                .map_err(|e| {
                    ConnectionError::Storage(format!("Failed to load connections: {}", e))
                })?;

            let mut map = HashMap::new();
            for record in records {
                if let Ok(mut conn) = serde_json::from_slice::<ConnectionRecord>(&record.value) {
                    // CRITICAL: Reconstruct tags from record fields since tags has #[serde(skip)]
                    // Without this, tags.state defaults to Start instead of the actual state!
                    conn.tags = ConnectionTags {
                        role: conn.role,
                        state: conn.state,
                        thread_id: conn.thread_id.clone(),
                        out_of_band_id: conn.out_of_band_id.clone(),
                        did: conn.did.clone(),
                        their_did: conn.their_did.clone(),
                    };

                    let mut migrated = false;

                    // MIGRATION 1: Strip fragment from their_did if present
                    // Old connections may have DIDs with #key-2 fragments that break resolution
                    if let Some(ref mut their_did) = conn.their_did {
                        if their_did.contains('#') {
                            let clean_did =
                                their_did.split('#').next().unwrap_or(their_did).to_string();
                            if clean_did != *their_did {
                                tracing::info!(
                                    "Migrating connection {}: stripping fragment from their_did",
                                    conn.id
                                );
                                *their_did = clean_did.clone();
                                conn.tags.their_did = Some(clean_did);
                                migrated = true;
                            }
                        }
                    }

                    // MIGRATION 2: Ensure validator connections have Completed state
                    // Old connections may have been saved with wrong state
                    if conn.id.starts_with("validator-")
                        && conn.state != DidExchangeState::Completed
                    {
                        tracing::info!(
                            "Migrating connection {}: updating state from {:?} to Completed",
                            conn.id,
                            conn.state
                        );
                        conn.state = DidExchangeState::Completed;
                        conn.tags.state = DidExchangeState::Completed;
                        migrated = true;
                    }

                    if migrated {
                        tracing::debug!(
                            "Connection {} after migration: state={:?}",
                            conn.id,
                            conn.state
                        );
                    }

                    map.insert(conn.id.clone(), conn);
                }
            }

            if !map.is_empty() {
                tracing::info!("Loaded {} connections from storage", map.len());
            }

            // Build secondary indexes for O(1) lookup
            let mut auth_idx = self.auth_key_index.write().await;
            let mut ka_idx = self.ka_key_index.write().await;
            let mut did_idx = self.their_did_index.write().await;
            auth_idx.clear();
            ka_idx.clear();
            did_idx.clear();
            for record in map.values() {
                Self::index_record(&mut auth_idx, &mut ka_idx, &mut did_idx, record);
            }

            *cache = Some(map);
        }
        Ok(())
    }

    /// Get read access to the cache
    async fn with_cache<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&HashMap<String, ConnectionRecord>) -> T,
    {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(f(cache.as_ref().unwrap()))
    }

    /// Convert ConnectionRecord to storage Record
    fn to_storage_record(conn: &ConnectionRecord) -> Result<Record> {
        let value = serde_json::to_vec(conn).map_err(|e| {
            ConnectionError::Storage(format!("Failed to serialize connection: {}", e))
        })?;

        let mut tags = HashMap::new();
        tags.insert("thread_id".to_string(), conn.thread_id.clone());
        tags.insert("state".to_string(), format!("{:?}", conn.state));
        tags.insert("role".to_string(), format!("{:?}", conn.role));
        tags.insert("did".to_string(), conn.did.clone());
        tags.insert("out_of_band_id".to_string(), conn.out_of_band_id.clone());

        if let Some(their_did) = &conn.their_did {
            tags.insert("their_did".to_string(), their_did.clone());
        }
        if let Some(ref auth_key) = conn.their_authentication_key_base58 {
            tags.insert("their_auth_key".to_string(), auth_key.clone());
        }
        if let Some(ref ka_key) = conn.their_key_agreement_key_base58 {
            tags.insert("their_ka_key".to_string(), ka_key.clone());
        }

        Ok(Record {
            category: CONNECTION_CATEGORY.to_string(),
            name: conn.id.clone(),
            value,
            tags,
        })
    }
}

#[async_trait]
impl ConnectionRepositoryTrait for StorageBackedConnectionRepository {
    async fn save(&self, record: &ConnectionRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if already exists
        {
            let cache = self.cache.read().await;
            if cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(ConnectionError::AlreadyExists(record.id.clone()));
            }
        }

        // Save to storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage
            .save(&storage_record)
            .await
            .map_err(|e| ConnectionError::Storage(format!("Failed to save connection: {}", e)))?;

        // Update cache + indexes
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());
        {
            let mut auth_idx = self.auth_key_index.write().await;
            let mut ka_idx = self.ka_key_index.write().await;
            let mut did_idx = self.their_did_index.write().await;
            Self::index_record(&mut auth_idx, &mut ka_idx, &mut did_idx, record);
        }

        Ok(())
    }

    async fn update(&self, record: &ConnectionRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(ConnectionError::NotFound(record.id.clone()));
            }
        }

        // Update in storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage
            .update(&storage_record)
            .await
            .map_err(|e| ConnectionError::Storage(format!("Failed to update connection: {}", e)))?;

        // Update cache + indexes
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());
        {
            let mut auth_idx = self.auth_key_index.write().await;
            let mut ka_idx = self.ka_key_index.write().await;
            let mut did_idx = self.their_did_index.write().await;
            Self::index_record(&mut auth_idx, &mut ka_idx, &mut did_idx, record);
        }

        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<ConnectionRecord>> {
        self.with_cache(|cache| cache.get(id).cloned()).await
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .find(|r| r.tags.thread_id == thread_id)
                .cloned()
        })
        .await
    }

    async fn find_by_role_and_thread_id(
        &self,
        role: DidExchangeRole,
        thread_id: &str,
    ) -> Result<Option<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .find(|r| r.tags.role == role && r.tags.thread_id == thread_id)
                .cloned()
        })
        .await
    }

    async fn find_by_out_of_band_id(&self, oob_id: &str) -> Result<Vec<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.tags.out_of_band_id == oob_id)
                .cloned()
                .collect()
        })
        .await
    }

    async fn find_by_did(&self, did: &str) -> Result<Vec<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.tags.did == did)
                .cloned()
                .collect()
        })
        .await
    }

    async fn find_by_their_did(&self, their_did: &str) -> Result<Vec<ConnectionRecord>> {
        self.ensure_cache().await?;
        // O(1) index lookup instead of O(N) full scan
        let did_idx = self.their_did_index.read().await;
        if let Some(conn_id) = did_idx.get(their_did) {
            let cache = self.cache.read().await;
            if let Some(record) = cache.as_ref().unwrap().get(conn_id) {
                return Ok(vec![record.clone()]);
            }
        }
        Ok(vec![])
    }

    async fn find_by_state(&self, state: DidExchangeState) -> Result<Vec<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.tags.state == state)
                .cloned()
                .collect()
        })
        .await
    }

    async fn find_by_role(&self, role: DidExchangeRole) -> Result<Vec<ConnectionRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.tags.role == role)
                .cloned()
                .collect()
        })
        .await
    }

    async fn find_all_completed(&self) -> Result<Vec<ConnectionRecord>> {
        // Debug: Log what we're looking for
        let result = self.find_by_state(DidExchangeState::Completed).await;
        if let Ok(ref conns) = result {
            tracing::debug!(
                "find_all_completed: found {} connections with Completed state",
                conns.len()
            );
            if conns.is_empty() {
                // Log all connections and their states for debugging
                if let Ok(all) = self.get_all().await {
                    for conn in &all {
                        tracing::debug!(
                            "  Connection {}: state={:?}, their_did={:?}",
                            conn.id,
                            conn.tags.state,
                            conn.their_did.as_ref().map(|d| &d[..50.min(d.len())])
                        );
                    }
                }
            }
        }
        result
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(id) {
                return Err(ConnectionError::NotFound(id.to_string()));
            }
        }

        // Delete from storage
        self.storage
            .delete(CONNECTION_CATEGORY, id)
            .await
            .map_err(|e| ConnectionError::Storage(format!("Failed to delete connection: {}", e)))?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.as_mut().unwrap().remove(id);

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<ConnectionRecord>> {
        self.with_cache(|cache| cache.values().cloned().collect())
            .await
    }

    /// O(1) indexed lookup by their authentication key (base58 verkey).
    async fn find_by_auth_key(&self, key: &str) -> Result<Option<ConnectionRecord>> {
        self.ensure_cache().await?;
        // O(1) index lookup
        let conn_id = self.auth_key_index.read().await.get(key).cloned();
        if let Some(ref id) = conn_id {
            let cache = self.cache.read().await;
            return Ok(cache.as_ref().and_then(|c| c.get(id).cloned()));
        }
        // Index miss: tag-based storage query (handles keys added by another instance)
        use agent_core::traits::Query;
        let query = Query::new().with_tag("their_auth_key", key);
        let records = self
            .storage
            .find_all(CONNECTION_CATEGORY, &query)
            .await
            .map_err(|e| ConnectionError::Storage(format!("Failed to query by auth key: {}", e)))?;
        if let Some(record) = records.first() {
            let conn: ConnectionRecord = serde_json::from_slice(&record.value)
                .map_err(|e| ConnectionError::Storage(format!("Failed to deserialize: {}", e)))?;
            // Update indexes
            let mut auth_idx = self.auth_key_index.write().await;
            let mut ka_idx = self.ka_key_index.write().await;
            let mut did_idx = self.their_did_index.write().await;
            Self::index_record(&mut auth_idx, &mut ka_idx, &mut did_idx, &conn);
            return Ok(Some(conn));
        }
        Ok(None)
    }

    /// O(1) indexed lookup by their key agreement key (base58).
    async fn find_by_ka_key(&self, key: &str) -> Result<Option<ConnectionRecord>> {
        self.ensure_cache().await?;
        let conn_id = self.ka_key_index.read().await.get(key).cloned();
        if let Some(ref id) = conn_id {
            let cache = self.cache.read().await;
            return Ok(cache.as_ref().and_then(|c| c.get(id).cloned()));
        }
        use agent_core::traits::Query;
        let query = Query::new().with_tag("their_ka_key", key);
        let records = self
            .storage
            .find_all(CONNECTION_CATEGORY, &query)
            .await
            .map_err(|e| ConnectionError::Storage(format!("Failed to query by KA key: {}", e)))?;
        if let Some(record) = records.first() {
            let conn: ConnectionRecord = serde_json::from_slice(&record.value)
                .map_err(|e| ConnectionError::Storage(format!("Failed to deserialize: {}", e)))?;
            let mut auth_idx = self.auth_key_index.write().await;
            let mut ka_idx = self.ka_key_index.write().await;
            let mut did_idx = self.their_did_index.write().await;
            Self::index_record(&mut auth_idx, &mut ka_idx, &mut did_idx, &conn);
            return Ok(Some(conn));
        }
        Ok(None)
    }
}
