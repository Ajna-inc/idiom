//! Storage-backed credential exchange repository
//!
//! Persists credential exchange records using the StorageProvider trait,
//! enabling exchanges to survive across restarts.

use crate::domain::{CredentialExchangeRole, CredentialExchangeState};
use crate::repository::credential_exchange::{
    CredentialExchangeRecord, CredentialExchangeRepositoryTrait,
};
use crate::{CredentialError, Result};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage category for credential exchange records
const CREDENTIAL_EXCHANGE_CATEGORY: &str = "anoncreds_credential_exchange";

/// Storage-backed credential exchange repository that persists to durable storage.
///
/// Follows the write-through cache pattern:
/// - Lazy-loads all records from storage on first access
/// - Writes go to both cache and storage
/// - Reads are cache-only after initial load
pub struct StorageBackedCredentialExchangeRepository {
    storage: Arc<dyn StorageProvider>,
    cache: Arc<RwLock<Option<HashMap<String, CredentialExchangeRecord>>>>,
}

impl StorageBackedCredentialExchangeRepository {
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
            let query = Query::new();
            let records = self
                .storage
                .find_all(CREDENTIAL_EXCHANGE_CATEGORY, &query)
                .await
                .map_err(|e| {
                    CredentialError::Protocol(format!("Failed to load credential exchanges: {}", e))
                })?;

            let mut map = HashMap::new();
            for record in records {
                match serde_json::from_slice::<CredentialExchangeRecord>(&record.value) {
                    Ok(exchange) => {
                        map.insert(exchange.id.clone(), exchange);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Skipping corrupt credential exchange record {}: {}",
                            record.name,
                            e
                        );
                    }
                }
            }

            if !map.is_empty() {
                tracing::info!("Loaded {} credential exchanges from storage", map.len());
            }

            *cache = Some(map);
        }
        Ok(())
    }

    /// Get read access to the cache
    async fn with_cache<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&HashMap<String, CredentialExchangeRecord>) -> T,
    {
        self.ensure_cache().await?;
        let cache = self.cache.read().await;
        Ok(f(cache.as_ref().unwrap()))
    }

    /// Convert a CredentialExchangeRecord to a storage Record
    fn to_storage_record(record: &CredentialExchangeRecord) -> Result<Record> {
        let value = serde_json::to_vec(record)?;

        let mut tags = HashMap::new();
        tags.insert("thread_id".to_string(), record.thread_id.clone());
        tags.insert("state".to_string(), format!("{:?}", record.state));
        tags.insert("role".to_string(), format!("{:?}", record.role));

        if let Some(ref conn_id) = record.connection_id {
            tags.insert("connection_id".to_string(), conn_id.clone());
        }
        if let Some(ref schema_id) = record.schema_id {
            tags.insert("schema_id".to_string(), schema_id.clone());
        }
        if let Some(ref cred_def_id) = record.cred_def_id {
            tags.insert("cred_def_id".to_string(), cred_def_id.clone());
        }

        Ok(Record {
            category: CREDENTIAL_EXCHANGE_CATEGORY.to_string(),
            name: record.id.clone(),
            value,
            tags,
        })
    }
}

#[async_trait]
impl CredentialExchangeRepositoryTrait for StorageBackedCredentialExchangeRepository {
    async fn save(&self, record: &CredentialExchangeRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if already exists
        {
            let cache = self.cache.read().await;
            if cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(CredentialError::AlreadyExists(record.id.clone()));
            }
        }

        // Save to storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage.save(&storage_record).await.map_err(|e| {
            CredentialError::Protocol(format!("Failed to save credential exchange: {}", e))
        })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());

        Ok(())
    }

    async fn update(&self, record: &CredentialExchangeRecord) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(&record.id) {
                return Err(CredentialError::NotFound(record.id.clone()));
            }
        }

        // Update in storage
        let storage_record = Self::to_storage_record(record)?;
        self.storage.update(&storage_record).await.map_err(|e| {
            CredentialError::Protocol(format!("Failed to update credential exchange: {}", e))
        })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(record.id.clone(), record.clone());

        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<CredentialExchangeRecord>> {
        self.with_cache(|cache| cache.get(id).cloned()).await
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<CredentialExchangeRecord>> {
        self.with_cache(|cache| cache.values().find(|r| r.thread_id == thread_id).cloned())
            .await
    }

    async fn find_by_state(
        &self,
        state: CredentialExchangeState,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.state == state)
                .cloned()
                .collect()
        })
        .await
    }

    async fn find_by_role(
        &self,
        role: CredentialExchangeRole,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        self.with_cache(|cache| cache.values().filter(|r| r.role == role).cloned().collect())
            .await
    }

    async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        self.with_cache(|cache| {
            cache
                .values()
                .filter(|r| r.connection_id.as_deref() == Some(connection_id))
                .cloned()
                .collect()
        })
        .await
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.ensure_cache().await?;

        // Check if exists
        {
            let cache = self.cache.read().await;
            if !cache.as_ref().unwrap().contains_key(id) {
                return Err(CredentialError::NotFound(id.to_string()));
            }
        }

        // Delete from storage
        self.storage
            .delete(CREDENTIAL_EXCHANGE_CATEGORY, id)
            .await
            .map_err(|e| {
                CredentialError::Protocol(format!("Failed to delete credential exchange: {}", e))
            })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.as_mut().unwrap().remove(id);

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<CredentialExchangeRecord>> {
        self.with_cache(|cache| cache.values().cloned().collect())
            .await
    }
}
