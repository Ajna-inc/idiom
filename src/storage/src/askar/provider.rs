//! Askar storage provider implementation

use crate::askar::config::AskarConfig;
use crate::askar::error::Result;
use crate::askar::query_converter::convert_query;
use agent_core::traits::{Query, Record, StorageProvider};
use aries_askar::entry::EntryTag;
use aries_askar::{PassKey, Store};
use async_trait::async_trait;
use std::sync::Arc;

/// Storage provider using Aries Askar
pub struct AskarStorageProvider {
    store: Arc<Store>,
}

impl AskarStorageProvider {
    /// Create a new Askar storage provider
    pub async fn new(config: AskarConfig) -> Result<Self> {
        let pass_key = PassKey::from(config.pass_key.as_str());

        let store = if config.create_if_missing {
            // Try to open first, provision if it doesn't exist
            match Store::open(
                &config.database_url,
                Some(config.key_method.into()),
                pass_key.clone(),
                config.profile.clone(),
            )
            .await
            {
                Ok(store) => store,
                Err(_) => {
                    // Store doesn't exist, provision it
                    Store::provision(
                        &config.database_url,
                        config.key_method.into(),
                        pass_key,
                        config.profile.clone(),
                        false, // recreate
                    )
                    .await?
                }
            }
        } else {
            Store::open(
                &config.database_url,
                Some(config.key_method.into()),
                pass_key,
                config.profile.clone(),
            )
            .await?
        };

        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Get the underlying Askar store (for advanced use cases)
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Re-key an existing store in place: open with the current key (from
    /// `config.pass_key`), replace the store's wrapping key with
    /// `new_pass_key`, and close.
    ///
    /// This is a standalone lifecycle operation — it must run while the store
    /// is **not** open anywhere else (Askar's `rekey` needs exclusive access),
    /// so it takes an owned `Store` rather than the shared `Arc<Store>` a live
    /// provider holds. Fails if `config.pass_key` is wrong (the store won't
    /// open) or the store is corrupt.
    pub async fn rekey(config: AskarConfig, new_pass_key: &str) -> Result<()> {
        let mut store = Store::open(
            &config.database_url,
            Some(config.key_method.into()),
            PassKey::from(config.pass_key.as_str()),
            config.profile.clone(),
        )
        .await?;
        store
            .rekey(config.key_method.into(), PassKey::from(new_pass_key))
            .await?;
        store.close().await?;
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for AskarStorageProvider {
    async fn save(&self, record: &Record) -> agent_core::Result<()> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        // Convert tags to Askar EntryTag format
        let tags: Vec<EntryTag> = record
            .tags
            .iter()
            .map(|(k, v)| EntryTag::Encrypted(k.clone(), v.clone()))
            .collect();

        // Serialize the full record
        let value = serde_json::to_vec(record)
            .map_err(|e| agent_core::AgentError::storage(format!("Serialization failed: {}", e)))?;

        session
            .insert(&record.category, &record.name, &value, Some(&tags), None) // no expiry
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Insert failed: {}", e)))?;

        // Commit the session to persist changes
        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Commit failed: {}", e)))?;

        Ok(())
    }

    async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        let entry = session
            .fetch(category, name, false)
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Fetch failed: {}", e)))?;

        match entry {
            Some(e) => {
                let record: Record = serde_json::from_slice(&e.value).map_err(|err| {
                    agent_core::AgentError::storage(format!("Deserialization failed: {}", err))
                })?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    async fn find_all(&self, category: &str, query: &Query) -> agent_core::Result<Vec<Record>> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        // Convert query to Askar TagFilter
        let tag_filter = convert_query(query);

        let entries = session
            .fetch_all(
                Some(category),
                Some(tag_filter),
                query.limit.map(|l| l as i64),
                None,  // order_by
                false, // descending
                false, // for_update
            )
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Fetch all failed: {}", e)))?;

        let mut records = Vec::new();
        for entry in entries {
            let record: Record = serde_json::from_slice(&entry.value).map_err(|err| {
                agent_core::AgentError::storage(format!("Deserialization failed: {}", err))
            })?;
            records.push(record);
        }

        Ok(records)
    }

    async fn update(&self, record: &Record) -> agent_core::Result<()> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        // Convert tags to Askar EntryTag format
        let tags: Vec<EntryTag> = record
            .tags
            .iter()
            .map(|(k, v)| EntryTag::Encrypted(k.clone(), v.clone()))
            .collect();

        let value = serde_json::to_vec(record)
            .map_err(|e| agent_core::AgentError::storage(format!("Serialization failed: {}", e)))?;

        session
            .replace(&record.category, &record.name, &value, Some(&tags), None) // no expiry
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Replace failed: {}", e)))?;

        // Commit the session to persist changes
        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Commit failed: {}", e)))?;

        Ok(())
    }

    async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        session
            .remove(category, name)
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Remove failed: {}", e)))?;

        // Commit the session to persist changes
        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Commit failed: {}", e)))?;

        Ok(())
    }

    async fn delete_all(&self, category: &str) -> agent_core::Result<()> {
        let mut session = self.store.session(None).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to create session: {}", e))
        })?;

        session
            .remove_all(Some(category), None)
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Remove all failed: {}", e)))?;

        // Commit the session to persist changes
        session
            .commit()
            .await
            .map_err(|e| agent_core::AgentError::storage(format!("Commit failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::traits::Record;
    use std::collections::HashMap;

    async fn create_test_provider() -> AskarStorageProvider {
        let config = AskarConfig::builder()
            .in_memory()
            .pass_key("test-key")
            .create_if_missing(true)
            .build()
            .unwrap();

        AskarStorageProvider::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn test_save_and_find() {
        let provider = create_test_provider().await;

        let value = serde_json::to_vec(&serde_json::json!({"data": "test value"})).unwrap();
        let record = Record {
            category: "test".to_string(),
            name: "test-1".to_string(),
            value,
            tags: [("status".to_string(), "active".to_string())]
                .into_iter()
                .collect(),
        };

        provider.save(&record).await.unwrap();

        let found = provider.find("test", "test-1").await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.name, "test-1");
        let found_value: serde_json::Value = serde_json::from_slice(&found.value).unwrap();
        assert_eq!(found_value["data"], "test value");
    }

    #[tokio::test]
    async fn test_find_nonexistent() {
        let provider = create_test_provider().await;

        let result = provider.find("test", "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update() {
        let provider = create_test_provider().await;

        let value = serde_json::to_vec(&serde_json::json!({"data": "original"})).unwrap();
        let mut record = Record {
            category: "test".to_string(),
            name: "test-1".to_string(),
            value,
            tags: HashMap::new(),
        };

        provider.save(&record).await.unwrap();

        record.value = serde_json::to_vec(&serde_json::json!({"data": "updated"})).unwrap();
        provider.update(&record).await.unwrap();

        let found = provider.find("test", "test-1").await.unwrap().unwrap();
        let found_value: serde_json::Value = serde_json::from_slice(&found.value).unwrap();
        assert_eq!(found_value["data"], "updated");
    }

    #[tokio::test]
    async fn test_delete() {
        let provider = create_test_provider().await;

        let value = serde_json::to_vec(&serde_json::json!({})).unwrap();
        let record = Record {
            category: "test".to_string(),
            name: "test-1".to_string(),
            value,
            tags: HashMap::new(),
        };

        provider.save(&record).await.unwrap();
        provider.delete("test", "test-1").await.unwrap();

        let found = provider.find("test", "test-1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_all_with_query() {
        let provider = create_test_provider().await;

        // Save multiple records
        for i in 1..=3 {
            let value = serde_json::to_vec(&serde_json::json!({"index": i})).unwrap();
            let record = Record {
                category: "test".to_string(),
                name: format!("test-{}", i),
                value,
                tags: [("status".to_string(), "active".to_string())]
                    .into_iter()
                    .collect(),
            };
            provider.save(&record).await.unwrap();
        }

        // Query with tag filter
        let mut query = Query::default();
        query
            .tags
            .insert("status".to_string(), "active".to_string());

        let results = provider.find_all("test", &query).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_delete_all() {
        let provider = create_test_provider().await;

        // Save multiple records
        for i in 1..=3 {
            let value = serde_json::to_vec(&serde_json::json!({})).unwrap();
            let record = Record {
                category: "test".to_string(),
                name: format!("test-{}", i),
                value,
                tags: HashMap::new(),
            };
            provider.save(&record).await.unwrap();
        }

        provider.delete_all("test").await.unwrap();

        let results = provider.find_all("test", &Query::default()).await.unwrap();
        assert_eq!(results.len(), 0);
    }
}
