//! Profile-scoped storage provider.
//!
//! Wraps a shared `Arc<Store>` and scopes ALL operations to a specific Askar profile.
//! This gives each tenant isolated storage within a single database.
//!
//! Two tenants using the same Store but different profiles cannot see each other's records.
//! Askar enforces this at the SQL level: `WHERE profile_id = ?`.

use agent_core::traits::{Query, Record, StorageProvider};
use aries_askar::entry::{EntryTag, TagFilter};
use aries_askar::Store;
use async_trait::async_trait;
use std::sync::Arc;

/// Storage provider scoped to a single Askar profile.
///
/// All save/find/update/delete operations open sessions with `store.session(Some(profile))`,
/// ensuring records are isolated to this tenant's namespace.
#[derive(Clone)]
pub struct ProfileScopedStorageProvider {
    store: Arc<Store>,
    profile: String,
}

impl ProfileScopedStorageProvider {
    /// Create a new profile-scoped storage provider.
    pub fn new(store: Arc<Store>, profile: impl Into<String>) -> Self {
        Self {
            store,
            profile: profile.into(),
        }
    }

    /// Get the profile name.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Get the underlying store (for advanced operations like key management).
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Convert agent_core Query tags to Askar TagFilter.
    fn convert_query(query: &Query) -> TagFilter {
        if query.tags.is_empty() {
            return TagFilter::all_of(vec![]);
        }
        let filters: Vec<TagFilter> = query
            .tags
            .iter()
            .map(|(k, v)| TagFilter::is_eq(k, v))
            .collect();
        if filters.len() == 1 {
            filters.into_iter().next().unwrap()
        } else {
            TagFilter::all_of(filters)
        }
    }
}

#[async_trait]
impl StorageProvider for ProfileScopedStorageProvider {
    async fn save(&self, record: &Record) -> agent_core::Result<()> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        let tags: Vec<EntryTag> = record
            .tags
            .iter()
            .map(|(k, v)| EntryTag::Encrypted(k.clone(), v.clone()))
            .collect();

        let value = serde_json::to_vec(record)
            .map_err(|e| agent_core::AgentError::storage(format!("Serialize: {}", e)))?;

        session
            .insert(&record.category, &record.name, &value, Some(&tags), None)
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Insert [{}]: {}", self.profile, e))
            })?;

        session.commit().await.map_err(|e| {
            agent_core::AgentError::storage(format!("Commit [{}]: {}", self.profile, e))
        })?;

        Ok(())
    }

    async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        let entry = session.fetch(category, name, false).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Fetch [{}]: {}", self.profile, e))
        })?;

        match entry {
            Some(e) => {
                let record: Record = serde_json::from_slice(&e.value)
                    .map_err(|e| agent_core::AgentError::storage(format!("Deserialize: {}", e)))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    async fn find_all(&self, category: &str, query: &Query) -> agent_core::Result<Vec<Record>> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        let tag_filter = Self::convert_query(query);

        let entries = session
            .fetch_all(
                Some(category),
                Some(tag_filter),
                query.limit.map(|l| l as i64),
                None,
                false,
                false,
            )
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Fetch all [{}]: {}", self.profile, e))
            })?;

        let mut records = Vec::new();
        for entry in entries {
            let record: Record = serde_json::from_slice(&entry.value)
                .map_err(|e| agent_core::AgentError::storage(format!("Deserialize: {}", e)))?;
            records.push(record);
        }
        Ok(records)
    }

    async fn update(&self, record: &Record) -> agent_core::Result<()> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        let tags: Vec<EntryTag> = record
            .tags
            .iter()
            .map(|(k, v)| EntryTag::Encrypted(k.clone(), v.clone()))
            .collect();

        let value = serde_json::to_vec(record)
            .map_err(|e| agent_core::AgentError::storage(format!("Serialize: {}", e)))?;

        session
            .replace(&record.category, &record.name, &value, Some(&tags), None)
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Replace [{}]: {}", self.profile, e))
            })?;

        session.commit().await.map_err(|e| {
            agent_core::AgentError::storage(format!("Commit [{}]: {}", self.profile, e))
        })?;

        Ok(())
    }

    async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        session.remove(category, name).await.map_err(|e| {
            agent_core::AgentError::storage(format!("Remove [{}]: {}", self.profile, e))
        })?;

        session.commit().await.map_err(|e| {
            agent_core::AgentError::storage(format!("Commit [{}]: {}", self.profile, e))
        })?;

        Ok(())
    }

    async fn delete_all(&self, category: &str) -> agent_core::Result<()> {
        let mut session = self
            .store
            .session(Some(self.profile.clone()))
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Session [{}]: {}", self.profile, e))
            })?;

        session
            .remove_all(Some(category), None)
            .await
            .map_err(|e| {
                agent_core::AgentError::storage(format!("Remove all [{}]: {}", self.profile, e))
            })?;

        session.commit().await.map_err(|e| {
            agent_core::AgentError::storage(format!("Commit [{}]: {}", self.profile, e))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aries_askar::storage::generate_raw_store_key;
    use aries_askar::StoreKeyMethod;

    async fn create_test_store() -> Arc<Store> {
        let pass_key = generate_raw_store_key(None).unwrap();
        let store = Store::provision(
            "sqlite://:memory:",
            StoreKeyMethod::RawKey,
            pass_key.as_ref(),
            None,
            false,
        )
        .await
        .unwrap();
        Arc::new(store)
    }

    #[tokio::test]
    async fn test_profile_isolation() {
        let store = create_test_store().await;

        // Create two profiles
        store
            .create_profile(Some("tenant-a".to_string()))
            .await
            .unwrap();
        store
            .create_profile(Some("tenant-b".to_string()))
            .await
            .unwrap();

        let storage_a = ProfileScopedStorageProvider::new(store.clone(), "tenant-a");
        let storage_b = ProfileScopedStorageProvider::new(store.clone(), "tenant-b");

        // Save a record in profile A
        let record = Record::new("test", "msg-1", b"hello from A".to_vec());
        storage_a.save(&record).await.unwrap();

        // Profile A can see it
        let found = storage_a.find("test", "msg-1").await.unwrap();
        assert!(found.is_some());

        // Profile B cannot see it
        let found = storage_b.find("test", "msg-1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_save_find_delete() {
        let store = create_test_store().await;
        store
            .create_profile(Some("tenant-x".to_string()))
            .await
            .unwrap();
        let storage = ProfileScopedStorageProvider::new(store, "tenant-x");

        let record =
            Record::new("messages", "m1", b"content".to_vec()).add_tag("channel", "general");
        storage.save(&record).await.unwrap();

        let found = storage.find("messages", "m1").await.unwrap().unwrap();
        assert_eq!(found.name, "m1");

        storage.delete("messages", "m1").await.unwrap();
        let found = storage.find("messages", "m1").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_all_with_tags() {
        let store = create_test_store().await;
        store
            .create_profile(Some("tenant-y".to_string()))
            .await
            .unwrap();
        let storage = ProfileScopedStorageProvider::new(store, "tenant-y");

        for i in 0..5 {
            let record = Record::new(
                "msg",
                format!("m{}", i),
                format!("content {}", i).into_bytes(),
            )
            .add_tag("channel", "general");
            storage.save(&record).await.unwrap();
        }

        let query = Query {
            tags: [("channel".to_string(), "general".to_string())].into(),
            limit: None,
            skip: None,
        };
        let results = storage.find_all("msg", &query).await.unwrap();
        assert_eq!(results.len(), 5);
    }
}
