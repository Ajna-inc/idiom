//! Storage-backed user profile repository
//!
//! Persists user profile records using the injected StorageProvider trait.
//! Follows the same pattern as StorageBackedReactionRepository, etc.

use crate::repository::user_profile_record::{
    UserProfileRecord, UserProfileRepositoryTrait, OWN_PROFILE_ID, USER_PROFILE_CATEGORY,
};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage-backed user profile repository.
///
/// Persists own profile and peer profiles to durable storage via the
/// injected `StorageProvider`. The storage provider is created by the
/// agent/TenantContext — this repo never knows what backend it uses.
pub struct StorageBackedUserProfileRepository {
    storage: Arc<dyn StorageProvider>,
    own_cache: Arc<RwLock<Option<Option<UserProfileRecord>>>>,
    peer_cache: Arc<RwLock<Option<HashMap<String, UserProfileRecord>>>>,
}

impl StorageBackedUserProfileRepository {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            own_cache: Arc::new(RwLock::new(None)),
            peer_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Load own profile from storage into cache
    async fn ensure_own_cache(&self) -> Result<(), String> {
        let mut cache = self.own_cache.write().await;
        if cache.is_none() {
            let record = self
                .storage
                .find(USER_PROFILE_CATEGORY, OWN_PROFILE_ID)
                .await
                .map_err(|e| format!("Failed to load own profile: {}", e))?;
            let profile = record.and_then(|r| serde_json::from_slice(&r.value).ok());
            *cache = Some(profile);
        }
        Ok(())
    }

    /// Load peer profiles from storage into cache
    async fn ensure_peer_cache(&self) -> Result<(), String> {
        let mut cache = self.peer_cache.write().await;
        if cache.is_none() {
            let query = Query::new();
            let records = self
                .storage
                .find_all(USER_PROFILE_CATEGORY, &query)
                .await
                .map_err(|e| format!("Failed to load peer profiles: {}", e))?;

            let mut map = HashMap::new();
            for record in records {
                // Skip the own profile record
                if record.name == OWN_PROFILE_ID {
                    continue;
                }
                if let Ok(profile) = serde_json::from_slice::<UserProfileRecord>(&record.value) {
                    // The record name is "peer:{connection_id}"
                    let conn_id = record.name.strip_prefix("peer:").unwrap_or(&record.name);
                    map.insert(conn_id.to_string(), profile);
                }
            }

            if !map.is_empty() {
                tracing::info!("Loaded {} peer profiles from storage", map.len());
            }

            *cache = Some(map);
        }
        Ok(())
    }

    fn profile_to_record(name: &str, profile: &UserProfileRecord) -> Result<Record, String> {
        let value = serde_json::to_vec(profile)
            .map_err(|e| format!("Failed to serialize profile: {}", e))?;

        let mut tags = HashMap::new();
        if let Some(ref display_name) = profile.display_name {
            tags.insert("display_name".to_string(), display_name.clone());
        }

        Ok(Record {
            category: USER_PROFILE_CATEGORY.to_string(),
            name: name.to_string(),
            value,
            tags,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl UserProfileRepositoryTrait for StorageBackedUserProfileRepository {
    async fn save_own_profile(&self, record: &UserProfileRecord) -> Result<(), String> {
        self.ensure_own_cache().await?;

        let storage_record = Self::profile_to_record(OWN_PROFILE_ID, record)?;

        // Try update first, fall back to save
        if self
            .storage
            .find(USER_PROFILE_CATEGORY, OWN_PROFILE_ID)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            self.storage
                .update(&storage_record)
                .await
                .map_err(|e| format!("Failed to update own profile: {}", e))?;
        } else {
            self.storage
                .save(&storage_record)
                .await
                .map_err(|e| format!("Failed to save own profile: {}", e))?;
        }

        // Update cache
        let mut cache = self.own_cache.write().await;
        *cache = Some(Some(record.clone()));

        Ok(())
    }

    async fn get_own_profile(&self) -> Result<Option<UserProfileRecord>, String> {
        self.ensure_own_cache().await?;
        let cache = self.own_cache.read().await;
        Ok(cache.as_ref().unwrap().clone())
    }

    async fn save_peer_profile(
        &self,
        connection_id: &str,
        record: &UserProfileRecord,
    ) -> Result<(), String> {
        self.ensure_peer_cache().await?;

        let name = format!("peer:{}", connection_id);
        let storage_record = Self::profile_to_record(&name, record)?;

        // Try update first, fall back to save
        if self
            .storage
            .find(USER_PROFILE_CATEGORY, &name)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            self.storage
                .update(&storage_record)
                .await
                .map_err(|e| format!("Failed to update peer profile: {}", e))?;
        } else {
            self.storage
                .save(&storage_record)
                .await
                .map_err(|e| format!("Failed to save peer profile: {}", e))?;
        }

        // Update cache
        let mut cache = self.peer_cache.write().await;
        cache
            .as_mut()
            .unwrap()
            .insert(connection_id.to_string(), record.clone());

        Ok(())
    }

    async fn get_peer_profile(
        &self,
        connection_id: &str,
    ) -> Result<Option<UserProfileRecord>, String> {
        self.ensure_peer_cache().await?;
        let cache = self.peer_cache.read().await;
        Ok(cache.as_ref().unwrap().get(connection_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::ImageData;
    use agent_core::traits::Query as CoreQuery;

    /// Minimal in-memory StorageProvider for tests. Backs a HashMap keyed by
    /// (category, name). Behaves like a fresh-from-disk store: dropping one
    /// `MockStorage` and creating another sharing the same Arc<Mutex<...>>
    /// simulates a process restart with persisted data still on disk.
    #[derive(Clone)]
    struct MockStorage {
        records: Arc<std::sync::Mutex<HashMap<(String, String), Record>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                records: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }

        /// Share the underlying disk with another instance — simulates restart.
        fn fork(&self) -> Self {
            Self {
                records: self.records.clone(),
            }
        }
    }

    #[async_trait]
    impl StorageProvider for MockStorage {
        async fn save(&self, record: &Record) -> agent_core::Result<()> {
            self.records.lock().unwrap().insert(
                (record.category.clone(), record.name.clone()),
                record.clone(),
            );
            Ok(())
        }

        async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .get(&(category.to_string(), name.to_string()))
                .cloned())
        }

        async fn find_all(
            &self,
            category: &str,
            _query: &CoreQuery,
        ) -> agent_core::Result<Vec<Record>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|((cat, _), _)| cat == category)
                .map(|(_, r)| r.clone())
                .collect())
        }

        async fn update(&self, record: &Record) -> agent_core::Result<()> {
            self.records.lock().unwrap().insert(
                (record.category.clone(), record.name.clone()),
                record.clone(),
            );
            Ok(())
        }

        async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
            self.records
                .lock()
                .unwrap()
                .remove(&(category.to_string(), name.to_string()));
            Ok(())
        }

        async fn delete_all(&self, category: &str) -> agent_core::Result<()> {
            self.records
                .lock()
                .unwrap()
                .retain(|(cat, _), _| cat != category);
            Ok(())
        }
    }

    fn alice() -> UserProfileRecord {
        UserProfileRecord {
            display_name: Some("Alice".into()),
            display_picture: Some(ImageData {
                mime_type: "image/png".into(),
                base64: "iVBORw0KGgo=".into(),
                links: vec![],
            }),
            display_icon: None,
            description: Some("Original bio".into()),
            preferred_language: Some("en".into()),
        }
    }

    fn bob() -> UserProfileRecord {
        UserProfileRecord {
            display_name: Some("Bob".into()),
            display_picture: None,
            display_icon: None,
            description: Some("Bob's bio".into()),
            preferred_language: None,
        }
    }

    #[tokio::test]
    async fn own_profile_persists_across_repo_instances() {
        let storage_disk = MockStorage::new();

        // First "session": save own profile, then drop the repo (cache evicts).
        let storage1: Arc<dyn StorageProvider> = Arc::new(storage_disk.clone());
        let repo1 = StorageBackedUserProfileRepository::new(storage1);
        let record = alice();
        repo1.save_own_profile(&record).await.unwrap();
        drop(repo1);

        // Second "session" against the same disk — cache must miss and reload.
        let storage2: Arc<dyn StorageProvider> = Arc::new(storage_disk.fork());
        let repo2 = StorageBackedUserProfileRepository::new(storage2);
        let loaded = repo2.get_own_profile().await.unwrap().unwrap();

        // Field-by-field equality (UserProfileRecord doesn't derive PartialEq
        // because of ImageData being a separate type, so check parts).
        assert_eq!(loaded.display_name, record.display_name);
        assert_eq!(loaded.description, record.description);
        assert_eq!(loaded.preferred_language, record.preferred_language);
        let pic = loaded.display_picture.as_ref().unwrap();
        let orig_pic = record.display_picture.as_ref().unwrap();
        assert_eq!(pic.mime_type, orig_pic.mime_type);
        assert_eq!(pic.base64, orig_pic.base64);
    }

    #[tokio::test]
    async fn peer_profiles_persist_across_repo_instances() {
        let storage_disk = MockStorage::new();

        let storage1: Arc<dyn StorageProvider> = Arc::new(storage_disk.clone());
        let repo1 = StorageBackedUserProfileRepository::new(storage1);
        repo1
            .save_peer_profile("conn-alice", &alice())
            .await
            .unwrap();
        repo1.save_peer_profile("conn-bob", &bob()).await.unwrap();
        drop(repo1);

        let storage2: Arc<dyn StorageProvider> = Arc::new(storage_disk.fork());
        let repo2 = StorageBackedUserProfileRepository::new(storage2);

        let alice_loaded = repo2.get_peer_profile("conn-alice").await.unwrap().unwrap();
        assert_eq!(alice_loaded.display_name, Some("Alice".into()));
        assert_eq!(alice_loaded.description, Some("Original bio".into()));

        let bob_loaded = repo2.get_peer_profile("conn-bob").await.unwrap().unwrap();
        assert_eq!(bob_loaded.display_name, Some("Bob".into()));

        // Unknown peer returns None.
        assert!(repo2
            .get_peer_profile("conn-charlie")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn save_overwrites_existing_record_and_invalidates_cache() {
        let storage_disk = MockStorage::new();
        let storage: Arc<dyn StorageProvider> = Arc::new(storage_disk.clone());
        let repo = StorageBackedUserProfileRepository::new(storage);

        // First save
        let mut record = alice();
        repo.save_own_profile(&record).await.unwrap();
        assert_eq!(
            repo.get_own_profile().await.unwrap().unwrap().display_name,
            Some("Alice".into())
        );

        // Mutate and save again on the SAME repo (cache is hot)
        record.display_name = Some("Alice v2".into());
        record.description = Some("Updated bio".into());
        repo.save_own_profile(&record).await.unwrap();

        let loaded = repo.get_own_profile().await.unwrap().unwrap();
        assert_eq!(loaded.display_name, Some("Alice v2".into()));
        assert_eq!(loaded.description, Some("Updated bio".into()));

        // And it's persisted: a new repo against the same disk sees v2.
        let storage2: Arc<dyn StorageProvider> = Arc::new(storage_disk.fork());
        let repo2 = StorageBackedUserProfileRepository::new(storage2);
        assert_eq!(
            repo2.get_own_profile().await.unwrap().unwrap().display_name,
            Some("Alice v2".into())
        );
    }

    #[tokio::test]
    async fn find_all_skips_own_profile_when_listing_peers() {
        // Regression: a previous bug walked find_all() and treated the
        // "default" (own) record as a peer keyed by "default".
        let storage_disk = MockStorage::new();
        let storage: Arc<dyn StorageProvider> = Arc::new(storage_disk.clone());
        let repo = StorageBackedUserProfileRepository::new(storage);

        repo.save_own_profile(&alice()).await.unwrap();
        repo.save_peer_profile("conn-bob", &bob()).await.unwrap();
        drop(repo);

        let storage2: Arc<dyn StorageProvider> = Arc::new(storage_disk.fork());
        let repo2 = StorageBackedUserProfileRepository::new(storage2);

        // Own profile is NOT exposed via get_peer_profile under any id.
        assert!(repo2.get_peer_profile("default").await.unwrap().is_none());
        assert!(repo2
            .get_peer_profile("peer:default")
            .await
            .unwrap()
            .is_none());

        // Peer profile is.
        assert!(repo2.get_peer_profile("conn-bob").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn empty_storage_returns_none() {
        let storage: Arc<dyn StorageProvider> = Arc::new(MockStorage::new());
        let repo = StorageBackedUserProfileRepository::new(storage);

        assert!(repo.get_own_profile().await.unwrap().is_none());
        assert!(repo
            .get_peer_profile("conn-anything")
            .await
            .unwrap()
            .is_none());
    }
}
