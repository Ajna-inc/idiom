use crate::{KeylistRecord, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for keylist repository operations
#[async_trait]
pub trait KeylistRepositoryTrait: Send + Sync {
    /// Save a new keylist record
    async fn save(&self, record: &KeylistRecord) -> Result<()>;

    /// Find keylist records by mediation ID
    async fn find_by_mediation_id(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>>;

    /// Find a keylist record by mediation ID and recipient key
    async fn find_by_recipient_key(
        &self,
        mediation_id: &str,
        recipient_key: &str,
    ) -> Result<Option<KeylistRecord>>;

    /// Delete keylist record by recipient key
    async fn delete_by_recipient_key(&self, mediation_id: &str, recipient_key: &str) -> Result<()>;

    /// Delete all keylist records for a mediation
    async fn delete_by_mediation_id(&self, mediation_id: &str) -> Result<()>;

    /// Get all keylist records
    async fn get_all(&self) -> Result<Vec<KeylistRecord>>;

    /// Find the keylist record for a recipient key across all mediations.
    /// This is the reverse lookup needed by ForwardService: given a key, find which mediation owns it.
    async fn find_mediation_for_recipient_key(
        &self,
        recipient_key: &str,
    ) -> Result<Option<KeylistRecord>> {
        // Default impl: iterate all records (in-memory fallback)
        let all = self.get_all().await?;
        Ok(all.into_iter().find(|r| r.recipient_key == recipient_key))
    }
}

/// In-memory keylist repository
pub struct KeylistRepository {
    records: Arc<RwLock<HashMap<String, KeylistRecord>>>,
}

impl KeylistRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for KeylistRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeylistRepositoryTrait for KeylistRepository {
    async fn save(&self, record: &KeylistRecord) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_mediation_id(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        let records = self.records.read().await;
        Ok(records
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
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.mediation_id == mediation_id && r.recipient_key == recipient_key)
            .cloned())
    }

    async fn delete_by_recipient_key(&self, mediation_id: &str, recipient_key: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records
            .retain(|_, r| !(r.mediation_id == mediation_id && r.recipient_key == recipient_key));
        Ok(())
    }

    async fn delete_by_mediation_id(&self, mediation_id: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records.retain(|_, r| r.mediation_id != mediation_id);
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<KeylistRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeylistAction, KeylistResult};

    #[tokio::test]
    async fn test_save_and_find() {
        let repo = KeylistRepository::new();
        let record = KeylistRecord::new(
            "med-123".to_string(),
            "did:key:z6Mkk...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );

        repo.save(&record).await.unwrap();
        let found = repo.find_by_mediation_id("med-123").await.unwrap();
        assert_eq!(found.len(), 1);
    }

    #[tokio::test]
    async fn test_find_by_recipient_key() {
        let repo = KeylistRepository::new();
        let record = KeylistRecord::new(
            "med-123".to_string(),
            "did:key:z6Mkk...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );

        repo.save(&record).await.unwrap();
        let found = repo
            .find_by_recipient_key("med-123", "did:key:z6Mkk...")
            .await
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_delete_by_recipient_key() {
        let repo = KeylistRepository::new();
        let record = KeylistRecord::new(
            "med-123".to_string(),
            "did:key:z6Mkk...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );

        repo.save(&record).await.unwrap();
        repo.delete_by_recipient_key("med-123", "did:key:z6Mkk...")
            .await
            .unwrap();

        let found = repo
            .find_by_recipient_key("med-123", "did:key:z6Mkk...")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_by_mediation_id() {
        let repo = KeylistRepository::new();
        let record1 = KeylistRecord::new(
            "med-123".to_string(),
            "did:key:z6Mkk1...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );
        let record2 = KeylistRecord::new(
            "med-123".to_string(),
            "did:key:z6Mkk2...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        repo.delete_by_mediation_id("med-123").await.unwrap();

        let found = repo.find_by_mediation_id("med-123").await.unwrap();
        assert_eq!(found.len(), 0);
    }
}
