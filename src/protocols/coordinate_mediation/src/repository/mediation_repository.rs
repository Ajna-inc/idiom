use crate::{MediationError, MediationRecord, MediationRole, MediationState, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for mediation repository operations
#[async_trait]
pub trait MediationRepositoryTrait: Send + Sync {
    /// Save a new mediation record
    async fn save(&self, record: &MediationRecord) -> Result<()>;

    /// Update an existing mediation record
    async fn update(&self, record: &MediationRecord) -> Result<()>;

    /// Find mediation by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<MediationRecord>>;

    /// Find mediation by connection ID
    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Option<MediationRecord>>;

    /// Find mediations by state
    async fn find_by_state(&self, state: MediationState) -> Result<Vec<MediationRecord>>;

    /// Find mediations by role
    async fn find_by_role(&self, role: MediationRole) -> Result<Vec<MediationRecord>>;

    /// Find all granted mediations (for recipient)
    async fn find_all_granted(&self) -> Result<Vec<MediationRecord>>;

    /// Delete mediation by ID
    async fn delete(&self, id: &str) -> Result<()>;

    /// Get all mediations
    async fn get_all(&self) -> Result<Vec<MediationRecord>>;
}

/// In-memory mediation repository
pub struct MediationRepository {
    records: Arc<RwLock<HashMap<String, MediationRecord>>>,
}

impl MediationRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MediationRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MediationRepositoryTrait for MediationRepository {
    async fn save(&self, record: &MediationRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(MediationError::AlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &MediationRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(MediationError::NotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<MediationRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Option<MediationRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.connection_id == connection_id)
            .cloned())
    }

    async fn find_by_state(&self, state: MediationState) -> Result<Vec<MediationRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.state == state)
            .cloned()
            .collect())
    }

    async fn find_by_role(&self, role: MediationRole) -> Result<Vec<MediationRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.role == role)
            .cloned()
            .collect())
    }

    async fn find_all_granted(&self) -> Result<Vec<MediationRecord>> {
        self.find_by_state(MediationState::Granted).await
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;
        records
            .remove(id)
            .ok_or_else(|| MediationError::NotFound(id.to_string()))?;
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<MediationRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediationRecordBuilder;

    #[tokio::test]
    async fn test_save_and_find() {
        let repo = MediationRepository::new();
        let record = MediationRecordBuilder::new("conn-123".to_string(), MediationRole::Recipient)
            .id("med-123".to_string())
            .build();

        repo.save(&record).await.unwrap();
        let found = repo.find_by_id("med-123").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "med-123");
    }

    #[tokio::test]
    async fn test_save_duplicate_fails() {
        let repo = MediationRepository::new();
        let record = MediationRecordBuilder::new("conn-123".to_string(), MediationRole::Recipient)
            .id("med-123".to_string())
            .build();

        repo.save(&record).await.unwrap();
        let result = repo.save(&record).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update() {
        let repo = MediationRepository::new();
        let mut record =
            MediationRecordBuilder::new("conn-123".to_string(), MediationRole::Recipient)
                .id("med-123".to_string())
                .build();

        repo.save(&record).await.unwrap();

        record.state = MediationState::Granted;
        record.endpoint = Some("https://mediator.example.com".to_string());

        repo.update(&record).await.unwrap();
        let found = repo.find_by_id("med-123").await.unwrap().unwrap();
        assert_eq!(found.state, MediationState::Granted);
        assert_eq!(found.endpoint.unwrap(), "https://mediator.example.com");
    }

    #[tokio::test]
    async fn test_find_by_connection_id() {
        let repo = MediationRepository::new();
        let record =
            MediationRecordBuilder::new("conn-123".to_string(), MediationRole::Recipient).build();

        repo.save(&record).await.unwrap();
        let found = repo.find_by_connection_id("conn-123").await.unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let repo = MediationRepository::new();
        let record1 = MediationRecordBuilder::new("conn-1".to_string(), MediationRole::Recipient)
            .state(MediationState::Requested)
            .build();
        let record2 = MediationRecordBuilder::new("conn-2".to_string(), MediationRole::Recipient)
            .state(MediationState::Granted)
            .build();

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let granted = repo.find_by_state(MediationState::Granted).await.unwrap();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].state, MediationState::Granted);
    }
}
