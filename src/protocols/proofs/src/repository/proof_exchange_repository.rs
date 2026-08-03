use crate::domain::{ProofExchangeRole, ProofExchangeState};
use crate::repository::proof_exchange::ProofExchangeRecord;
use crate::{ProofError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for proof exchange repository operations
#[async_trait]
pub trait ProofExchangeRepositoryTrait: Send + Sync {
    /// Save a new proof exchange record
    async fn save(&self, record: &ProofExchangeRecord) -> Result<()>;

    /// Update an existing proof exchange record
    async fn update(&self, record: &ProofExchangeRecord) -> Result<()>;

    /// Find proof exchange by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<ProofExchangeRecord>>;

    /// Find proof exchange by thread ID
    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<ProofExchangeRecord>>;

    /// Find proof exchanges by role and thread ID
    async fn find_by_role_and_thread_id(
        &self,
        role: ProofExchangeRole,
        thread_id: &str,
    ) -> Result<Option<ProofExchangeRecord>>;

    /// Find proof exchanges by connection ID
    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Vec<ProofExchangeRecord>>;

    /// Find proof exchanges by state
    async fn find_by_state(&self, state: ProofExchangeState) -> Result<Vec<ProofExchangeRecord>>;

    /// Find proof exchanges by role
    async fn find_by_role(&self, role: ProofExchangeRole) -> Result<Vec<ProofExchangeRecord>>;

    /// Delete proof exchange by ID
    async fn delete(&self, id: &str) -> Result<()>;

    /// Get all proof exchanges
    async fn get_all(&self) -> Result<Vec<ProofExchangeRecord>>;
}

/// In-memory proof exchange repository
pub struct ProofExchangeRepository {
    records: Arc<RwLock<HashMap<String, ProofExchangeRecord>>>,
}

impl ProofExchangeRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for ProofExchangeRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProofExchangeRepositoryTrait for ProofExchangeRepository {
    async fn save(&self, record: &ProofExchangeRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(ProofError::AlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &ProofExchangeRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(ProofError::NotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.values().find(|r| r.thread_id == thread_id).cloned())
    }

    async fn find_by_role_and_thread_id(
        &self,
        role: ProofExchangeRole,
        thread_id: &str,
    ) -> Result<Option<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.role == role && r.thread_id == thread_id)
            .cloned())
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Vec<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.connection_id.as_deref() == Some(connection_id))
            .cloned()
            .collect())
    }

    async fn find_by_state(&self, state: ProofExchangeState) -> Result<Vec<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.state == state)
            .cloned()
            .collect())
    }

    async fn find_by_role(&self, role: ProofExchangeRole) -> Result<Vec<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.role == role)
            .cloned()
            .collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;

        if records.remove(id).is_none() {
            return Err(ProofError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<ProofExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(
        thread_id: &str,
        role: ProofExchangeRole,
        state: ProofExchangeState,
    ) -> ProofExchangeRecord {
        ProofExchangeRecord::new(role, state, thread_id.to_string())
    }

    #[tokio::test]
    async fn test_save_and_find_by_id() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_save_duplicate() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record).await.unwrap();
        let result = repo.save(&record).await;

        assert!(result.is_err());
        match result {
            Err(ProofError::AlreadyExists(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[tokio::test]
    async fn test_update() {
        let repo = ProofExchangeRepository::new();
        let mut record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record).await.unwrap();

        record.update_state(ProofExchangeState::PresentationReceived);
        repo.update(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap().unwrap();
        assert_eq!(found.state, ProofExchangeState::PresentationReceived);
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        let result = repo.update(&record).await;

        assert!(result.is_err());
        match result {
            Err(ProofError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_find_by_thread_id() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-123",
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
        );

        repo.save(&record).await.unwrap();

        let found = repo.find_by_thread_id("thread-123").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().thread_id, "thread-123");
    }

    #[tokio::test]
    async fn test_find_by_role_and_thread_id() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record).await.unwrap();

        let found = repo
            .find_by_role_and_thread_id(ProofExchangeRole::Verifier, "thread-1")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().role, ProofExchangeRole::Verifier);

        // Should not find with wrong role
        let not_found = repo
            .find_by_role_and_thread_id(ProofExchangeRole::Prover, "thread-1")
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_find_by_connection_id() {
        let repo = ProofExchangeRepository::new();
        let mut record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );
        record.set_connection_id("conn-1".to_string());

        repo.save(&record).await.unwrap();

        let found = repo.find_by_connection_id("conn-1").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].connection_id, Some("conn-1".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let repo = ProofExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::Done,
        );
        let record2 = create_test_record(
            "thread-2",
            ProofExchangeRole::Prover,
            ProofExchangeState::Done,
        );
        let record3 = create_test_record(
            "thread-3",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();
        repo.save(&record3).await.unwrap();

        let found = repo.find_by_state(ProofExchangeState::Done).await.unwrap();
        assert_eq!(found.len(), 2);
    }

    #[tokio::test]
    async fn test_find_by_role() {
        let repo = ProofExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );
        let record2 = create_test_record(
            "thread-2",
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo
            .find_by_role(ProofExchangeRole::Verifier)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, ProofExchangeRole::Verifier);
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = ProofExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );

        repo.save(&record).await.unwrap();
        repo.delete(&record.id).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let repo = ProofExchangeRepository::new();

        let result = repo.delete("non-existent").await;

        assert!(result.is_err());
        match result {
            Err(ProofError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_all() {
        let repo = ProofExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
        );
        let record2 = create_test_record(
            "thread-2",
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let all = repo.get_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }
}
