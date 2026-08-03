use crate::domain::{DidExchangeRole, DidExchangeState};
use crate::repository::connection_record::ConnectionRecord;
use crate::{ConnectionError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for connection repository operations
#[async_trait]
pub trait ConnectionRepositoryTrait: Send + Sync {
    /// Save a new connection record
    async fn save(&self, record: &ConnectionRecord) -> Result<()>;

    /// Update an existing connection record
    async fn update(&self, record: &ConnectionRecord) -> Result<()>;

    /// Find connection by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<ConnectionRecord>>;

    /// Find connection by thread ID
    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<ConnectionRecord>>;

    /// Find connections by role and thread ID
    async fn find_by_role_and_thread_id(
        &self,
        role: DidExchangeRole,
        thread_id: &str,
    ) -> Result<Option<ConnectionRecord>>;

    /// Find connections by out-of-band ID
    async fn find_by_out_of_band_id(&self, oob_id: &str) -> Result<Vec<ConnectionRecord>>;

    /// Find connections by DID (our DID)
    async fn find_by_did(&self, did: &str) -> Result<Vec<ConnectionRecord>>;

    /// Find connections by their DID
    async fn find_by_their_did(&self, their_did: &str) -> Result<Vec<ConnectionRecord>>;

    /// Find connections by state
    async fn find_by_state(&self, state: DidExchangeState) -> Result<Vec<ConnectionRecord>>;

    /// Find connections by role
    async fn find_by_role(&self, role: DidExchangeRole) -> Result<Vec<ConnectionRecord>>;

    /// Find all completed connections
    async fn find_all_completed(&self) -> Result<Vec<ConnectionRecord>>;

    /// Delete connection by ID
    async fn delete(&self, id: &str) -> Result<()>;

    /// Get all connections
    async fn get_all(&self) -> Result<Vec<ConnectionRecord>>;

    /// Find connection by their authentication key (base58 verkey).
    /// Used for O(1) connection lookups in the mediator instead of O(n) scans.
    async fn find_by_auth_key(&self, key: &str) -> Result<Option<ConnectionRecord>> {
        // Default: linear scan (overridden by storage-backed impl with indexed query)
        let all = self.get_all().await?;
        Ok(all
            .into_iter()
            .find(|r| r.their_authentication_key_base58.as_deref() == Some(key)))
    }

    /// Find connection by their key agreement key (base58).
    async fn find_by_ka_key(&self, key: &str) -> Result<Option<ConnectionRecord>> {
        let all = self.get_all().await?;
        Ok(all
            .into_iter()
            .find(|r| r.their_key_agreement_key_base58.as_deref() == Some(key)))
    }
}

/// In-memory connection repository
pub struct ConnectionRepository {
    records: Arc<RwLock<HashMap<String, ConnectionRecord>>>,
}

impl ConnectionRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for ConnectionRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConnectionRepositoryTrait for ConnectionRepository {
    async fn save(&self, record: &ConnectionRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(ConnectionError::AlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &ConnectionRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(ConnectionError::NotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.tags.thread_id == thread_id)
            .cloned())
    }

    async fn find_by_role_and_thread_id(
        &self,
        role: DidExchangeRole,
        thread_id: &str,
    ) -> Result<Option<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.tags.role == role && r.tags.thread_id == thread_id)
            .cloned())
    }

    async fn find_by_out_of_band_id(&self, oob_id: &str) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.tags.out_of_band_id == oob_id)
            .cloned()
            .collect())
    }

    async fn find_by_did(&self, did: &str) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.tags.did == did)
            .cloned()
            .collect())
    }

    async fn find_by_their_did(&self, their_did: &str) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.tags.their_did.as_deref() == Some(their_did))
            .cloned()
            .collect())
    }

    async fn find_by_state(&self, state: DidExchangeState) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.tags.state == state)
            .cloned()
            .collect())
    }

    async fn find_by_role(&self, role: DidExchangeRole) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.tags.role == role)
            .cloned()
            .collect())
    }

    async fn find_all_completed(&self) -> Result<Vec<ConnectionRecord>> {
        self.find_by_state(DidExchangeState::Completed).await
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;

        if records.remove(id).is_none() {
            return Err(ConnectionError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<ConnectionRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::ConnectionRecordBuilder;

    async fn create_test_record(
        thread_id: &str,
        oob_id: &str,
        role: DidExchangeRole,
        state: DidExchangeState,
    ) -> ConnectionRecord {
        ConnectionRecordBuilder::new(
            role,
            state,
            thread_id.to_string(),
            oob_id.to_string(),
            format!("did:peer:{}", thread_id),
        )
        .build()
    }

    #[tokio::test]
    async fn test_save_and_find_by_id() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_save_duplicate() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();
        let result = repo.save(&record).await;

        assert!(result.is_err());
        match result {
            Err(ConnectionError::AlreadyExists(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[tokio::test]
    async fn test_update() {
        let repo = ConnectionRepository::new();
        let mut record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();

        record.update_state(DidExchangeState::ResponseReceived);
        repo.update(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap().unwrap();
        assert_eq!(found.state, DidExchangeState::ResponseReceived);
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        let result = repo.update(&record).await;

        assert!(result.is_err());
        match result {
            Err(ConnectionError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_find_by_thread_id() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-123",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();

        let found = repo.find_by_thread_id("thread-123").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().thread_id, "thread-123");
    }

    #[tokio::test]
    async fn test_find_by_role_and_thread_id() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
        )
        .await;

        repo.save(&record).await.unwrap();

        let found = repo
            .find_by_role_and_thread_id(DidExchangeRole::Responder, "thread-1")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().role, DidExchangeRole::Responder);
    }

    #[tokio::test]
    async fn test_find_by_out_of_band_id() {
        let repo = ConnectionRepository::new();

        let record1 = create_test_record(
            "thread-1",
            "oob-shared",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;
        let record2 = create_test_record(
            "thread-2",
            "oob-shared",
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
        )
        .await;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo.find_by_out_of_band_id("oob-shared").await.unwrap();
        assert_eq!(found.len(), 2);
    }

    #[tokio::test]
    async fn test_find_by_did() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();

        let found = repo.find_by_did("did:peer:thread-1").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].did, "did:peer:thread-1");
    }

    #[tokio::test]
    async fn test_find_by_their_did() {
        let repo = ConnectionRepository::new();
        let mut record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::ResponseReceived,
        )
        .await;

        record.set_their_did("did:peer:responder".to_string());
        repo.save(&record).await.unwrap();

        let found = repo.find_by_their_did("did:peer:responder").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].their_did, Some("did:peer:responder".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let repo = ConnectionRepository::new();

        let record1 = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
        )
        .await;
        let record2 = create_test_record(
            "thread-2",
            "oob-2",
            DidExchangeRole::Responder,
            DidExchangeState::Completed,
        )
        .await;
        let record3 = create_test_record(
            "thread-3",
            "oob-3",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();
        repo.save(&record3).await.unwrap();

        let found = repo
            .find_by_state(DidExchangeState::Completed)
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
    }

    #[tokio::test]
    async fn test_find_by_role() {
        let repo = ConnectionRepository::new();

        let record1 = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;
        let record2 = create_test_record(
            "thread-2",
            "oob-2",
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
        )
        .await;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo.find_by_role(DidExchangeRole::Requester).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, DidExchangeRole::Requester);
    }

    #[tokio::test]
    async fn test_find_all_completed() {
        let repo = ConnectionRepository::new();

        let record1 = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::Completed,
        )
        .await;
        let record2 = create_test_record(
            "thread-2",
            "oob-2",
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
        )
        .await;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo.find_all_completed().await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].state, DidExchangeState::Completed);
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = ConnectionRepository::new();
        let record = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;

        repo.save(&record).await.unwrap();
        repo.delete(&record.id).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let repo = ConnectionRepository::new();

        let result = repo.delete("non-existent").await;

        assert!(result.is_err());
        match result {
            Err(ConnectionError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_all() {
        let repo = ConnectionRepository::new();

        let record1 = create_test_record(
            "thread-1",
            "oob-1",
            DidExchangeRole::Requester,
            DidExchangeState::RequestSent,
        )
        .await;
        let record2 = create_test_record(
            "thread-2",
            "oob-2",
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
        )
        .await;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let all = repo.get_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }
}
