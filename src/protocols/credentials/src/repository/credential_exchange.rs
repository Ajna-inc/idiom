use crate::domain::{CredentialExchangeRole, CredentialExchangeState};
use crate::{CredentialError, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Credential Exchange Record
///
/// Represents a credential exchange with full state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialExchangeRecord {
    /// Unique identifier for this exchange
    pub id: String,

    /// Thread ID from the protocol messages
    pub thread_id: String,

    /// Connection ID (optional, links to a DID Exchange connection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,

    /// Role in the credential exchange
    pub role: CredentialExchangeRole,

    /// Current state of the exchange
    pub state: CredentialExchangeState,

    /// Schema ID for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,

    /// Credential definition ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_def_id: Option<String>,

    /// Serialized credential proposal JSON (set when the exchange started
    /// from a propose-credential message).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential_proposal_json: Option<String>,

    /// Serialized credential offer JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_offer_json: Option<String>,

    /// Serialized credential request JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_json: Option<String>,

    /// Serialized credential JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_json: Option<String>,

    /// Credential ID after processing/storing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,

    /// Error message if exchange failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Attributes to auto-issue when the holder's request arrives (issuer side).
    /// Persisted on the record so auto-issue survives a restart and works when a
    /// captured request is replayed — the in-memory registration alone doesn't.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auto_issue_attributes: Option<HashMap<String, String>>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl CredentialExchangeRecord {
    /// Create a new credential exchange record
    pub fn new(
        role: CredentialExchangeRole,
        state: CredentialExchangeState,
        thread_id: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            connection_id: None,
            role,
            state,
            schema_id: None,
            cred_def_id: None,
            credential_proposal_json: None,
            credential_offer_json: None,
            credential_request_json: None,
            credential_json: None,
            credential_id: None,
            error_message: None,
            auto_issue_attributes: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the exchange state
    pub fn update_state(&mut self, new_state: CredentialExchangeState) {
        self.state = new_state;
        self.updated_at = Utc::now();
    }

    /// Set connection ID
    pub fn set_connection_id(&mut self, connection_id: String) {
        self.connection_id = Some(connection_id);
        self.updated_at = Utc::now();
    }

    /// Set error message and move to Abandoned state
    pub fn set_error(&mut self, error: String) {
        self.error_message = Some(error);
        self.state = CredentialExchangeState::Abandoned;
        self.updated_at = Utc::now();
    }

    /// Check if exchange is complete
    pub fn is_done(&self) -> bool {
        self.state == CredentialExchangeState::Done
    }

    /// Check if exchange is active (not terminal)
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// Trait for credential exchange repository operations
#[async_trait]
pub trait CredentialExchangeRepositoryTrait: Send + Sync {
    /// Save a new credential exchange record
    async fn save(&self, record: &CredentialExchangeRecord) -> Result<()>;

    /// Update an existing credential exchange record
    async fn update(&self, record: &CredentialExchangeRecord) -> Result<()>;

    /// Find exchange by ID
    async fn find_by_id(&self, id: &str) -> Result<Option<CredentialExchangeRecord>>;

    /// Find exchange by thread ID
    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<CredentialExchangeRecord>>;

    /// Find exchanges by state
    async fn find_by_state(
        &self,
        state: CredentialExchangeState,
    ) -> Result<Vec<CredentialExchangeRecord>>;

    /// Find exchanges by role
    async fn find_by_role(
        &self,
        role: CredentialExchangeRole,
    ) -> Result<Vec<CredentialExchangeRecord>>;

    /// Find exchanges by connection ID
    async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Vec<CredentialExchangeRecord>>;

    /// Delete exchange by ID
    async fn delete(&self, id: &str) -> Result<()>;

    /// Get all exchanges
    async fn get_all(&self) -> Result<Vec<CredentialExchangeRecord>>;
}

/// In-memory credential exchange repository
pub struct CredentialExchangeRepository {
    records: Arc<RwLock<HashMap<String, CredentialExchangeRecord>>>,
}

impl CredentialExchangeRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for CredentialExchangeRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialExchangeRepositoryTrait for CredentialExchangeRepository {
    async fn save(&self, record: &CredentialExchangeRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(CredentialError::AlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &CredentialExchangeRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(CredentialError::NotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Option<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.values().find(|r| r.thread_id == thread_id).cloned())
    }

    async fn find_by_state(
        &self,
        state: CredentialExchangeState,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.state == state)
            .cloned()
            .collect())
    }

    async fn find_by_role(
        &self,
        role: CredentialExchangeRole,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.role == role)
            .cloned()
            .collect())
    }

    async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Vec<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .filter(|r| r.connection_id.as_deref() == Some(connection_id))
            .cloned()
            .collect())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;

        if records.remove(id).is_none() {
            return Err(CredentialError::NotFound(id.to_string()));
        }

        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<CredentialExchangeRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(
        thread_id: &str,
        role: CredentialExchangeRole,
        state: CredentialExchangeState,
    ) -> CredentialExchangeRecord {
        CredentialExchangeRecord::new(role, state, thread_id.to_string())
    }

    #[tokio::test]
    async fn test_save_and_find_by_id() {
        let repo = CredentialExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        repo.save(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_save_duplicate() {
        let repo = CredentialExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        repo.save(&record).await.unwrap();
        let result = repo.save(&record).await;

        assert!(result.is_err());
        match result {
            Err(CredentialError::AlreadyExists(_)) => {}
            _ => panic!("Expected AlreadyExists error"),
        }
    }

    #[tokio::test]
    async fn test_update() {
        let repo = CredentialExchangeRepository::new();
        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        repo.save(&record).await.unwrap();

        record.update_state(CredentialExchangeState::RequestReceived);
        repo.update(&record).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap().unwrap();
        assert_eq!(found.state, CredentialExchangeState::RequestReceived);
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let repo = CredentialExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        let result = repo.update(&record).await;

        assert!(result.is_err());
        match result {
            Err(CredentialError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_find_by_thread_id() {
        let repo = CredentialExchangeRepository::new();
        let record = create_test_record(
            "thread-123",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
        );

        repo.save(&record).await.unwrap();

        let found = repo.find_by_thread_id("thread-123").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().thread_id, "thread-123");
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let repo = CredentialExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        let record2 = create_test_record(
            "thread-2",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        let record3 = create_test_record(
            "thread-3",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();
        repo.save(&record3).await.unwrap();

        let found = repo
            .find_by_state(CredentialExchangeState::OfferSent)
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
    }

    #[tokio::test]
    async fn test_find_by_role() {
        let repo = CredentialExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        let record2 = create_test_record(
            "thread-2",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo
            .find_by_role(CredentialExchangeRole::Issuer)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, CredentialExchangeRole::Issuer);
    }

    #[tokio::test]
    async fn test_find_by_connection_id() {
        let repo = CredentialExchangeRepository::new();

        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        record.set_connection_id("conn-abc".to_string());

        repo.save(&record).await.unwrap();

        let found = repo.find_by_connection_id("conn-abc").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].connection_id, Some("conn-abc".to_string()));
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = CredentialExchangeRepository::new();
        let record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        repo.save(&record).await.unwrap();
        repo.delete(&record.id).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let repo = CredentialExchangeRepository::new();

        let result = repo.delete("non-existent").await;

        assert!(result.is_err());
        match result {
            Err(CredentialError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_all() {
        let repo = CredentialExchangeRepository::new();

        let record1 = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        let record2 = create_test_record(
            "thread-2",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
        );

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let all = repo.get_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_record_state_update() {
        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );

        let initial_updated_at = record.updated_at;

        record.update_state(CredentialExchangeState::RequestReceived);

        assert_eq!(record.state, CredentialExchangeState::RequestReceived);
        assert!(record.updated_at >= initial_updated_at);
    }

    #[test]
    fn test_record_set_error() {
        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::RequestSent,
        );

        record.set_error("Connection timeout".to_string());

        assert_eq!(record.state, CredentialExchangeState::Abandoned);
        assert_eq!(record.error_message, Some("Connection timeout".to_string()));
    }

    #[test]
    fn test_is_done() {
        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Holder,
            CredentialExchangeState::CredentialReceived,
        );

        assert!(!record.is_done());

        record.update_state(CredentialExchangeState::Done);
        assert!(record.is_done());
    }

    #[test]
    fn test_serialization() {
        let mut record = create_test_record(
            "thread-1",
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
        );
        record.schema_id = Some("schema:1".to_string());
        record.cred_def_id = Some("cred:1".to_string());

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("thread_id"));
        assert!(json.contains("schema_id"));
        assert!(json.contains("cred_def_id"));

        let deserialized: CredentialExchangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.thread_id, record.thread_id);
        assert_eq!(deserialized.schema_id, record.schema_id);
        assert_eq!(deserialized.cred_def_id, record.cred_def_id);
    }
}
