use async_trait::async_trait;
use std::collections::HashMap;

use crate::domain::{OutOfBandRole, OutOfBandState};
use crate::error::{OutOfBandError, Result};
use crate::repository::oob_record::OutOfBandRecord;

/// Repository for persisting and querying Out-of-Band records
///
/// This provides CRUD operations and query methods for OutOfBandRecord.
/// It abstracts the storage layer to allow different implementations.
#[async_trait]
pub trait OutOfBandRepositoryTrait: Send + Sync {
    /// Save a new Out-of-Band record
    async fn save(&self, record: &OutOfBandRecord) -> Result<()>;

    /// Update an existing Out-of-Band record
    async fn update(&self, record: &OutOfBandRecord) -> Result<()>;

    /// Find a record by its ID
    async fn find_by_id(&self, id: &str) -> Result<Option<OutOfBandRecord>>;

    /// Delete a record by its ID
    async fn delete(&self, id: &str) -> Result<()>;

    /// Find records by tags (AND query)
    async fn find_by_tags(&self, tags: &HashMap<String, String>) -> Result<Vec<OutOfBandRecord>>;

    /// Find a record by invitation ID and role
    async fn find_by_invitation_id(
        &self,
        invitation_id: &str,
        role: OutOfBandRole,
    ) -> Result<Option<OutOfBandRecord>>;

    /// Find records by recipient key fingerprint
    async fn find_by_recipient_key(
        &self,
        recipient_key_fingerprint: &str,
    ) -> Result<Vec<OutOfBandRecord>>;

    /// Find records by thread ID
    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Vec<OutOfBandRecord>>;

    /// Find all records with a specific state
    async fn find_by_state(&self, state: OutOfBandState) -> Result<Vec<OutOfBandRecord>>;

    /// Find all records with a specific role
    async fn find_by_role(&self, role: OutOfBandRole) -> Result<Vec<OutOfBandRecord>>;

    /// Get all records
    async fn get_all(&self) -> Result<Vec<OutOfBandRecord>>;

    /// Check if a record exists
    async fn exists(&self, id: &str) -> Result<bool>;
}

/// In-memory implementation of OutOfBandRepository for testing
///
/// This provides a simple HashMap-based storage for development and testing.
/// Production code should use a proper storage backend (Askar, etc.)
pub struct OutOfBandRepository {
    records: tokio::sync::RwLock<HashMap<String, OutOfBandRecord>>,
}

impl OutOfBandRepository {
    /// Create a new in-memory repository
    pub fn new() -> Self {
        Self {
            records: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Helper to match tags against a record
    fn matches_tags(record: &OutOfBandRecord, tags: &HashMap<String, String>) -> bool {
        for (key, value) in tags {
            match key.as_str() {
                "role" => {
                    let role_str = match record.role {
                        OutOfBandRole::Sender => "sender",
                        OutOfBandRole::Receiver => "receiver",
                    };
                    if role_str != value {
                        return false;
                    }
                }
                "state" => {
                    let state_str = match record.state {
                        OutOfBandState::Initial => "initial",
                        OutOfBandState::AwaitResponse => "await-response",
                        OutOfBandState::PrepareResponse => "prepare-response",
                        OutOfBandState::Done => "done",
                    };
                    if state_str != value {
                        return false;
                    }
                }
                "invitationId" => {
                    if record.tags.invitation_id != *value {
                        return false;
                    }
                }
                "threadId" => {
                    if record.tags.thread_id.as_deref() != Some(value.as_str()) {
                        return false;
                    }
                }
                _ => {
                    // Unknown tag key
                    return false;
                }
            }
        }
        true
    }
}

impl Default for OutOfBandRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutOfBandRepositoryTrait for OutOfBandRepository {
    async fn save(&self, record: &OutOfBandRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if records.contains_key(&record.id) {
            return Err(OutOfBandError::RecordAlreadyExists(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn update(&self, record: &OutOfBandRecord) -> Result<()> {
        let mut records = self.records.write().await;

        if !records.contains_key(&record.id) {
            return Err(OutOfBandError::RecordNotFound(record.id.clone()));
        }

        records.insert(record.id.clone(), record.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<OutOfBandRecord>> {
        let records = self.records.read().await;
        Ok(records.get(id).cloned())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let mut records = self.records.write().await;

        if records.remove(id).is_none() {
            return Err(OutOfBandError::RecordNotFound(id.to_string()));
        }

        Ok(())
    }

    async fn find_by_tags(&self, tags: &HashMap<String, String>) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;

        let results = records
            .values()
            .filter(|record| Self::matches_tags(record, tags))
            .cloned()
            .collect();

        Ok(results)
    }

    async fn find_by_invitation_id(
        &self,
        invitation_id: &str,
        role: OutOfBandRole,
    ) -> Result<Option<OutOfBandRecord>> {
        let records = self.records.read().await;

        let result = records
            .values()
            .find(|record| record.tags.invitation_id == invitation_id && record.role == role)
            .cloned();

        Ok(result)
    }

    async fn find_by_recipient_key(
        &self,
        recipient_key_fingerprint: &str,
    ) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;

        let results = records
            .values()
            .filter(|record| {
                record
                    .tags
                    .recipient_key_fingerprints
                    .contains(&recipient_key_fingerprint.to_string())
            })
            .cloned()
            .collect();

        Ok(results)
    }

    async fn find_by_thread_id(&self, thread_id: &str) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;

        let results = records
            .values()
            .filter(|record| {
                record
                    .tags
                    .thread_id
                    .as_ref()
                    .map(|tid| tid == thread_id)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        Ok(results)
    }

    async fn find_by_state(&self, state: OutOfBandState) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;

        let results = records
            .values()
            .filter(|record| record.state == state)
            .cloned()
            .collect();

        Ok(results)
    }

    async fn find_by_role(&self, role: OutOfBandRole) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;

        let results = records
            .values()
            .filter(|record| record.role == role)
            .cloned()
            .collect();

        Ok(results)
    }

    async fn get_all(&self) -> Result<Vec<OutOfBandRecord>> {
        let records = self.records.read().await;
        Ok(records.values().cloned().collect())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        let records = self.records.read().await;
        Ok(records.contains_key(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{InlineService, OutOfBandInvitation, OutOfBandService};

    fn create_test_invitation() -> OutOfBandInvitation {
        OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
            .with_label("Test Agent".to_string())
    }

    fn create_test_record() -> OutOfBandRecord {
        let invitation = create_test_invitation();
        OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
    }

    #[tokio::test]
    async fn test_save_and_find_by_id() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();

        // Save
        repo.save(&record).await.unwrap();

        // Find
        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_save_duplicate_fails() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();

        repo.save(&record).await.unwrap();

        // Try to save again
        let result = repo.save(&record).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::RecordAlreadyExists(_)
        ));
    }

    #[tokio::test]
    async fn test_update() {
        let repo = OutOfBandRepository::new();
        let mut record = create_test_record();

        repo.save(&record).await.unwrap();

        // Update state
        record.update_state(OutOfBandState::Done);
        repo.update(&record).await.unwrap();

        // Verify update
        let found = repo.find_by_id(&record.id).await.unwrap().unwrap();
        assert_eq!(found.state, OutOfBandState::Done);
    }

    #[tokio::test]
    async fn test_update_nonexistent_fails() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();

        let result = repo.update(&record).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::RecordNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();

        repo.save(&record).await.unwrap();
        repo.delete(&record.id).await.unwrap();

        let found = repo.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_fails() {
        let repo = OutOfBandRepository::new();

        let result = repo.delete("nonexistent-id").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::RecordNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_exists() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();

        assert!(!repo.exists(&record.id).await.unwrap());

        repo.save(&record).await.unwrap();
        assert!(repo.exists(&record.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_find_by_invitation_id() {
        let repo = OutOfBandRepository::new();
        let record = create_test_record();
        let invitation_id = record.invitation.id.clone();

        repo.save(&record).await.unwrap();

        // Find by invitation ID and role
        let found = repo
            .find_by_invitation_id(&invitation_id, OutOfBandRole::Sender)
            .await
            .unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().invitation.id, invitation_id);

        // Should not find with wrong role
        let not_found = repo
            .find_by_invitation_id(&invitation_id, OutOfBandRole::Receiver)
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_find_by_recipient_key() {
        let repo = OutOfBandRepository::new();

        // Create invitation with inline service
        let service = InlineService::new(
            "#inline-0".to_string(),
            vec!["did:key:z6MkpTHR123".to_string()],
            vec![],
            "https://example.com".to_string(),
        );

        let invitation = OutOfBandInvitation::new(vec![OutOfBandService::Inline(service.clone())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);

        repo.save(&record).await.unwrap();

        // Find by recipient key fingerprint
        let fingerprint = &record.tags.recipient_key_fingerprints[0];
        let found = repo.find_by_recipient_key(fingerprint).await.unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, record.id);
    }

    #[tokio::test]
    async fn test_find_by_state() {
        let repo = OutOfBandRepository::new();

        let mut record1 = create_test_record();
        record1.update_state(OutOfBandState::AwaitResponse);

        let mut record2 = create_test_record();
        record2.id = "record-2".to_string();
        record2.update_state(OutOfBandState::Done);

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        // Find by state
        let await_response_records = repo
            .find_by_state(OutOfBandState::AwaitResponse)
            .await
            .unwrap();
        assert_eq!(await_response_records.len(), 1);
        assert_eq!(await_response_records[0].id, record1.id);

        let done_records = repo.find_by_state(OutOfBandState::Done).await.unwrap();
        assert_eq!(done_records.len(), 1);
        assert_eq!(done_records[0].id, record2.id);
    }

    #[tokio::test]
    async fn test_find_by_role() {
        let repo = OutOfBandRepository::new();

        let record1 = create_test_record(); // Sender
        let mut record2 = create_test_record();
        record2.id = "record-2".to_string();
        record2.role = OutOfBandRole::Receiver;
        record2.tags.role = OutOfBandRole::Receiver;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let senders = repo.find_by_role(OutOfBandRole::Sender).await.unwrap();
        assert_eq!(senders.len(), 1);
        assert_eq!(senders[0].id, record1.id);

        let receivers = repo.find_by_role(OutOfBandRole::Receiver).await.unwrap();
        assert_eq!(receivers.len(), 1);
        assert_eq!(receivers[0].id, record2.id);
    }

    #[tokio::test]
    async fn test_find_by_tags() {
        let repo = OutOfBandRepository::new();

        let mut record1 = create_test_record();
        record1.update_state(OutOfBandState::AwaitResponse);

        let mut record2 = create_test_record();
        record2.id = "record-2".to_string();
        record2.role = OutOfBandRole::Receiver;
        record2.tags.role = OutOfBandRole::Receiver;

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        // Query by multiple tags
        let mut tags = HashMap::new();
        tags.insert("role".to_string(), "sender".to_string());
        tags.insert("state".to_string(), "await-response".to_string());

        let found = repo.find_by_tags(&tags).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, record1.id);
    }

    #[tokio::test]
    async fn test_find_by_thread_id() {
        let repo = OutOfBandRepository::new();

        let mut record1 = create_test_record();
        record1.tags.thread_id = Some("thread-123".to_string());

        let mut record2 = create_test_record();
        record2.id = "record-2".to_string();
        record2.tags.thread_id = Some("thread-456".to_string());

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let found = repo.find_by_thread_id("thread-123").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, record1.id);
    }

    #[tokio::test]
    async fn test_get_all() {
        let repo = OutOfBandRepository::new();

        let record1 = create_test_record();
        let mut record2 = create_test_record();
        record2.id = "record-2".to_string();

        repo.save(&record1).await.unwrap();
        repo.save(&record2).await.unwrap();

        let all = repo.get_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_find_nonexistent() {
        let repo = OutOfBandRepository::new();

        let found = repo.find_by_id("nonexistent").await.unwrap();
        assert!(found.is_none());
    }
}
