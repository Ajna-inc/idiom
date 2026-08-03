//! Message Queue Repository for Message Pickup Protocol V2
//!
//! Provides storage and retrieval of queued messages at a mediator.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::{QueuedMessage, QueuedMessageState};
use crate::error::Result;

/// Repository trait for message queue operations
#[async_trait]
pub trait MessageQueueRepositoryTrait: Send + Sync {
    /// Add a message to the queue
    async fn add_message(&self, message: QueuedMessage) -> Result<String>;

    /// Get count of pending messages for a connection
    async fn get_pending_count(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<u64>;

    /// Get total byte count of pending messages
    async fn get_total_bytes(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<u64>;

    /// Get the oldest message time for a connection
    async fn get_oldest_message_time(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<Option<DateTime<Utc>>>;

    /// Take messages from queue (marks them as sending)
    /// Returns up to `limit` messages, oldest first
    async fn take_from_queue(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
        limit: u32,
    ) -> Result<Vec<QueuedMessage>>;

    /// Remove messages from queue (after successful acknowledgment)
    async fn remove_messages(&self, message_ids: &[String]) -> Result<()>;

    /// Return messages to pending state (delivery failed)
    async fn return_to_pending(&self, message_ids: &[String]) -> Result<()>;

    /// Find a message by ID
    async fn find_by_id(&self, message_id: &str) -> Result<Option<QueuedMessage>>;

    /// Clear all messages for a connection (for cleanup)
    async fn clear_connection(&self, connection_id: &str) -> Result<u64>;

    /// Delete messages older than `max_age` (across all connections).
    /// Returns the number deleted. Used by the mediator's periodic TTL task
    /// to keep stale undelivered messages from pinning the per-connection cap.
    async fn delete_expired(&self, max_age: std::time::Duration) -> Result<u64> {
        // Default no-op; in-memory + storage-backed override.
        let _ = max_age;
        Ok(0)
    }

    /// Delete messages older than `max_age` for one connection only.
    /// Used by the forward path's cap-relief retry: before rejecting a
    /// forward with "queue full", try aging out stale messages.
    async fn delete_expired_for_connection(
        &self,
        connection_id: &str,
        max_age: std::time::Duration,
    ) -> Result<u64> {
        // Default no-op; in-memory + storage-backed override.
        let _ = (connection_id, max_age);
        Ok(0)
    }
}

/// In-memory implementation of the message queue repository
pub struct InMemoryMessageQueueRepository {
    /// Messages stored by ID
    messages: Arc<RwLock<HashMap<String, QueuedMessage>>>,
    /// Index by connection_id for faster lookups
    by_connection: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemoryMessageQueueRepository {
    /// Create a new in-memory repository
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(HashMap::new())),
            by_connection: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryMessageQueueRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessageQueueRepositoryTrait for InMemoryMessageQueueRepository {
    async fn add_message(&self, message: QueuedMessage) -> Result<String> {
        let id = message.id.clone();
        let connection_id = message.connection_id.clone();

        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;

        messages.insert(id.clone(), message);
        by_connection
            .entry(connection_id)
            .or_default()
            .push(id.clone());

        Ok(id)
    }

    async fn get_pending_count(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<u64> {
        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;

        let count = by_connection
            .get(connection_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| messages.get(id))
                    .filter(|m| m.state == QueuedMessageState::Pending)
                    .filter(|m| m.matches_recipient_key(recipient_key))
                    .count() as u64
            })
            .unwrap_or(0);

        Ok(count)
    }

    async fn get_total_bytes(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<u64> {
        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;

        let bytes = by_connection
            .get(connection_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| messages.get(id))
                    .filter(|m| m.state == QueuedMessageState::Pending)
                    .filter(|m| m.matches_recipient_key(recipient_key))
                    .map(|m| m.byte_size() as u64)
                    .sum()
            })
            .unwrap_or(0);

        Ok(bytes)
    }

    async fn get_oldest_message_time(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<Option<DateTime<Utc>>> {
        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;

        let oldest = by_connection.get(connection_id).and_then(|ids| {
            ids.iter()
                .filter_map(|id| messages.get(id))
                .filter(|m| m.state == QueuedMessageState::Pending)
                .filter(|m| m.matches_recipient_key(recipient_key))
                .map(|m| m.received_at)
                .min()
        });

        Ok(oldest)
    }

    async fn take_from_queue(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
        limit: u32,
    ) -> Result<Vec<QueuedMessage>> {
        let mut messages = self.messages.write().await;
        let by_connection = self.by_connection.read().await;

        let Some(ids) = by_connection.get(connection_id) else {
            return Ok(vec![]);
        };

        // Get pending messages sorted by received_at
        let mut pending: Vec<_> = ids
            .iter()
            .filter_map(|id| messages.get(id).cloned())
            .filter(|m| m.state == QueuedMessageState::Pending)
            .filter(|m| m.matches_recipient_key(recipient_key))
            .collect();

        pending.sort_by_key(|a| a.received_at);

        // Take up to limit and mark as sending
        let taken: Vec<_> = pending.into_iter().take(limit as usize).collect();

        for msg in &taken {
            if let Some(stored) = messages.get_mut(&msg.id) {
                stored.mark_sending();
            }
        }

        Ok(taken)
    }

    async fn remove_messages(&self, message_ids: &[String]) -> Result<()> {
        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;

        for id in message_ids {
            if let Some(msg) = messages.remove(id) {
                if let Some(ids) = by_connection.get_mut(&msg.connection_id) {
                    ids.retain(|i| i != id);
                }
            }
        }

        Ok(())
    }

    async fn return_to_pending(&self, message_ids: &[String]) -> Result<()> {
        let mut messages = self.messages.write().await;

        for id in message_ids {
            if let Some(msg) = messages.get_mut(id) {
                msg.mark_pending();
            }
        }

        Ok(())
    }

    async fn find_by_id(&self, message_id: &str) -> Result<Option<QueuedMessage>> {
        let messages = self.messages.read().await;
        Ok(messages.get(message_id).cloned())
    }

    async fn clear_connection(&self, connection_id: &str) -> Result<u64> {
        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;

        let count = if let Some(ids) = by_connection.remove(connection_id) {
            let removed = ids.len() as u64;
            for id in ids {
                messages.remove(&id);
            }
            removed
        } else {
            0
        };

        Ok(count)
    }

    async fn delete_expired(&self, max_age: std::time::Duration) -> Result<u64> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(7));

        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;

        let expired: Vec<(String, String)> = messages
            .values()
            .filter(|m| m.received_at < cutoff)
            .map(|m| (m.id.clone(), m.connection_id.clone()))
            .collect();

        for (id, conn) in &expired {
            messages.remove(id);
            if let Some(ids) = by_connection.get_mut(conn) {
                ids.retain(|i| i != id);
            }
        }

        Ok(expired.len() as u64)
    }

    async fn delete_expired_for_connection(
        &self,
        connection_id: &str,
        max_age: std::time::Duration,
    ) -> Result<u64> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(7));

        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;

        let Some(ids) = by_connection.get(connection_id).cloned() else {
            return Ok(0);
        };

        let expired_ids: Vec<String> = ids
            .iter()
            .filter_map(|id| messages.get(id))
            .filter(|m| m.received_at < cutoff)
            .map(|m| m.id.clone())
            .collect();

        for id in &expired_ids {
            messages.remove(id);
        }
        if let Some(conn_ids) = by_connection.get_mut(connection_id) {
            conn_ids.retain(|i| !expired_ids.contains(i));
        }

        Ok(expired_ids.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_count() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg = QueuedMessage::new(
            "conn-1".to_string(),
            vec!["key1".to_string()],
            "{}".to_string(),
        );
        repo.add_message(msg).await.unwrap();

        let count = repo.get_pending_count("conn-1", None).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_recipient_key_filter() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg1 = QueuedMessage::new(
            "conn-1".to_string(),
            vec!["key1".to_string()],
            "{}".to_string(),
        );
        let msg2 = QueuedMessage::new(
            "conn-1".to_string(),
            vec!["key2".to_string()],
            "{}".to_string(),
        );
        repo.add_message(msg1).await.unwrap();
        repo.add_message(msg2).await.unwrap();

        let count_all = repo.get_pending_count("conn-1", None).await.unwrap();
        assert_eq!(count_all, 2);

        let count_key1 = repo
            .get_pending_count("conn-1", Some("key1"))
            .await
            .unwrap();
        assert_eq!(count_key1, 1);
    }

    #[tokio::test]
    async fn test_take_and_remove() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg1 = QueuedMessage::new("conn-1".to_string(), vec![], "msg1".to_string());
        let msg2 = QueuedMessage::new("conn-1".to_string(), vec![], "msg2".to_string());
        repo.add_message(msg1).await.unwrap();
        repo.add_message(msg2).await.unwrap();

        // Take messages
        let taken = repo.take_from_queue("conn-1", None, 10).await.unwrap();
        assert_eq!(taken.len(), 2);

        // They should now be in sending state, so pending count is 0
        let count = repo.get_pending_count("conn-1", None).await.unwrap();
        assert_eq!(count, 0);

        // Remove them
        let ids: Vec<_> = taken.iter().map(|m| m.id.clone()).collect();
        repo.remove_messages(&ids).await.unwrap();

        // Try to take again - should be empty
        let taken2 = repo.take_from_queue("conn-1", None, 10).await.unwrap();
        assert!(taken2.is_empty());
    }

    #[tokio::test]
    async fn test_return_to_pending() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        let id = repo.add_message(msg).await.unwrap();

        // Take it
        let taken = repo.take_from_queue("conn-1", None, 1).await.unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(repo.get_pending_count("conn-1", None).await.unwrap(), 0);

        // Return to pending
        repo.return_to_pending(std::slice::from_ref(&id))
            .await
            .unwrap();
        assert_eq!(repo.get_pending_count("conn-1", None).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_oldest_message_time() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg1 = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let msg2 = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());

        let time1 = msg1.received_at;
        repo.add_message(msg1).await.unwrap();
        repo.add_message(msg2).await.unwrap();

        let oldest = repo.get_oldest_message_time("conn-1", None).await.unwrap();
        assert_eq!(oldest, Some(time1));
    }

    /// Fix 1C: delete_expired across all connections.
    #[tokio::test]
    async fn delete_expired_periodic() {
        let repo = InMemoryMessageQueueRepository::new();
        // Three messages, two backdated.
        let mut m_old1 = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        m_old1.received_at = chrono::Utc::now() - chrono::Duration::days(8);
        let mut m_old2 = QueuedMessage::new("conn-2".to_string(), vec![], "{}".to_string());
        m_old2.received_at = chrono::Utc::now() - chrono::Duration::days(10);
        let m_fresh = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        repo.add_message(m_old1).await.unwrap();
        repo.add_message(m_old2).await.unwrap();
        repo.add_message(m_fresh).await.unwrap();

        let deleted = repo
            .delete_expired(std::time::Duration::from_secs(7 * 86_400))
            .await
            .unwrap();
        assert_eq!(
            deleted, 2,
            "two messages older than 7 days should be deleted"
        );

        // Only the fresh one remains.
        assert_eq!(repo.get_pending_count("conn-1", None).await.unwrap(), 1);
        assert_eq!(repo.get_pending_count("conn-2", None).await.unwrap(), 0);
    }

    /// Fix 1A's cap-relief path: per-connection variant only touches one connection.
    #[tokio::test]
    async fn delete_expired_for_connection_isolates() {
        let repo = InMemoryMessageQueueRepository::new();
        let mut m_old_a = QueuedMessage::new("conn-A".to_string(), vec![], "a".to_string());
        m_old_a.received_at = chrono::Utc::now() - chrono::Duration::days(10);
        let mut m_old_b = QueuedMessage::new("conn-B".to_string(), vec![], "b".to_string());
        m_old_b.received_at = chrono::Utc::now() - chrono::Duration::days(10);
        repo.add_message(m_old_a).await.unwrap();
        repo.add_message(m_old_b).await.unwrap();

        let deleted = repo
            .delete_expired_for_connection("conn-A", std::time::Duration::from_secs(7 * 86_400))
            .await
            .unwrap();
        assert_eq!(deleted, 1, "only conn-A's message removed");
        assert_eq!(repo.get_pending_count("conn-A", None).await.unwrap(), 0);
        assert_eq!(repo.get_pending_count("conn-B", None).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_clear_connection() {
        let repo = InMemoryMessageQueueRepository::new();

        let msg1 = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        let msg2 = QueuedMessage::new("conn-1".to_string(), vec![], "{}".to_string());
        let msg3 = QueuedMessage::new("conn-2".to_string(), vec![], "{}".to_string());
        repo.add_message(msg1).await.unwrap();
        repo.add_message(msg2).await.unwrap();
        repo.add_message(msg3).await.unwrap();

        let removed = repo.clear_connection("conn-1").await.unwrap();
        assert_eq!(removed, 2);

        assert_eq!(repo.get_pending_count("conn-1", None).await.unwrap(), 0);
        assert_eq!(repo.get_pending_count("conn-2", None).await.unwrap(), 1);
    }
}
