//! Storage-backed message queue repository
//!
//! Persists queued messages using the StorageProvider trait,
//! enabling message queue to survive across restarts.

use crate::domain::{QueuedMessage, QueuedMessageState};
use crate::error::{PickupError, Result};
use agent_core::traits::{Query, Record, StorageProvider};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::MessageQueueRepositoryTrait;

/// Storage category for queued messages
const MESSAGE_QUEUE_CATEGORY: &str = "message_queue";

/// Storage-backed message queue repository that persists to Askar storage.
///
/// This implementation:
/// - Persists all queued messages to durable storage (SQLite via Askar)
/// - Maintains an in-memory cache with dual indexing for fast lookups
/// - Loads existing records on startup
/// - Survives across process restarts
pub struct StorageBackedMessageQueueRepository {
    /// Storage provider for persistence
    storage: Arc<dyn StorageProvider>,
    /// Messages stored by ID (populated from storage on first access)
    messages: Arc<RwLock<Option<HashMap<String, QueuedMessage>>>>,
    /// Index by connection_id for faster lookups
    by_connection: Arc<RwLock<Option<HashMap<String, Vec<String>>>>>,
}

impl StorageBackedMessageQueueRepository {
    /// Create a new storage-backed message queue repository
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            messages: Arc::new(RwLock::new(None)),
            by_connection: Arc::new(RwLock::new(None)),
        }
    }

    /// Warm up the cache: load all messages from storage and reset orphaned
    /// "Sending" messages to "Pending" (crash recovery).
    pub async fn warm_up(&self) -> Result<usize> {
        self.ensure_loaded().await?;
        let messages = self.messages.read().await;
        Ok(messages.as_ref().map_or(0, |m| m.len()))
    }

    /// Delete messages older than `max_age`. Returns the number deleted.
    pub async fn delete_expired(&self, max_age: std::time::Duration) -> Result<usize> {
        self.ensure_loaded().await?;

        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(7));

        // Collect expired IDs under read lock
        let expired_ids: Vec<String> = {
            let messages = self.messages.read().await;
            messages.as_ref().map_or(Vec::new(), |m| {
                m.values()
                    .filter(|msg| msg.received_at < cutoff)
                    .map(|msg| msg.id.clone())
                    .collect()
            })
        };

        if expired_ids.is_empty() {
            return Ok(0);
        }

        // Delete under write lock
        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_mut().unwrap();

        for id in &expired_ids {
            let _ = self.storage.delete(MESSAGE_QUEUE_CATEGORY, id).await;
            if let Some(msg) = msg_map.remove(id) {
                if let Some(ids) = conn_map.get_mut(&msg.connection_id) {
                    ids.retain(|i| i != id);
                }
            }
        }

        Ok(expired_ids.len())
    }

    /// Ensure caches are populated from storage
    async fn ensure_loaded(&self) -> Result<()> {
        // Fast path: read lock to check if already loaded (non-blocking for concurrent ops)
        {
            let messages = self.messages.read().await;
            if messages.is_some() {
                return Ok(());
            }
        }
        // Slow path: write lock only when truly uninitialized
        let mut messages = self.messages.write().await;
        if messages.is_some() {
            return Ok(()); // Another task loaded while we waited for write lock
        }

        let query = Query::new();
        let records = self
            .storage
            .find_all(MESSAGE_QUEUE_CATEGORY, &query)
            .await
            .map_err(|e| {
                PickupError::Storage(format!("Failed to load message queue records: {}", e))
            })?;

        let mut msg_map = HashMap::new();
        let mut conn_map: HashMap<String, Vec<String>> = HashMap::new();

        for record in records {
            if let Ok(queued) = serde_json::from_slice::<QueuedMessage>(&record.value) {
                conn_map
                    .entry(queued.connection_id.clone())
                    .or_default()
                    .push(queued.id.clone());
                msg_map.insert(queued.id.clone(), queued);
            }
        }

        // Reset any messages stuck in "Sending" state back to "Pending".
        // These were mid-delivery when the process crashed/restarted.
        let mut orphan_ids = Vec::new();
        for (id, msg) in msg_map.iter_mut() {
            if msg.state == QueuedMessageState::Sending {
                msg.mark_pending();
                orphan_ids.push(id.clone());
            }
        }
        if !orphan_ids.is_empty() {
            tracing::warn!(
                "[MessageQueue] Reset {} orphaned Sending messages to Pending",
                orphan_ids.len()
            );
            // Update storage for each reset message
            for id in &orphan_ids {
                if let Some(msg) = msg_map.get(id) {
                    if let Err(e) = self.update_in_storage(msg).await {
                        tracing::warn!("Failed to reset orphaned message {} in storage: {}", id, e);
                    }
                }
            }
        }

        tracing::info!(
            "[MessageQueue] Loaded {} queued messages from storage",
            msg_map.len()
        );

        *messages = Some(msg_map);
        drop(messages);

        let mut by_connection = self.by_connection.write().await;
        *by_connection = Some(conn_map);

        Ok(())
    }

    /// Build storage tags for a queued message
    fn build_tags(msg: &QueuedMessage) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        tags.insert("connection_id".to_string(), msg.connection_id.clone());
        tags.insert("state".to_string(), msg.state.to_string());
        tags
    }

    /// Persist a message to storage
    async fn persist(&self, msg: &QueuedMessage) -> Result<()> {
        let value = serde_json::to_vec(msg)
            .map_err(|e| PickupError::Storage(format!("Failed to serialize message: {}", e)))?;

        let storage_record =
            Record::new(MESSAGE_QUEUE_CATEGORY, &msg.id, value).with_tags(Self::build_tags(msg));

        self.storage
            .save(&storage_record)
            .await
            .map_err(|e| PickupError::Storage(format!("Failed to store queued message: {}", e)))?;

        Ok(())
    }

    /// Update a message in storage
    async fn update_in_storage(&self, msg: &QueuedMessage) -> Result<()> {
        let value = serde_json::to_vec(msg)
            .map_err(|e| PickupError::Storage(format!("Failed to serialize message: {}", e)))?;

        let storage_record =
            Record::new(MESSAGE_QUEUE_CATEGORY, &msg.id, value).with_tags(Self::build_tags(msg));

        self.storage
            .update(&storage_record)
            .await
            .map_err(|e| PickupError::Storage(format!("Failed to update queued message: {}", e)))?;

        Ok(())
    }

    /// Delete a message from storage
    async fn delete_from_storage(&self, id: &str) -> Result<()> {
        self.storage
            .delete(MESSAGE_QUEUE_CATEGORY, id)
            .await
            .map_err(|e| PickupError::Storage(format!("Failed to delete queued message: {}", e)))?;
        Ok(())
    }
}

#[async_trait]
impl MessageQueueRepositoryTrait for StorageBackedMessageQueueRepository {
    async fn add_message(&self, message: QueuedMessage) -> Result<String> {
        self.ensure_loaded().await?;

        let id = message.id.clone();
        let connection_id = message.connection_id.clone();

        // Persist to storage first
        self.persist(&message).await?;

        // Then update caches
        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_mut().unwrap();

        msg_map.insert(id.clone(), message);
        conn_map
            .entry(connection_id.clone())
            .or_default()
            .push(id.clone());

        let total_msgs = msg_map.len();
        let conn_msgs = conn_map.get(&connection_id).map(|v| v.len()).unwrap_or(0);
        tracing::info!(
            message_id = %id,
            connection_id = %connection_id,
            total_in_cache = total_msgs,
            for_this_connection = conn_msgs,
            total_connections = conn_map.len(),
            "[MessageQueue] Message ADDED to cache"
        );

        Ok(id)
    }

    async fn get_pending_count(
        &self,
        connection_id: &str,
        recipient_key: Option<&str>,
    ) -> Result<u64> {
        self.ensure_loaded().await?;

        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;
        let msg_map = messages.as_ref().unwrap();
        let conn_map = by_connection.as_ref().unwrap();

        let count = conn_map
            .get(connection_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| msg_map.get(id))
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
        self.ensure_loaded().await?;

        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;
        let msg_map = messages.as_ref().unwrap();
        let conn_map = by_connection.as_ref().unwrap();

        let bytes = conn_map
            .get(connection_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| msg_map.get(id))
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
        self.ensure_loaded().await?;

        let messages = self.messages.read().await;
        let by_connection = self.by_connection.read().await;
        let msg_map = messages.as_ref().unwrap();
        let conn_map = by_connection.as_ref().unwrap();

        let oldest = conn_map.get(connection_id).and_then(|ids| {
            ids.iter()
                .filter_map(|id| msg_map.get(id))
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
        self.ensure_loaded().await?;

        let mut messages = self.messages.write().await;
        let by_connection = self.by_connection.read().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_ref().unwrap();

        let all_conn_keys: Vec<&String> = conn_map.keys().collect();
        tracing::info!(
            connection_id = %connection_id,
            total_messages = msg_map.len(),
            total_connections = conn_map.len(),
            connection_keys = ?all_conn_keys,
            "[MessageQueue] take_from_queue called"
        );

        let Some(ids) = conn_map.get(connection_id) else {
            tracing::info!(
                connection_id = %connection_id,
                "[MessageQueue] No messages found for connection (not in conn_map)"
            );
            return Ok(vec![]);
        };

        // Get pending messages sorted by received_at
        let mut pending: Vec<_> = ids
            .iter()
            .filter_map(|id| msg_map.get(id).cloned())
            .filter(|m| m.state == QueuedMessageState::Pending)
            .filter(|m| m.matches_recipient_key(recipient_key))
            .collect();

        pending.sort_by_key(|a| a.received_at);

        // Take up to limit and mark as sending in cache
        let taken: Vec<_> = pending.into_iter().take(limit as usize).collect();

        let mut ids_to_persist = Vec::new();
        for msg in &taken {
            if let Some(stored) = msg_map.get_mut(&msg.id) {
                stored.mark_sending();
                ids_to_persist.push(stored.clone());
            }
        }

        // Release locks BEFORE storage I/O to avoid blocking concurrent operations
        drop(by_connection);
        drop(messages);

        // Persist state changes outside the lock
        for msg in &ids_to_persist {
            if let Err(e) = self.update_in_storage(msg).await {
                tracing::warn!("Failed to update message state in storage: {}", e);
            }
        }

        Ok(taken)
    }

    async fn remove_messages(&self, message_ids: &[String]) -> Result<()> {
        self.ensure_loaded().await?;

        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_mut().unwrap();

        for id in message_ids {
            // Delete from storage first
            if let Err(e) = self.delete_from_storage(id).await {
                tracing::warn!("Failed to delete message from storage: {}", e);
            }

            // Then update caches
            if let Some(msg) = msg_map.remove(id) {
                if let Some(ids) = conn_map.get_mut(&msg.connection_id) {
                    ids.retain(|i| i != id);
                }
            }
        }

        Ok(())
    }

    async fn return_to_pending(&self, message_ids: &[String]) -> Result<()> {
        self.ensure_loaded().await?;

        let mut messages = self.messages.write().await;
        let msg_map = messages.as_mut().unwrap();

        for id in message_ids {
            if let Some(msg) = msg_map.get_mut(id) {
                msg.mark_pending();
                // Update state in storage
                if let Err(e) = self.update_in_storage(msg).await {
                    tracing::warn!("Failed to update message state in storage: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn find_by_id(&self, message_id: &str) -> Result<Option<QueuedMessage>> {
        self.ensure_loaded().await?;
        let messages = self.messages.read().await;
        Ok(messages.as_ref().unwrap().get(message_id).cloned())
    }

    async fn clear_connection(&self, connection_id: &str) -> Result<u64> {
        self.ensure_loaded().await?;

        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_mut().unwrap();

        let count = if let Some(ids) = conn_map.remove(connection_id) {
            let removed = ids.len() as u64;
            for id in &ids {
                // Delete from storage
                if let Err(e) = self.delete_from_storage(id).await {
                    tracing::warn!("Failed to delete message from storage: {}", e);
                }
                msg_map.remove(id);
            }
            removed
        } else {
            0
        };

        Ok(count)
    }

    // Forward to the inherent impl so the periodic TTL cleanup task can call
    // through the trait. (See `Self::delete_expired` above for the body.)
    async fn delete_expired(&self, max_age: std::time::Duration) -> Result<u64> {
        StorageBackedMessageQueueRepository::delete_expired(self, max_age)
            .await
            .map(|n| n as u64)
    }

    async fn delete_expired_for_connection(
        &self,
        connection_id: &str,
        max_age: std::time::Duration,
    ) -> Result<u64> {
        self.ensure_loaded().await?;

        let cutoff = chrono::Utc::now()
            - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(7));

        // Collect expired IDs for this connection under read lock
        let expired_ids: Vec<String> = {
            let messages = self.messages.read().await;
            let by_connection = self.by_connection.read().await;
            let Some(ids) = by_connection.as_ref().and_then(|m| m.get(connection_id)) else {
                return Ok(0);
            };
            ids.iter()
                .filter_map(|id| messages.as_ref().and_then(|m| m.get(id)))
                .filter(|msg| msg.received_at < cutoff)
                .map(|msg| msg.id.clone())
                .collect()
        };

        if expired_ids.is_empty() {
            return Ok(0);
        }

        // Delete under write lock
        let mut messages = self.messages.write().await;
        let mut by_connection = self.by_connection.write().await;
        let msg_map = messages.as_mut().unwrap();
        let conn_map = by_connection.as_mut().unwrap();

        for id in &expired_ids {
            let _ = self.storage.delete(MESSAGE_QUEUE_CATEGORY, id).await;
            msg_map.remove(id);
        }
        if let Some(ids) = conn_map.get_mut(connection_id) {
            ids.retain(|i| !expired_ids.contains(i));
        }

        Ok(expired_ids.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    // Storage-backed tests require a real StorageProvider (Askar).
    // Unit tests for the queue trait are in message_queue.rs.
    // Integration tests should be added with a test storage backend.
}
