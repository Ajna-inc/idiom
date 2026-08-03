//! Live Session Manager
//!
//! Manages active WebSocket sessions for live message delivery.
//! Uses DashMap for lock-free concurrent access — register/remove operations
//! don't block concurrent deliveries, critical at 10K+ connected agents.

use dashmap::DashMap;
use tokio::sync::mpsc;

/// Manages live WebSocket sessions for push-based delivery.
///
/// Each connected client registers a channel sender. When a message
/// arrives for that client, the forward service can push it directly
/// through the WebSocket instead of only queuing for pickup.
pub struct LiveSessionManager {
    /// Map of connection_id → WebSocket text-frame sender.
    /// DashMap provides fine-grained per-key locking instead of a global RwLock.
    sessions: DashMap<String, mpsc::Sender<String>>,
    /// Parallel map for binary-frame delivery — used by DCX
    /// (DIDComm Express) opaque-relay to forward encrypted frames to
    /// the recipient tenant's WS without touching the payload.
    /// Register alongside `sessions` at connect time; both indices are
    /// cleaned together on `remove_session`.
    binary_sessions: DashMap<String, mpsc::Sender<Vec<u8>>>,
}

impl LiveSessionManager {
    /// Create a new live session manager
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            binary_sessions: DashMap::new(),
        }
    }

    /// Register a WebSocket session for a connection.
    ///
    /// Returns a receiver that the WS handler should read from
    /// to push messages to the client.
    pub async fn register_session(
        &self,
        connection_id: &str,
        buffer_size: usize,
    ) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(buffer_size);
        self.sessions.insert(connection_id.to_string(), tx);
        tracing::info!(connection_id = connection_id, "Live session registered");
        rx
    }

    /// Register a session with an existing sender channel.
    pub async fn register_session_with_sender(
        &self,
        connection_id: &str,
        sender: mpsc::Sender<String>,
    ) {
        self.sessions.insert(connection_id.to_string(), sender);
        tracing::info!(
            connection_id = connection_id,
            "Live session registered (external sender)"
        );
    }

    /// Register a binary-frame sender for a connection. Called by the
    /// mediator WS handler alongside `register_session_with_sender` so
    /// the DCX opaque-relay path (`try_deliver_binary`) can push
    /// encrypted frames back to the recipient tenant's WS.
    pub async fn register_binary_sender(&self, connection_id: &str, sender: mpsc::Sender<Vec<u8>>) {
        self.binary_sessions
            .insert(connection_id.to_string(), sender);
        tracing::debug!(
            connection_id = connection_id,
            "Live binary session registered"
        );
    }

    /// Remove a session (e.g. when WebSocket disconnects). Clears both
    /// the text and binary indices so a subsequent live-delivery attempt
    /// fails fast rather than pushing into a dead channel.
    pub async fn remove_session(&self, connection_id: &str) {
        let had_text = self.sessions.remove(connection_id).is_some();
        let _ = self.binary_sessions.remove(connection_id);
        if had_text {
            tracing::info!(connection_id = connection_id, "Live session removed");
        }
    }

    /// Check if a connection has an active live session
    pub async fn has_session(&self, connection_id: &str) -> bool {
        self.sessions.contains_key(connection_id)
    }

    /// Try to deliver a message through the live session (non-blocking).
    ///
    /// Returns Ok(()) if the message was sent to the channel,
    /// Err if the session doesn't exist or the channel is full/closed.
    pub async fn try_deliver(
        &self,
        connection_id: &str,
        message: String,
    ) -> std::result::Result<(), String> {
        if let Some(sender) = self.sessions.get(connection_id) {
            sender
                .try_send(message)
                .map_err(|e| format!("Failed to deliver to live session: {}", e))
        } else {
            Err(format!("No live session for connection: {}", connection_id))
        }
    }

    /// Try to deliver a binary frame through the live session
    /// (non-blocking). Used by the DCX opaque-relay path — the
    /// mediator forwards encrypted DIDComm Express frames to the
    /// recipient tenant's WS without touching the ciphertext.
    ///
    /// Returns Ok(()) if the frame was sent to the channel,
    /// Err if the session doesn't have a binary sender or the channel
    /// is full/closed. Callers should treat both errors as "peer not
    /// reachable via DCX" and fall back to their legacy path.
    pub async fn try_deliver_binary(
        &self,
        connection_id: &str,
        frame: Vec<u8>,
    ) -> std::result::Result<(), String> {
        if let Some(sender) = self.binary_sessions.get(connection_id) {
            sender
                .try_send(frame)
                .map_err(|e| format!("Failed to deliver binary to live session: {}", e))
        } else {
            Err(format!(
                "No binary live session for connection: {}",
                connection_id
            ))
        }
    }

    /// Deliver a message via `send().await` with an upper-bound timeout.
    ///
    /// Used by Fix 4B (the queue-first forward path): we want to wait briefly
    /// for the recipient's WS channel to drain rather than drop on transient
    /// fullness, but we must NOT pin the forward task on a misbehaving / dead
    /// channel. After `timeout` we give up on the live push — the queue still
    /// holds the message, so the next HTTP pickup or reconnect-replay covers it.
    pub async fn deliver_or_drop(
        &self,
        connection_id: &str,
        message: String,
        timeout: std::time::Duration,
    ) -> std::result::Result<(), String> {
        let sender = match self.sessions.get(connection_id) {
            Some(s) => s.clone(),
            None => return Err(format!("No live session for connection: {}", connection_id)),
        };

        match tokio::time::timeout(timeout, sender.send(message)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("Live session channel closed: {}", e)),
            Err(_) => Err(format!(
                "Live session channel full beyond {:?} — falling back to queue",
                timeout
            )),
        }
    }

    /// Get the count of active live sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Broadcast a message to ALL live sessions. Returns delivery stats.
    pub async fn broadcast_all(&self, message: String) -> BroadcastResult {
        let mut delivered = 0u32;
        let mut failed = 0u32;
        for entry in self.sessions.iter() {
            match entry.value().try_send(message.clone()) {
                Ok(_) => delivered += 1,
                Err(_) => failed += 1,
            }
        }
        BroadcastResult { delivered, failed }
    }
}

/// Result of a broadcast operation
pub struct BroadcastResult {
    pub delivered: u32,
    pub failed: u32,
}

impl Default for LiveSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_deliver() {
        let manager = LiveSessionManager::new();

        let mut rx = manager.register_session("conn-1", 10).await;
        assert!(manager.has_session("conn-1").await);

        manager
            .try_deliver("conn-1", "hello".to_string())
            .await
            .unwrap();

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg, "hello");
    }

    #[tokio::test]
    async fn test_remove_session() {
        let manager = LiveSessionManager::new();

        let _rx = manager.register_session("conn-1", 10).await;
        assert!(manager.has_session("conn-1").await);

        manager.remove_session("conn-1").await;
        assert!(!manager.has_session("conn-1").await);
    }

    #[tokio::test]
    async fn test_deliver_no_session() {
        let manager = LiveSessionManager::new();
        let result = manager.try_deliver("conn-1", "hello".to_string()).await;
        assert!(result.is_err());
    }
}
