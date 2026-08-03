use async_trait::async_trait;
use std::sync::Arc;

/// Abstraction over "deliver a push to this wallet". The mediator-side
/// forward path invokes this fire-and-forget after queueing a message for a
/// connection that has a stored device-info registration.
///
/// Two production implementations live in `mediator_server/src/push_notifier.rs`:
///   * `FcmPushNotifier` — calls Firebase Cloud Messaging HTTP v1.
///   * `WebhookPushNotifier` — POSTs to a user-supplied URL so the wallet
///     team can swap in any push backend.
///
/// The trait lives in this protocol crate (rather than in mediator_server)
/// so `ForwardService` can hold an `Option<Arc<dyn PushNotifier>>` without
/// pulling in a binary-crate dep.
#[async_trait]
pub trait PushNotifier: Send + Sync {
    async fn notify(&self, connection_id: &str) -> Result<(), String>;
}

/// A trivial test/mocking notifier that records every connection id it was
/// asked to notify. Used by ForwardService unit tests + the mediator-side
/// integration test to assert the push hook fires correctly.
#[derive(Default, Clone)]
pub struct RecordingNotifier {
    inner: Arc<tokio::sync::Mutex<Vec<String>>>,
}

impl RecordingNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn calls(&self) -> Vec<String> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl PushNotifier for RecordingNotifier {
    async fn notify(&self, connection_id: &str) -> Result<(), String> {
        self.inner.lock().await.push(connection_id.to_string());
        Ok(())
    }
}

/// Always-fails notifier — used to assert the ForwardService swallows
/// notify errors (push is best-effort, must never block forward delivery).
pub struct ErroringNotifier;

#[async_trait]
impl PushNotifier for ErroringNotifier {
    async fn notify(&self, _connection_id: &str) -> Result<(), String> {
        Err("simulated push failure".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_notifier_collects_calls() {
        let n = RecordingNotifier::new();
        n.notify("c1").await.unwrap();
        n.notify("c2").await.unwrap();
        assert_eq!(n.calls().await, vec!["c1".to_string(), "c2".to_string()]);
    }
}
