//! Mediator Forward Handler
//!
//! Handles incoming forward messages on the **mediator** side.
//! When a sender wants to deliver a message to a mediated recipient,
//! it wraps the encrypted message in a Forward envelope and sends it
//! to the mediator. This handler extracts the recipient key and message,
//! then delegates to ForwardService for queuing and live delivery.

use crate::messages::ForwardMessage;
use crate::services::{ForwardService, LiveSessionManager};
use crate::{KeylistRepositoryTrait, MediationRepositoryTrait};
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use protocol_pickup::MessageQueueRepositoryTrait;
use protocol_push_notifications::PushNotifier;
use std::sync::Arc;

use crate::MAX_FORWARDED_MESSAGE_SIZE_BYTES;

/// Handler for forward messages (mediator side).
///
/// This handler:
/// 1. Parses the ForwardMessage to extract `to` (recipient key) and `msg` (encrypted JWE)
/// 2. Calls `ForwardService::process_forward()` to queue and optionally live-deliver
/// 3. Returns `Ok(None)` — forwarding is fire-and-forget from the sender's perspective
pub struct MediatorForwardHandler<Q: MessageQueueRepositoryTrait + 'static> {
    forward_service: Arc<ForwardService<Q>>,
}

impl<Q: MessageQueueRepositoryTrait + 'static> MediatorForwardHandler<Q> {
    /// Create a new mediator forward handler
    pub fn new(forward_service: Arc<ForwardService<Q>>) -> Self {
        Self { forward_service }
    }

    /// Create a handler with all dependencies
    pub fn with_deps(
        mediation_repo: Arc<dyn MediationRepositoryTrait>,
        keylist_repo: Arc<dyn KeylistRepositoryTrait>,
        pickup_service: Arc<protocol_pickup::PickupMediatorService<Q>>,
        live_sessions: Arc<LiveSessionManager>,
        strategy: crate::ForwardingStrategy,
    ) -> Self {
        let forward_service = Arc::new(ForwardService::new(
            mediation_repo,
            keylist_repo,
            pickup_service,
            live_sessions,
            strategy,
        ));
        Self { forward_service }
    }

    /// Same as `with_deps`, but also attaches a push notifier that the
    /// underlying `ForwardService` will invoke fire-and-forget whenever a
    /// queued message has no live WS session to deliver into.
    pub fn with_deps_and_notifier(
        mediation_repo: Arc<dyn MediationRepositoryTrait>,
        keylist_repo: Arc<dyn KeylistRepositoryTrait>,
        pickup_service: Arc<protocol_pickup::PickupMediatorService<Q>>,
        live_sessions: Arc<LiveSessionManager>,
        strategy: crate::ForwardingStrategy,
        push_notifier: Arc<dyn PushNotifier>,
    ) -> Self {
        let forward_service = Arc::new(
            ForwardService::new(
                mediation_repo,
                keylist_repo,
                pickup_service,
                live_sessions,
                strategy,
            )
            .with_push_notifier(push_notifier),
        );
        Self { forward_service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<Q: MessageQueueRepositoryTrait + 'static> MessageHandler for MediatorForwardHandler<Q> {
    fn supported_types(&self) -> Vec<String> {
        vec![ForwardMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        message: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        // Parse the forward message 'to' field (recipient verkey).
        // In v1 format, 'to' is a top-level string that may end up in body, extra,
        // or the DIDComm envelope 'to' field (as Vec<String>) depending on parsing.
        let to = message
            .message
            .body
            .get("to")
            .and_then(|v| v.as_str())
            .or_else(|| message.message.extra.get("to").and_then(|v| v.as_str()))
            .or_else(|| {
                // v1 forward: 'to' string may be parsed into the envelope to field
                message
                    .message
                    .to
                    .as_ref()
                    .and_then(|t| t.first())
                    .map(|s| s.as_str())
            })
            .ok_or_else(|| {
                MessageHandlerError::InvalidMessage("Missing 'to' field in forward message".into())
            })?
            .to_string();

        // Drop expired messages (e.g. typing indicators with short TTLs).
        // This prevents ephemeral signals from piling up in offline queues.
        if let Some(expires_time) = message.message.expires_time {
            let now = chrono::Utc::now().timestamp();
            if expires_time < now {
                tracing::debug!(
                    recipient = %to,
                    expires_time = expires_time,
                    "Dropping expired forward message (TTL exceeded)"
                );
                return Ok(None);
            }
        }

        let encrypted_msg = message
            .message
            .body
            .get("msg")
            .or_else(|| message.message.extra.get("msg"))
            .ok_or_else(|| {
                MessageHandlerError::InvalidMessage("Missing 'msg' field in forward message".into())
            })?;

        // Serialize the encrypted message to JSON string
        let encrypted_json = serde_json::to_string(encrypted_msg)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        if encrypted_json.len() > MAX_FORWARDED_MESSAGE_SIZE_BYTES {
            return Err(MessageHandlerError::InvalidMessage(
                "Forwarded message too large".into(),
            ));
        }

        tracing::debug!(recipient = to, "Processing forward message");

        // Delegate to forward service
        match self
            .forward_service
            .process_forward(&to, &encrypted_json)
            .await
        {
            Ok(message_id) => {
                tracing::info!(
                    recipient = to,
                    message_id = message_id,
                    "Forward message queued successfully"
                );
            }
            Err(e) => {
                tracing::warn!(
                    recipient = to,
                    error = %e,
                    "Failed to process forward message"
                );
                return Err(MessageHandlerError::ProcessingFailed(e.to_string()));
            }
        }

        // Fire-and-forget: no response to sender
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeylistAction, KeylistResult};
    use crate::services::ForwardingStrategy;
    use crate::{
        KeylistRecord, KeylistRepository, KeylistRepositoryTrait, MediationRecordBuilder,
        MediationRepository, MediationRepositoryTrait, MediationRole, MediationState,
    };
    use didcomm::core::Message as DidcommMessage;
    use didcomm::messaging::MessageContext;
    use protocol_pickup::{InMemoryMessageQueueRepository, PickupMediatorService};
    use serde_json::json;

    async fn setup_handler() -> MediatorForwardHandler<InMemoryMessageQueueRepository> {
        let mediation_repo: Arc<dyn MediationRepositoryTrait> =
            Arc::new(MediationRepository::new());
        let keylist_repo: Arc<dyn KeylistRepositoryTrait> = Arc::new(KeylistRepository::new());
        let queue_repo = Arc::new(InMemoryMessageQueueRepository::new());
        let pickup_service = Arc::new(PickupMediatorService::new(queue_repo));
        let live_sessions = Arc::new(LiveSessionManager::new());

        // Set up granted mediation with a registered key
        let mut record =
            MediationRecordBuilder::new("conn-1".to_string(), MediationRole::Mediator).build();
        mediation_repo.save(&record).await.unwrap();
        record.state = MediationState::Granted;
        record.endpoint = Some("https://mediator.example.com".to_string());
        mediation_repo.update(&record).await.unwrap();

        let kl_record = KeylistRecord::new(
            record.id.clone(),
            "did:key:z6MkkRecipient".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );
        keylist_repo.save(&kl_record).await.unwrap();

        MediatorForwardHandler::with_deps(
            mediation_repo,
            keylist_repo,
            pickup_service,
            live_sessions,
            ForwardingStrategy::QueueOnly,
        )
    }

    #[tokio::test]
    async fn test_handle_forward_queues_message() {
        let handler = setup_handler().await;

        let body = json!({
            "to": "did:key:z6MkkRecipient",
            "msg": {"protected": "...", "ciphertext": "..."}
        });

        let msg = DidcommMessage {
            id: "fwd-1".to_string(),
            msg_type: ForwardMessage::TYPE.to_string(),
            body,
            from: Some("did:peer:sender".to_string()),
            to: Some(vec!["did:peer:mediator".to_string()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: Default::default(),
        };

        let inbound = InboundMessage {
            message: msg,
            context: MessageContext {
                from: Some("did:peer:sender".to_string()),
                to: Some("did:peer:mediator".to_string()),
                thread_id: None,
                parent_thread_id: None,
                connection_id: Some("sender-conn".to_string()),
                encrypted: true,
                authenticated: true,
                sender_endpoint: None,
                raw_plaintext: None,
            },
        };

        let result = handler.handle(inbound).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Fire-and-forget
    }
}
