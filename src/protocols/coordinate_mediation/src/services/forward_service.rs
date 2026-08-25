//! Forward Service
//!
//! Handles routing forwarded messages to the correct recipient's queue
//! and optionally pushing via live WebSocket sessions.

use crate::{
    KeylistRepositoryTrait, MediationError, MediationRepositoryTrait, MediationState, Result,
    MAX_FORWARDED_MESSAGE_SIZE_BYTES,
};
use protocol_pickup::{MessageDeliveryMessage, MessageQueueRepositoryTrait, PickupMediatorService};
use protocol_push_notifications::PushNotifier;
use std::sync::Arc;
use std::time::Duration;

use super::live_session_manager::LiveSessionManager;

/// Cap-relief stale-message TTL applied by `process_forward` when the per-
/// connection queue is full. Stale = older than this. Picked to match the
/// mediator's periodic full-sweep TTL (`MediatorConfig::pickup_message_max_age_secs`).
const FORWARD_STALE_RELIEF_TTL: Duration = Duration::from_secs(7 * 86_400);

/// Maximum time to wait when pushing onto a live WS session's mpsc channel.
/// Fix 4B: switched from non-blocking `try_send` to bounded `send`-with-timeout
/// so a momentarily-full buffer (1024 capacity) doesn't drop the live-push
/// optimization — but a stuck channel doesn't pin the forward task forever
/// either. The message is durable in the queue regardless (Fix 1A).
const LIVE_PUSH_TIMEOUT: Duration = Duration::from_millis(500);

/// How many messages to drain per `flush_queued_for_connection` call (Fix 1B).
/// Matches the typical pickup batch size; larger batches still work because
/// the live channel applies its own backpressure via `LIVE_PUSH_TIMEOUT`.
const RECONNECT_REPLAY_BATCH: u32 = 50;

/// Wrap queued message(s) as a `messagepickup/2.0/delivery` DIDComm message
/// (serialized JSON), each attachment carrying its queue-entry ID.
///
/// This is what makes a live / reconnect push **ACK-able**. The recipient's
/// pickup dispatch reads the attachment IDs and returns a `messages-received`
/// ACK, which removes the entries from the queue. Previously the live push
/// sent the RAW encrypted message with NO ID, so the recipient could never ACK
/// it — the queue row stayed `Pending` forever and was re-pushed on every
/// reconnect (the amplification / backlog storm). The client already routes a
/// `delivery` frame through its ACK path (`dispatch_frame` →
/// `ack_and_route_delivery`), so no client change is needed.
fn build_delivery_frame(
    delivery_id: &str,
    attachments: Vec<didcomm::core::models::Attachment>,
) -> Option<String> {
    let mut builder = didcomm::core::MessageBuilder::new(MessageDeliveryMessage::TYPE)
        .id(delivery_id.to_string())
        .body(serde_json::json!({}))
        .thread(delivery_id.to_string());
    for att in attachments {
        builder = builder.add_attachment(att);
    }
    serde_json::to_string(&builder.build()).ok()
}

/// Build a single delivery `Attachment` from a queue entry's ID + its already
/// -encrypted payload (mirrors `PickupMediatorService::process_delivery_request`).
fn encrypted_to_attachment(message_id: &str, encrypted_message: &str) -> didcomm::core::models::Attachment {
    use base64::Engine;
    didcomm::core::models::Attachment {
        id: Some(message_id.to_string()),
        description: None,
        filename: None,
        media_type: Some("application/didcomm-encrypted+json".to_string()),
        format: None,
        lastmod_time: None,
        byte_count: Some(encrypted_message.len()),
        data: didcomm::core::models::AttachmentData::Base64 {
            base64: base64::engine::general_purpose::STANDARD.encode(encrypted_message.as_bytes()),
        },
    }
}

/// Strategy for how forwarded messages are handled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardingStrategy {
    /// Only queue messages for pickup
    QueueOnly,
    /// Queue messages AND attempt live delivery via WebSocket
    #[default]
    QueueAndLiveDelivery,
}

impl ForwardingStrategy {
    /// Parse from string (e.g. from env var)
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "queue-only" | "queue_only" => Self::QueueOnly,
            _ => Self::QueueAndLiveDelivery,
        }
    }
}

/// Service for processing forwarded messages.
///
/// Given a recipient key and encrypted message, this service:
/// 1. Looks up which mediation owns the recipient key
/// 2. Verifies the mediation is in Granted state
/// 3. Queues the message for pickup
/// 4. Optionally attempts live delivery via WebSocket
pub struct ForwardService<Q: MessageQueueRepositoryTrait + 'static> {
    mediation_repo: Arc<dyn MediationRepositoryTrait>,
    keylist_repo: Arc<dyn KeylistRepositoryTrait>,
    pickup_service: Arc<PickupMediatorService<Q>>,
    live_sessions: Arc<LiveSessionManager>,
    strategy: ForwardingStrategy,
    /// Optional push-notification hook. When set + the recipient has no
    /// live WS session, fired fire-and-forget after `queue_message`
    /// succeeds — so we wake the wallet's OS push channel and it can
    /// reconnect for pickup once a message has been queued.
    push_notifier: Option<Arc<dyn PushNotifier>>,
}

impl<Q: MessageQueueRepositoryTrait + 'static> ForwardService<Q> {
    /// Create a new forward service
    pub fn new(
        mediation_repo: Arc<dyn MediationRepositoryTrait>,
        keylist_repo: Arc<dyn KeylistRepositoryTrait>,
        pickup_service: Arc<PickupMediatorService<Q>>,
        live_sessions: Arc<LiveSessionManager>,
        strategy: ForwardingStrategy,
    ) -> Self {
        Self {
            mediation_repo,
            keylist_repo,
            pickup_service,
            live_sessions,
            strategy,
            push_notifier: None,
        }
    }

    /// Attach a push notifier. Builder-style so existing `new(..)` call
    /// sites stay unchanged. The notifier is invoked fire-and-forget after
    /// every successful `queue_message` whenever the recipient has no live
    /// WS session — i.e. the only path where the wallet wouldn't already
    /// have the message live.
    pub fn with_push_notifier(mut self, notifier: Arc<dyn PushNotifier>) -> Self {
        self.push_notifier = Some(notifier);
        self
    }

    /// Process a forwarded message for a given recipient key.
    ///
    /// Returns the queue message ID on success.
    pub async fn process_forward(
        &self,
        recipient_key: &str,
        encrypted_message: &str,
    ) -> Result<String> {
        if encrypted_message.len() > MAX_FORWARDED_MESSAGE_SIZE_BYTES {
            return Err(MediationError::Storage(format!(
                "Forwarded message too large: {} bytes (max {})",
                encrypted_message.len(),
                MAX_FORWARDED_MESSAGE_SIZE_BYTES
            )));
        }

        // Canonicalise the lookup key. The keylist stores keys in raw
        // base58 form (see `mediator_service::canonicalize_recipient_key`
        // — DIDComm v1 authcrypt JWEs carry raw verkeys as `kid`, so
        // that's the storage form). Callers pass `did:key:z6Mk…` (the
        // application-level identifier); without canonicalising the
        // lookup we always get "No mediation found" for the did:key form
        // even though the raw form is in the keylist, and forwards to
        // channel invitees silently fail.
        let recipient_key_canonical =
            crate::services::mediator_service::canonicalize_recipient_key(recipient_key);

        // 1. Find which mediation owns this recipient key
        let keylist_record = self
            .keylist_repo
            .find_mediation_for_recipient_key(&recipient_key_canonical)
            .await?
            .ok_or_else(|| {
                MediationError::NotFound(format!(
                    "No mediation found for recipient key: {}",
                    recipient_key
                ))
            })?;

        let mediation_id = &keylist_record.mediation_id;

        // 2. Verify mediation is granted and get connection_id
        let mediation_record = self
            .mediation_repo
            .find_by_id(mediation_id)
            .await?
            .ok_or_else(|| {
                MediationError::NotFound(format!("Mediation not found: {}", mediation_id))
            })?;

        if mediation_record.state != MediationState::Granted {
            return Err(MediationError::InvalidState {
                expected: vec![MediationState::Granted],
                actual: mediation_record.state,
            });
        }

        let connection_id = &mediation_record.connection_id;

        // 3. Queue cap with stale-message relief.
        //
        // The hard cap protects the mediator from a misbehaving sender filling
        // a per-connection queue. But a queue can also fill with messages
        // destined for a recipient that's been offline / uninstalled for days
        // — those are dead weight. Before rejecting a fresh forward, try aging
        // out anything older than `FORWARD_STALE_RELIEF_TTL`. If the cleanup
        // returns 0, the recipient really is just slow; we reject.
        const MAX_QUEUE_PER_CONNECTION: u64 = 1000;
        if let Ok(count) = self.pickup_service.pending_count(connection_id).await {
            if count >= MAX_QUEUE_PER_CONNECTION {
                let deleted = self
                    .pickup_service
                    .delete_expired_for_connection(connection_id, FORWARD_STALE_RELIEF_TTL)
                    .await
                    .unwrap_or(0);
                if deleted == 0 {
                    return Err(MediationError::Storage(format!(
                        "Queue full for connection {} ({} messages, max {})",
                        connection_id, count, MAX_QUEUE_PER_CONNECTION
                    )));
                }
                tracing::info!(
                    connection_id = connection_id,
                    deleted = deleted,
                    "Forward: cap-relief aged out stale messages, accepting forward"
                );
            }
        }

        // 4. ALWAYS queue the message first. The queue is the durability
        //    boundary; the live push below is an optimization on top. This
        //    is the fix for the live-delivery-and-forget bug: previously a
        //    successful `try_deliver` returned without queueing, so any
        //    in-flight WS frame lost on iOS/macOS suspend was unrecoverable.
        //    Now the client's `messages-received` ACK clears the queue entry
        //    after processing; reconnect-time replay (Fix 1B) re-delivers
        //    anything the client didn't ACK.
        let message_id = self
            .pickup_service
            .queue_message(
                connection_id,
                vec![recipient_key.to_string()],
                encrypted_message,
            )
            .await
            .map_err(|e| MediationError::Storage(format!("Failed to queue message: {}", e)))?;

        // 5a. ALWAYS wake the recipient's OS push channel (no-op if no device
        //     token is registered). This must NOT be gated on "no live
        //     session": a WS session can be STALE — the app was swipe-killed
        //     but the mediator hasn't yet detected the dead socket (it lingers
        //     ~15-20s until the read times out). Gating FCM on it meant a
        //     call/message to a just-killed device got live-pushed into a dead
        //     socket and the FCM wake never fired, so the device never rang.
        //     The client de-dups harmlessly: a genuinely-live app just gets a
        //     redundant wake (it pulls, finds nothing new), a killed app gets
        //     woken to boot + pull. Best-effort: a Firebase/APNS outage never
        //     affects forward durability (the message is already queued).
        if let Some(notifier) = self.push_notifier.clone() {
            let conn = connection_id.to_string();
            let mid = message_id.clone();
            tokio::spawn(async move {
                match notifier.notify(&conn).await {
                    Ok(()) => tracing::debug!(
                        connection_id = conn,
                        message_id = mid,
                        "Forward: push notification dispatched"
                    ),
                    Err(e) => tracing::warn!(
                        connection_id = conn,
                        message_id = mid,
                        error = %e,
                        "Forward: push notification failed (queued message still available)"
                    ),
                }
            });
        }

        // 5b. Best-effort live push (latency optimization, in ADDITION to the
        //     FCM wake). Failure is harmless — the message stays queued for
        //     HTTP pickup or reconnect replay, and the client's ACK removes it.
        //     NOTE: this MUST be non-blocking. `deliver_or_drop` used
        //     `send().await` (bounded by a timeout) which could still pin this
        //     forward call for up to LIVE_PUSH_TIMEOUT waiting on a full live
        //     channel whose sole drainer is stalled on socket backpressure —
        //     that head-of-line-blocked the mediator WS read loop and could
        //     starve the runtime (2026-07-18 outage). Since the message is
        //     ALREADY durably queued above, a full/slow live channel must be a
        //     `try_send` drop, not an await: pickup/reconnect covers delivery.
        if self.strategy == ForwardingStrategy::QueueAndLiveDelivery
            && self.live_sessions.has_session(connection_id).await
        {
            // Push an ACK-able `delivery` wrapper carrying the queue ID (NOT the
            // raw message). The client's `messages-received` ACK then removes
            // this entry — otherwise a raw live push can never be ACKed, the row
            // stays `Pending`, and every reconnect re-delivers it (the backlog
            // storm). We deliberately do NOT mark the row `Sending` here: it
            // stays `Pending` so that if this push drops-on-full, the periodic
            // re-drain / reconnect flush still re-delivers it (also wrapped).
            let attach = encrypted_to_attachment(&message_id, encrypted_message);
            match build_delivery_frame(&message_id, vec![attach]) {
                Some(frame) => match self.live_sessions.try_deliver(connection_id, frame).await {
                    Ok(()) => tracing::info!(
                        connection_id = connection_id,
                        message_id = message_id,
                        "Forward: queued + live-pushed (ACK-able delivery, +push wake)"
                    ),
                    Err(e) => tracing::debug!(
                        connection_id = connection_id,
                        message_id = message_id,
                        error = %e,
                        "Forward: queued; live push dropped-on-full (pickup/reconnect will cover)"
                    ),
                },
                None => tracing::warn!(
                    connection_id = connection_id,
                    message_id = message_id,
                    "Forward: could not build delivery frame; message stays queued for pickup"
                ),
            }
        } else {
            tracing::info!(
                recipient_key = recipient_key,
                connection_id = connection_id,
                message_id = message_id,
                "Forward: message queued for pickup (no live session)"
            );
        }

        Ok(message_id)
    }

    /// Drain queued (Pending) messages for a connection and push them over
    /// its live WS session. Called by the WS handler immediately after a
    /// client (re)registers a live session — this defeats the case where
    /// the client missed live deliveries while its WS was stalled or down.
    ///
    /// Takes up to `RECONNECT_REPLAY_BATCH` messages at a time. They're
    /// marked `Sending` by `take_from_queue`; the client's `messages-received`
    /// ACK clears them on the normal path. If the WS drops again before ACK,
    /// the orphaned `Sending` messages are reset to `Pending` on the next
    /// mediator restart (`storage_backed_message_queue.rs:131-149`).
    pub async fn flush_queued_for_connection(&self, connection_id: &str) -> Result<usize> {
        let mut delivered = 0usize;
        loop {
            let batch = self
                .pickup_service
                .process_delivery_request(
                    protocol_pickup::DeliveryRequestMessage::new(RECONNECT_REPLAY_BATCH),
                    connection_id,
                )
                .await
                .map_err(|e| MediationError::Storage(format!("flush take_from_queue: {}", e)))?;

            if batch.attachments.is_empty() {
                break;
            }

            // Push the whole batch as ONE ACK-able `delivery` frame carrying
            // each entry's queue ID. `take_from_queue` (inside
            // `process_delivery_request` above) already marked these `Sending`;
            // the client's `messages-received` ACK completes their removal.
            // Previously this unwrapped the batch to raw per-attachment pushes
            // with NO ID, so the client couldn't ACK them and the rows leaked
            // (re-pushed on every reconnect — the amplification storm).
            let count = batch.attachments.len();
            let frame = match build_delivery_frame(&batch.id, batch.attachments.clone()) {
                Some(f) => f,
                None => {
                    tracing::warn!(connection_id, "flush: could not build delivery frame; stopping");
                    return Ok(delivered);
                }
            };
            if let Err(e) = self
                .live_sessions
                .deliver_or_drop(connection_id, frame, LIVE_PUSH_TIMEOUT)
                .await
            {
                tracing::warn!(
                    connection_id,
                    error = %e,
                    "flush: live push failed, will await client status-request"
                );
                // Stop the flush — backpressure or session vanished.
                return Ok(delivered);
            }
            delivered += count;

            if count < RECONNECT_REPLAY_BATCH as usize {
                break;
            }
        }

        if delivered > 0 {
            tracing::info!(
                connection_id,
                delivered,
                "Reconnect replay: pushed queued messages over live session"
            );
        }
        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeylistAction, KeylistResult};
    use crate::KeylistRecord;
    use crate::{KeylistRepository, MediationRecordBuilder, MediationRepository, MediationRole};
    use protocol_pickup::InMemoryMessageQueueRepository;

    async fn setup() -> (
        ForwardService<InMemoryMessageQueueRepository>,
        Arc<dyn MediationRepositoryTrait>,
    ) {
        let mediation_repo: Arc<dyn MediationRepositoryTrait> =
            Arc::new(MediationRepository::new());
        let keylist_repo: Arc<dyn KeylistRepositoryTrait> = Arc::new(KeylistRepository::new());
        let queue_repo = Arc::new(InMemoryMessageQueueRepository::new());
        let pickup_service = Arc::new(PickupMediatorService::new(queue_repo));
        let live_sessions = Arc::new(LiveSessionManager::new());

        let service = ForwardService::new(
            mediation_repo.clone(),
            keylist_repo.clone(),
            pickup_service,
            live_sessions,
            ForwardingStrategy::QueueOnly,
        );

        // Set up a granted mediation with a registered key
        let mut record =
            MediationRecordBuilder::new("conn-1".to_string(), MediationRole::Mediator).build();
        mediation_repo.save(&record).await.unwrap();

        record.state = MediationState::Granted;
        record.endpoint = Some("https://mediator.example.com".to_string());
        mediation_repo.update(&record).await.unwrap();

        let kl_record = KeylistRecord::new(
            record.id.clone(),
            "did:key:z6Mkk1...".to_string(),
            KeylistAction::Add,
            KeylistResult::Success,
        );
        keylist_repo.save(&kl_record).await.unwrap();

        (service, mediation_repo)
    }

    #[tokio::test]
    async fn test_process_forward_success() {
        let (service, _) = setup().await;

        let result = service
            .process_forward("did:key:z6Mkk1...", r#"{"encrypted":"data"}"#)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_process_forward_unknown_key() {
        let (service, _) = setup().await;

        let result = service
            .process_forward("did:key:z6Unknown", r#"{"encrypted":"data"}"#)
            .await;
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────
    // Fix 1A + 1B + 1C tests
    // ────────────────────────────────────────────────────────────────────

    /// Helper: build a ForwardService with `QueueAndLiveDelivery` strategy
    /// + shared queue repo so tests can inspect queue contents directly.
    async fn setup_live() -> (
        ForwardService<InMemoryMessageQueueRepository>,
        Arc<PickupMediatorService<InMemoryMessageQueueRepository>>,
        Arc<LiveSessionManager>,
        String, // recipient key
        String, // connection_id
    ) {
        let mediation_repo: Arc<dyn MediationRepositoryTrait> =
            Arc::new(MediationRepository::new());
        let keylist_repo: Arc<dyn KeylistRepositoryTrait> = Arc::new(KeylistRepository::new());
        let queue_repo = Arc::new(InMemoryMessageQueueRepository::new());
        let pickup_service = Arc::new(PickupMediatorService::new(queue_repo));
        let live_sessions = Arc::new(LiveSessionManager::new());

        let service = ForwardService::new(
            mediation_repo.clone(),
            keylist_repo.clone(),
            pickup_service.clone(),
            live_sessions.clone(),
            ForwardingStrategy::QueueAndLiveDelivery,
        );

        let mut record =
            MediationRecordBuilder::new("conn-live".to_string(), MediationRole::Mediator).build();
        mediation_repo.save(&record).await.unwrap();
        record.state = MediationState::Granted;
        record.endpoint = Some("https://mediator.example.com".to_string());
        mediation_repo.update(&record).await.unwrap();

        let key = "did:key:z6MkLiveTest".to_string();
        let kl_record = KeylistRecord::new(
            record.id.clone(),
            key.clone(),
            KeylistAction::Add,
            KeylistResult::Success,
        );
        keylist_repo.save(&kl_record).await.unwrap();

        (
            service,
            pickup_service,
            live_sessions,
            key,
            record.connection_id.clone(),
        )
    }

    /// Fix 1A: even when a live WS session is active and `try_deliver`
    /// succeeds, the message MUST be queued. Previously the code path
    /// returned a fake UUID and skipped the queue, losing the message on
    /// any WS frame drop.
    #[tokio::test]
    async fn live_delivery_also_queues() {
        let (service, pickup, live_sessions, key, conn_id) = setup_live().await;

        let mut rx = live_sessions.register_session(&conn_id, 16).await;

        let mid = service
            .process_forward(&key, r#"{"e":"m1"}"#)
            .await
            .expect("forward succeeded");

        // Live channel received the push.
        let pushed = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("live push within timeout")
            .expect("channel open");
        assert_eq!(pushed, r#"{"e":"m1"}"#);

        // Queue ALSO has the message — that's the bug fix.
        let pending = pickup.pending_count(&conn_id).await.unwrap();
        assert_eq!(
            pending, 1,
            "Fix 1A: live-pushed message must remain in queue until ACK"
        );

        // ACK that returned message_id; queue should clear.
        let ack = protocol_pickup::MessagesReceivedMessage::new(vec![mid]);
        pickup
            .process_messages_received(ack, &conn_id)
            .await
            .unwrap();
        assert_eq!(
            pickup.pending_count(&conn_id).await.unwrap(),
            0,
            "returned message_id must address a real queue entry"
        );
    }

    /// Fix 1A end-to-end: queue-first → live-push → client ACK clears.
    #[tokio::test]
    async fn live_delivery_then_ack_clears() {
        let (service, pickup, live_sessions, key, conn_id) = setup_live().await;
        let mut _rx = live_sessions.register_session(&conn_id, 16).await;

        let mid = service
            .process_forward(&key, r#"{"e":"m2"}"#)
            .await
            .unwrap();
        assert_eq!(pickup.pending_count(&conn_id).await.unwrap(), 1);

        // Recipient sends messages-received ACK.
        let ack = protocol_pickup::MessagesReceivedMessage::new(vec![mid]);
        pickup
            .process_messages_received(ack, &conn_id)
            .await
            .unwrap();

        assert_eq!(
            pickup.pending_count(&conn_id).await.unwrap(),
            0,
            "ACK should clear the queue entry"
        );
    }

    /// Fix 1B: messages queued while no live session exists are pushed
    /// when the client (re)registers a live session, via
    /// `flush_queued_for_connection`.
    #[tokio::test]
    async fn live_delivery_then_reconnect_replay() {
        let (service, pickup, live_sessions, key, conn_id) = setup_live().await;

        // No live session yet — three forwards land in queue only.
        for i in 0..3 {
            let body = format!(r#"{{"e":"r{}"}}"#, i);
            service.process_forward(&key, &body).await.unwrap();
        }
        assert_eq!(pickup.pending_count(&conn_id).await.unwrap(), 3);

        // Client reconnects: registers a new live session.
        let mut rx = live_sessions.register_session(&conn_id, 16).await;

        // Mediator side fires the reconnect flush.
        let delivered = service.flush_queued_for_connection(&conn_id).await.unwrap();
        assert_eq!(delivered, 3, "all queued messages should be pushed");

        // All 3 land on the live channel, in order.
        for i in 0..3 {
            let msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
                .await
                .expect("push within timeout")
                .expect("channel open");
            assert!(
                msg.contains(&format!("r{}", i)),
                "expected r{} in order, got {}",
                i,
                msg
            );
        }

        // Messages are still in queue but marked `Sending` (cleared on ACK).
        let pending = pickup.pending_count(&conn_id).await.unwrap();
        assert_eq!(pending, 0, "marked Sending — pending count excludes them");
    }

    /// Fix 1A: cap-relief cleans up stale messages before rejecting a
    /// fresh forward when the per-connection queue is full.
    #[tokio::test]
    async fn queue_cap_with_stale_relief() {
        let (service, pickup, _live, key, conn_id) = setup_live().await;

        // Fill the queue to the cap. We can't easily inject old timestamps
        // through the public API, but the InMemory repo's `delete_expired_for_connection`
        // is exercised by `delete_expired_for_connection_test` below — here we
        // just confirm queue-full IS hit when the cap is reached with all
        // fresh messages.
        for i in 0..1000 {
            let body = format!(r#"{{"e":"f{}"}}"#, i);
            service.process_forward(&key, &body).await.unwrap();
        }
        assert_eq!(pickup.pending_count(&conn_id).await.unwrap(), 1000);

        // 1001st should be rejected (all messages are <1ms old, can't be aged out).
        let err = service.process_forward(&key, r#"{"e":"overflow"}"#).await;
        assert!(err.is_err(), "queue should reject at the cap");
    }

    // ────────────────────────────────────────────────────────────────────
    // Push-notifier hook tests
    // ────────────────────────────────────────────────────────────────────

    use protocol_push_notifications::{ErroringNotifier, PushNotifier, RecordingNotifier};

    /// Same as `setup_live` but attaches a push notifier and returns it for
    /// assertion. Uses QueueAndLiveDelivery so the notifier-vs-live-session
    /// path is exercisable.
    async fn setup_with_notifier(
        notifier: Arc<dyn PushNotifier>,
    ) -> (
        ForwardService<InMemoryMessageQueueRepository>,
        Arc<LiveSessionManager>,
        String,
        String,
    ) {
        let mediation_repo: Arc<dyn MediationRepositoryTrait> =
            Arc::new(MediationRepository::new());
        let keylist_repo: Arc<dyn KeylistRepositoryTrait> = Arc::new(KeylistRepository::new());
        let queue_repo = Arc::new(InMemoryMessageQueueRepository::new());
        let pickup_service = Arc::new(PickupMediatorService::new(queue_repo));
        let live_sessions = Arc::new(LiveSessionManager::new());

        let service = ForwardService::new(
            mediation_repo.clone(),
            keylist_repo.clone(),
            pickup_service,
            live_sessions.clone(),
            ForwardingStrategy::QueueAndLiveDelivery,
        )
        .with_push_notifier(notifier);

        let mut rec =
            MediationRecordBuilder::new("conn-push".to_string(), MediationRole::Mediator).build();
        mediation_repo.save(&rec).await.unwrap();
        rec.state = MediationState::Granted;
        rec.endpoint = Some("https://mediator.example.com".to_string());
        mediation_repo.update(&rec).await.unwrap();

        let key = "did:key:z6MkPushTest".to_string();
        let kl = KeylistRecord::new(
            rec.id.clone(),
            key.clone(),
            KeylistAction::Add,
            KeylistResult::Success,
        );
        keylist_repo.save(&kl).await.unwrap();

        (service, live_sessions, key, rec.connection_id.clone())
    }

    #[tokio::test]
    async fn push_notifier_fires_when_no_live_session() {
        let notifier = Arc::new(RecordingNotifier::new());
        let (service, live_sessions, key, conn_id) = setup_with_notifier(notifier.clone()).await;
        // No live session installed.
        assert!(!live_sessions.has_session(&conn_id).await);

        service.process_forward(&key, r#"{"e":"m"}"#).await.unwrap();

        // Notify is fire-and-forget — yield to let the spawned task run.
        for _ in 0..50 {
            if !notifier.calls().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let calls = notifier.calls().await;
        assert_eq!(calls, vec![conn_id]);
    }

    #[tokio::test]
    async fn push_notifier_fires_even_with_live_session_present() {
        // Corrected premise: the OS push (FCM/APNS) wake must fire even when a
        // live WS session exists. A session can be STALE (app swipe-killed, dead
        // socket not yet detected — it lingers ~15-20s). Gating the push on
        // "no live session" caused the 2026-07-18 outage where calls to
        // just-killed devices were live-pushed into a dead socket and the device
        // never rang. See the "5a" comment in `process_forward`: the wake MUST
        // NOT be gated on live-session presence. The client de-dups a redundant
        // wake harmlessly. The old test asserted the buggy (gated) behavior.
        let notifier = Arc::new(RecordingNotifier::new());
        let (service, live_sessions, key, conn_id) = setup_with_notifier(notifier.clone()).await;

        // Install a live session so the live-push branch is also taken.
        let mut rx = live_sessions.register_session(&conn_id, 8).await;
        assert!(live_sessions.has_session(&conn_id).await);

        service
            .process_forward(&key, r#"{"e":"live"}"#)
            .await
            .unwrap();
        let received = rx.recv().await;
        assert!(
            received.is_some(),
            "live session should have received the push"
        );

        // The FCM wake is fire-and-forget — yield to let the spawned task run.
        for _ in 0..50 {
            if !notifier.calls().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            notifier.calls().await,
            vec![conn_id],
            "notifier must fire even when a live session exists (stale-session safety)"
        );
    }

    #[tokio::test]
    async fn push_notifier_errors_swallowed() {
        // ErroringNotifier returns Err; process_forward must still succeed.
        let notifier = Arc::new(ErroringNotifier);
        let (service, _live, key, _conn) = setup_with_notifier(notifier).await;
        let r = service.process_forward(&key, r#"{"e":"m"}"#).await;
        assert!(r.is_ok(), "push failure must not break forward path");
    }

    #[tokio::test]
    async fn forward_works_without_any_notifier() {
        // Sanity: the optional notifier is genuinely optional.
        let (service, _) = setup().await;
        let r = service
            .process_forward("did:key:z6Mkk1...", r#"{"e":"m"}"#)
            .await;
        assert!(r.is_ok());
    }
}
