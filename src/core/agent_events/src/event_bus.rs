//! Event bus implementation using Tokio broadcast with replay buffer
//!
//! This implementation adds a replay buffer so that late subscribers can
//! receive recent events that were published before they subscribed.
//! This is critical for blockchain validator bootstrap where event timing
//! cannot be guaranteed.

use crate::typed::{EventMetadata, TypedEvent, TypedEventError};
use crate::{Event, EventFilter};
use futures_core::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tracing::warn;

/// Default replay buffer size - stores last N events for late subscribers
const DEFAULT_REPLAY_BUFFER_SIZE: usize = 50;

/// Error from `EventBus::emit` — surfaces serialization failures so schema
/// drift between producer and consumer is loud at the call site.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("typed-event serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Error from `Subscriber::recv_typed` — distinguishes channel-level failures
/// (Lagged / Closed) from typed-decode failures so callers can treat them
/// differently. Decode failures usually indicate producer/consumer schema
/// drift and warrant logging without disconnecting.
#[derive(Debug, thiserror::Error)]
pub enum TypedRecvError {
    #[error(transparent)]
    Recv(broadcast::error::RecvError),
    #[error(transparent)]
    Decode(TypedEventError),
}

/// Event bus for publishing and subscribing to events
///
/// Uses Tokio's broadcast channel for efficient fan-out messaging,
/// with an added replay buffer so late subscribers don't miss recent events.
///
/// # Replay Buffer
///
/// The replay buffer stores the most recent events. When a new subscriber
/// is created, they first receive any buffered events that match their filter,
/// then continue receiving live events. This solves the "late subscriber" problem
/// where subscribers miss events published before they called `recv()`.
///
/// # Example
///
/// ```rust
/// use agent_events::{EventBus, Event, EventFilter};
///
/// #[tokio::main]
/// async fn main() {
///     let bus = EventBus::new(100);
///
///     // Publish BEFORE subscribing
///     bus.publish(Event::new("agent", "bootstrap", "peer_discovered",
///         serde_json::json!({"peer": "did:peer:2.xyz"})))
///         .await.ok();
///
///     // Subscribe AFTER event was published
///     let mut subscriber = bus.subscribe();
///
///     // Late subscriber WILL receive the earlier event (from replay buffer)!
///     if let Ok(event) = subscriber.recv().await {
///         println!("Received: {}", event.topic);
///     }
/// }
/// ```
pub struct EventBus {
    tx: broadcast::Sender<Event>,
    /// Replay buffer for late subscribers
    replay_buffer: Arc<RwLock<VecDeque<Event>>>,
    /// Maximum size of replay buffer
    replay_buffer_size: usize,
}

impl EventBus {
    /// Create a new event bus with the specified broadcast capacity
    ///
    /// Uses default replay buffer size (50 events).
    pub fn new(capacity: usize) -> Self {
        Self::with_replay_buffer(capacity, DEFAULT_REPLAY_BUFFER_SIZE)
    }

    /// Create a new event bus with custom replay buffer size
    ///
    /// # Arguments
    /// * `capacity` - Broadcast channel capacity (for slow subscribers)
    /// * `replay_buffer_size` - Number of recent events to keep for late subscribers
    pub fn with_replay_buffer(capacity: usize, replay_buffer_size: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            replay_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(replay_buffer_size))),
            replay_buffer_size,
        }
    }

    /// Publish a typed event.
    ///
    /// Wraps `payload` in a wire envelope (using the type's `TypedEvent::TOPIC`
    /// / `NAME` constants and the metadata's `tenant_id`) and broadcasts it via
    /// `publish`. Prefer this over `publish(Event::new(...))` — the topic /
    /// name strings come from the type, so typo bugs become compile errors.
    ///
    /// `serde_json::to_value` failures bubble up via the typed error so
    /// schema-drift bugs surface at the call site instead of silently
    /// emitting `null` payloads.
    pub async fn emit<E: TypedEvent>(
        &self,
        meta: &EventMetadata,
        payload: E,
    ) -> Result<usize, EmitError> {
        let envelope = Event::from_typed(meta, &payload).map_err(EmitError::Serialize)?;
        match self.publish(envelope).await {
            Ok(n) => Ok(n),
            Err(broadcast::error::SendError(_)) => {
                // No live subscribers — the event is still in the replay buffer
                // (if enabled), so this isn't really an error:
                // emit is fire-and-forget at the producer layer.
                Ok(0)
            }
        }
    }

    /// Publish an event to all subscribers
    ///
    /// The event is also stored in the replay buffer for late subscribers.
    ///
    /// Returns Ok with the number of subscribers that received the event,
    /// or Err if there are no active subscribers (event is still buffered).
    pub async fn publish(&self, event: Event) -> Result<usize, broadcast::error::SendError<Event>> {
        // Order matters: broadcast FIRST so existing subscribers (whose
        // `tx.subscribe()` Receiver was created before this publish) get the
        // event via the live channel. THEN insert into the replay buffer.
        //
        // `subscribe()` snapshots the replay buffer's contents at the moment
        // of subscription, so a subscriber created before this publish sees
        // the event exactly once (via broadcast) — never via replay (its
        // snapshot doesn't include this event). A subscriber created AFTER
        // this publish sees it via replay, never via broadcast (Receiver
        // started after the send). That's the exactly-once guarantee.
        let send_result = self.tx.send(event.clone());

        let mut buffer = self.replay_buffer.write().expect("replay buffer poisoned");
        buffer.push_back(event);
        while buffer.len() > self.replay_buffer_size {
            buffer.pop_front();
        }
        drop(buffer);

        send_result
    }

    /// Subscribe to all events
    ///
    /// Returns a Subscriber that receives:
    /// 1. First: any events that were buffered at the moment of subscription
    ///    (a snapshot — events published *after* this point reach the
    ///    subscriber only through the live channel below).
    /// 2. Then: live events as they are published.
    ///
    /// The snapshot-at-subscribe behavior is what guarantees no duplicate
    /// delivery: events published after `subscribe()` arrive only via the
    /// broadcast Receiver (which Tokio guarantees only sees post-subscribe
    /// sends), never via the per-Subscriber replay buffer.
    pub fn subscribe(&self) -> Subscriber {
        let replay_snapshot = self
            .replay_buffer
            .read()
            .expect("replay buffer poisoned")
            .iter()
            .cloned()
            .collect();
        Subscriber {
            rx: self.tx.subscribe(),
            filter: None,
            replay_snapshot,
            replay_index: 0,
            stream: None,
            tx: self.tx.clone(),
        }
    }

    /// Subscribe to filtered events. Replay snapshot is taken at subscribe
    /// time; the filter is applied to both the snapshot and live events.
    pub fn subscribe_filtered(&self, filter: EventFilter) -> Subscriber {
        let replay_snapshot = self
            .replay_buffer
            .read()
            .expect("replay buffer poisoned")
            .iter()
            .cloned()
            .collect();
        Subscriber {
            rx: self.tx.subscribe(),
            filter: Some(filter),
            replay_snapshot,
            replay_index: 0,
            stream: None,
            tx: self.tx.clone(),
        }
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Get the current replay buffer size
    pub fn replay_buffer_len(&self) -> usize {
        self.replay_buffer
            .read()
            .expect("replay buffer poisoned")
            .len()
    }

    /// Clear the replay buffer
    ///
    /// Useful for testing or when you want to reset event history.
    pub fn clear_replay_buffer(&self) {
        self.replay_buffer
            .write()
            .expect("replay buffer poisoned")
            .clear();
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            replay_buffer: self.replay_buffer.clone(),
            replay_buffer_size: self.replay_buffer_size,
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(100)
    }
}

/// Subscriber for receiving events from the event bus
///
/// Supports optional filtering and automatic replay of buffered events.
///
/// On the first call to `recv()`, any matching events from the replay buffer
/// are returned first, then live events are received.
///
/// Also implements `Stream` trait for use with `StreamExt::next()`, but note
/// that the Stream implementation does NOT replay buffered events - it only
/// receives live events. Use `recv()` for replay buffer support.
pub struct Subscriber {
    rx: broadcast::Receiver<Event>,
    filter: Option<EventFilter>,
    /// Per-Subscriber snapshot of the replay buffer captured at `subscribe()`
    /// time. Drained linearly on first `recv()` calls. Owning the snapshot
    /// (vs. holding a reference to the bus's shared buffer) is what gives
    /// us exactly-once delivery — events published *after* this subscriber
    /// was created don't appear in this VecDeque, so they can only arrive
    /// via the broadcast `rx`.
    replay_snapshot: VecDeque<Event>,
    /// Current position in `replay_snapshot`. Once it equals `replay_snapshot.len()`,
    /// the snapshot is fully drained and `recv` falls through to the live channel.
    replay_index: usize,
    /// Lazily initialized stream for Stream trait implementation
    /// Note: This creates a separate receiver, so subscriber_count may be higher
    stream: Option<Pin<Box<BroadcastStream<Event>>>>,
    /// Sender reference for creating stream on demand
    tx: broadcast::Sender<Event>,
}

impl Subscriber {
    /// Receive the next event
    ///
    /// On first call, returns events from replay buffer (matching filter).
    /// After replay buffer is exhausted, returns live events.
    ///
    /// If a filter is set, this will automatically skip events that don't match.
    ///
    /// # Errors
    ///
    /// - `RecvError::Lagged`: The subscriber fell behind and missed some events
    /// - `RecvError::Closed`: The event bus was dropped
    pub async fn recv(&mut self) -> Result<Event, broadcast::error::RecvError> {
        // Drain the per-subscriber replay snapshot first. The snapshot was
        // taken at `subscribe()` time, so it only contains events published
        // BEFORE this subscriber existed. Live events arrive via `self.rx`
        // below — they cannot also appear here, so no double delivery.
        while self.replay_index < self.replay_snapshot.len() {
            let event = self.replay_snapshot[self.replay_index].clone();
            self.replay_index += 1;

            if let Some(filter) = &self.filter {
                if !filter.matches(&event) {
                    continue;
                }
            }
            return Ok(event);
        }

        // Snapshot drained — fall through to live broadcast.
        loop {
            let event = self.rx.recv().await?;
            if let Some(filter) = &self.filter {
                if !filter.matches(&event) {
                    continue;
                }
            }
            return Ok(event);
        }
    }

    /// Receive the next event, treating broadcast `Lagged` as a skip (with
    /// a warning) instead of an error.
    ///
    /// Returns:
    /// - `Ok(Some(event))` for a normal delivery.
    /// - `Ok(None)` when the subscriber fell behind capacity. The bus has
    ///   discarded `n` events, but the channel is still open. Caller should
    ///   loop and call again — they're free to keep delivering live events
    ///   without disconnecting their downstream (e.g. a WS client).
    /// - `Err(Closed)` only when the bus is shut down — terminal.
    ///
    /// This is the helper to use in any consumer where dropping events under
    /// load is preferable to disconnecting (the WS-forwarders in
    /// `vilko_api/src/ws.rs` are the canonical case). The plain `recv()` keeps
    /// the original `Lagged` behavior for callers that want to handle it
    /// explicitly.
    pub async fn recv_or_skip(&mut self) -> Result<Option<Event>, broadcast::error::RecvError> {
        match self.recv().await {
            Ok(event) => Ok(Some(event)),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    skipped = n,
                    "event subscriber lagged behind broadcast capacity; skipping ahead"
                );
                Ok(None)
            }
            Err(e @ broadcast::error::RecvError::Closed) => Err(e),
        }
    }

    /// Receive the next event matching `E`'s `(topic, name)` and decode its
    /// payload into the typed struct.
    ///
    /// Skips non-matching events transparently (so callers don't need to drain
    /// a topic-soup themselves). Returns the decoded payload plus the
    /// envelope's metadata so consumers can still inspect `tenant_id` /
    /// `trace_id`.
    pub async fn recv_typed<E: TypedEvent>(
        &mut self,
    ) -> Result<(EventMetadata, E), TypedRecvError> {
        loop {
            let event = self.recv().await.map_err(TypedRecvError::Recv)?;
            if event.topic != E::TOPIC || event.name != E::NAME {
                continue;
            }
            let meta = EventMetadata {
                tenant_id: event.agent_id.clone(),
                trace_id: event.trace_id.clone(),
            };
            let payload = event.payload::<E>().map_err(TypedRecvError::Decode)?;
            return Ok((meta, payload));
        }
    }

    /// Try to receive an event without blocking.
    ///
    /// First drains the per-subscriber replay snapshot, then polls live events.
    /// Returns:
    /// - `Ok(event)` if an event matching the filter is available
    /// - `Err(TryRecvError::Empty)` if no events are available
    /// - `Err(TryRecvError::Lagged)` if the subscriber fell behind
    /// - `Err(TryRecvError::Closed)` if the event bus was dropped
    pub fn try_recv(&mut self) -> Result<Event, broadcast::error::TryRecvError> {
        while self.replay_index < self.replay_snapshot.len() {
            let event = self.replay_snapshot[self.replay_index].clone();
            self.replay_index += 1;
            if let Some(filter) = &self.filter {
                if !filter.matches(&event) {
                    continue;
                }
            }
            return Ok(event);
        }

        loop {
            let event = self.rx.try_recv()?;
            if let Some(filter) = &self.filter {
                if !filter.matches(&event) {
                    continue;
                }
            }
            return Ok(event);
        }
    }

    /// Get the filter for this subscriber
    pub fn filter(&self) -> Option<&EventFilter> {
        self.filter.as_ref()
    }

    /// Check if the replay snapshot has been fully consumed.
    pub fn replay_complete(&self) -> bool {
        self.replay_index >= self.replay_snapshot.len()
    }

    /// Skip the replay snapshot and only receive live events.
    pub fn skip_replay(&mut self) {
        self.replay_index = self.replay_snapshot.len();
    }
}

/// Implement Stream trait for Subscriber to enable async iteration with `.next().await`
///
/// NOTE: The Stream implementation does NOT replay buffered events. It only receives
/// live events from the point of subscription. If you need replay buffer support,
/// use the `recv()` method instead.
impl Stream for Subscriber {
    type Item = Event;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Lazily initialize the stream on first poll
        if this.stream.is_none() {
            let rx = this.tx.subscribe();
            this.stream = Some(Box::pin(BroadcastStream::new(rx)));
        }

        // Poll the underlying stream
        loop {
            let stream = this.stream.as_mut().unwrap();
            match stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(event))) => {
                    // If we have a filter, check if the event matches
                    if let Some(filter) = &this.filter {
                        if !filter.matches(&event) {
                            // Event doesn't match filter, continue polling
                            continue;
                        }
                    }
                    return Poll::Ready(Some(event));
                }
                Poll::Ready(Some(Err(_))) => {
                    // On error (lagged), continue polling for next event
                    continue;
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Category 1: Basic Functionality ====================

    #[tokio::test]
    async fn test_publish_and_receive() {
        let bus = EventBus::new(10);
        let mut subscriber = bus.subscribe();

        let event = Event::new(
            "agent",
            "test",
            "event",
            serde_json::json!({"key": "value"}),
        );
        bus.publish(event.clone()).await.unwrap();

        let received = subscriber.recv().await.unwrap();
        assert_eq!(received.topic, event.topic);
        assert_eq!(received.name, event.name);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(10);
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 2);

        let event = Event::new("agent", "test", "event", serde_json::json!({}));
        bus.publish(event.clone()).await.unwrap();

        let recv1 = sub1.recv().await.unwrap();
        let recv2 = sub2.recv().await.unwrap();

        assert_eq!(recv1.topic, "test");
        assert_eq!(recv2.topic, "test");
    }

    #[tokio::test]
    async fn test_filtered_subscription() {
        let bus = EventBus::new(10);
        let mut filtered = bus.subscribe_filtered(EventFilter::topic("connection"));

        // Publish events with different topics
        bus.publish(Event::new(
            "agent",
            "credential",
            "received",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
        bus.publish(Event::new(
            "agent",
            "connection",
            "state_changed",
            serde_json::json!({}),
        ))
        .await
        .unwrap();

        // Should only receive the connection event
        let received = filtered.recv().await.unwrap();
        assert_eq!(received.topic, "connection");
    }

    #[tokio::test]
    async fn test_event_ordering() {
        let bus = EventBus::new(10);
        let mut subscriber = bus.subscribe();

        // Publish events in order
        for i in 0..5 {
            bus.publish(Event::new(
                "agent",
                "test",
                "event",
                serde_json::json!({"index": i}),
            ))
            .await
            .unwrap();
        }

        // Receive events in order
        for i in 0..5 {
            let event = subscriber.recv().await.unwrap();
            assert_eq!(event.data["index"], i);
        }
    }

    // ==================== Category 2: Late Subscriber Tests ====================

    #[tokio::test]
    async fn test_late_subscriber_receives_buffered_events() {
        let bus = EventBus::new(10);

        // Publish BEFORE subscribing (the problem case!)
        bus.publish(Event::new(
            "agent",
            "bootstrap",
            "peer_discovered",
            serde_json::json!({"peer": "did:peer:2.abc"}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "bootstrap",
            "peer_discovered",
            serde_json::json!({"peer": "did:peer:2.xyz"}),
        ))
        .await
        .ok();

        // Subscribe AFTER events were published
        let mut subscriber = bus.subscribe();

        // Late subscriber SHOULD receive both events from replay buffer!
        let event1 = subscriber.recv().await.unwrap();
        assert_eq!(event1.data["peer"], "did:peer:2.abc");

        let event2 = subscriber.recv().await.unwrap();
        assert_eq!(event2.data["peer"], "did:peer:2.xyz");
    }

    #[tokio::test]
    async fn test_late_subscriber_with_filter() {
        let bus = EventBus::new(10);

        // Publish mixed events BEFORE subscribing
        bus.publish(Event::new(
            "agent",
            "credential",
            "received",
            serde_json::json!({"type": "credential"}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "bootstrap",
            "peer_discovered",
            serde_json::json!({"type": "peer"}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "connection",
            "state_changed",
            serde_json::json!({"type": "connection"}),
        ))
        .await
        .ok();

        // Subscribe with filter AFTER events
        let mut filtered = bus.subscribe_filtered(EventFilter::topic("bootstrap"));

        // Should only receive bootstrap event from replay buffer
        let event = filtered.recv().await.unwrap();
        assert_eq!(event.topic, "bootstrap");
        assert_eq!(event.data["type"], "peer");
    }

    #[tokio::test]
    async fn test_replay_then_live_events() {
        let bus = EventBus::new(10);

        // Publish buffered event
        bus.publish(Event::new(
            "agent",
            "test",
            "buffered",
            serde_json::json!({"order": 1}),
        ))
        .await
        .ok();

        let mut subscriber = bus.subscribe();

        // Publish live event
        bus.publish(Event::new(
            "agent",
            "test",
            "live",
            serde_json::json!({"order": 2}),
        ))
        .await
        .unwrap();

        // Should get buffered first, then live
        let e1 = subscriber.recv().await.unwrap();
        assert_eq!(e1.data["order"], 1);
        assert_eq!(e1.name, "buffered");

        let e2 = subscriber.recv().await.unwrap();
        assert_eq!(e2.data["order"], 2);
        assert_eq!(e2.name, "live");
    }

    // ==================== Category 3: Buffer Management Tests ====================

    #[tokio::test]
    async fn test_replay_buffer_size_limit() {
        // Create bus with small replay buffer (3 events)
        let bus = EventBus::with_replay_buffer(10, 3);

        // Publish 5 events
        for i in 0..5 {
            bus.publish(Event::new(
                "agent",
                "test",
                "event",
                serde_json::json!({"index": i}),
            ))
            .await
            .ok();
        }

        // Buffer should only have last 3
        assert_eq!(bus.replay_buffer_len(), 3);

        // Late subscriber should only get last 3 events
        let mut subscriber = bus.subscribe();

        let e1 = subscriber.recv().await.unwrap();
        assert_eq!(e1.data["index"], 2); // Events 0,1 were evicted

        let e2 = subscriber.recv().await.unwrap();
        assert_eq!(e2.data["index"], 3);

        let e3 = subscriber.recv().await.unwrap();
        assert_eq!(e3.data["index"], 4);
    }

    #[tokio::test]
    async fn test_clear_replay_buffer() {
        let bus = EventBus::new(10);

        // Publish some events
        bus.publish(Event::new(
            "agent",
            "test",
            "old",
            serde_json::json!({"msg": "old"}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "test",
            "old2",
            serde_json::json!({"msg": "old2"}),
        ))
        .await
        .ok();

        assert_eq!(bus.replay_buffer_len(), 2);

        // Clear buffer
        bus.clear_replay_buffer();
        assert_eq!(bus.replay_buffer_len(), 0);

        // Late subscriber should not receive old events
        let mut subscriber = bus.subscribe();

        // Publish new event
        bus.publish(Event::new(
            "agent",
            "test",
            "new",
            serde_json::json!({"msg": "new"}),
        ))
        .await
        .unwrap();

        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.name, "new");
    }

    #[tokio::test]
    async fn test_default_replay_buffer_size() {
        let bus = EventBus::new(10);

        // Publish more than default buffer size (50)
        for i in 0..60 {
            bus.publish(Event::new(
                "agent",
                "test",
                "event",
                serde_json::json!({"index": i}),
            ))
            .await
            .ok();
        }

        // Buffer should be capped at 50
        assert_eq!(bus.replay_buffer_len(), 50);
    }

    // ==================== Category 4: Skip Replay Tests ====================

    #[tokio::test]
    async fn test_skip_replay() {
        let bus = EventBus::new(10);

        // Publish before subscribing
        bus.publish(Event::new(
            "agent",
            "test",
            "old",
            serde_json::json!({"msg": "old"}),
        ))
        .await
        .ok();

        // Subscribe and skip replay
        let mut subscriber = bus.subscribe();
        subscriber.skip_replay();

        // Publish new event
        bus.publish(Event::new(
            "agent",
            "test",
            "new",
            serde_json::json!({"msg": "new"}),
        ))
        .await
        .unwrap();

        // Should only receive new event
        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.data["msg"], "new");
    }

    #[tokio::test]
    async fn test_replay_complete_flag() {
        let bus = EventBus::new(10);

        bus.publish(Event::new("agent", "test", "e1", serde_json::json!({})))
            .await
            .ok();

        let mut subscriber = bus.subscribe();
        assert!(!subscriber.replay_complete());

        // Consume replay buffer
        subscriber.recv().await.unwrap();

        // After consuming all buffered events, next recv would wait for live
        // But we can check replay_complete is now true
        assert!(subscriber.replay_complete());
    }

    // ==================== Category 5: Clone and Concurrency Tests ====================

    #[tokio::test]
    async fn test_clone_shares_replay_buffer() {
        let bus1 = EventBus::new(10);
        let bus2 = bus1.clone();

        // Publish via bus1
        bus1.publish(Event::new("agent", "test", "e1", serde_json::json!({})))
            .await
            .ok();

        // Check buffer via bus2
        assert_eq!(bus2.replay_buffer_len(), 1);

        // Subscribe via bus2, should get event from shared buffer
        let mut subscriber = bus2.subscribe();
        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.name, "e1");
    }

    #[tokio::test]
    async fn test_publish_from_clone() {
        let bus1 = EventBus::new(10);
        let bus2 = bus1.clone();

        let mut subscriber = bus1.subscribe();

        // Publish from cloned bus
        bus2.publish(Event::new("agent", "test", "event", serde_json::json!({})))
            .await
            .unwrap();

        // Should receive from original bus subscription
        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.topic, "test");

        // Verify replay buffer is shared
        assert_eq!(bus1.replay_buffer_len(), bus2.replay_buffer_len());
    }

    // ==================== Category 6: Edge Cases ====================

    #[tokio::test]
    async fn test_empty_replay_buffer() {
        let bus = EventBus::new(10);
        let mut subscriber = bus.subscribe();

        // No events in buffer, publish live event
        bus.publish(Event::new("agent", "test", "live", serde_json::json!({})))
            .await
            .unwrap();

        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.name, "live");
    }

    #[tokio::test]
    async fn test_zero_size_replay_buffer() {
        // Create bus with no replay (size 0)
        let bus = EventBus::with_replay_buffer(10, 0);

        bus.publish(Event::new("agent", "test", "e1", serde_json::json!({})))
            .await
            .ok();

        // Buffer should be empty (size 0)
        assert_eq!(bus.replay_buffer_len(), 0);

        let mut subscriber = bus.subscribe();

        // Late subscriber won't get the old event
        bus.publish(Event::new("agent", "test", "e2", serde_json::json!({})))
            .await
            .unwrap();

        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.name, "e2");
    }

    #[tokio::test]
    async fn test_try_recv_empty() {
        let bus = EventBus::new(10);
        let mut subscriber = bus.subscribe();

        // No events yet (and no buffered events)
        assert!(subscriber.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_try_recv_with_buffered_events() {
        let bus = EventBus::new(10);

        // Publish before subscribing
        bus.publish(Event::new(
            "agent",
            "test",
            "buffered",
            serde_json::json!({}),
        ))
        .await
        .ok();

        let mut subscriber = bus.subscribe();

        // Should get buffered event via try_recv
        let event = subscriber.try_recv().unwrap();
        assert_eq!(event.name, "buffered");

        // No more events
        assert!(subscriber.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_complex_filter_with_replay() {
        let bus = EventBus::new(10);

        // Publish various events before subscribing
        bus.publish(Event::new(
            "agent",
            "connection",
            "received",
            serde_json::json!({}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "credential",
            "state_changed",
            serde_json::json!({}),
        ))
        .await
        .ok();
        bus.publish(Event::new(
            "agent",
            "connection",
            "state_changed",
            serde_json::json!({"match": true}),
        ))
        .await
        .ok();

        let filter = EventFilter::new()
            .with_topic("connection")
            .with_name("state_changed");

        let mut filtered = bus.subscribe_filtered(filter);

        // Should only receive the matching event from replay
        let event = filtered.recv().await.unwrap();
        assert_eq!(event.topic, "connection");
        assert_eq!(event.name, "state_changed");
        assert_eq!(event.data["match"], true);
    }

    #[tokio::test]
    async fn test_subscriber_count() {
        let bus = EventBus::new(10);
        assert_eq!(bus.subscriber_count(), 0);

        let _sub1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _sub2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        drop(_sub1);
        // Note: subscriber_count may not immediately update after drop
    }

    #[tokio::test]
    async fn test_default_event_bus() {
        let bus = EventBus::default();

        bus.publish(Event::new("agent", "test", "event", serde_json::json!({})))
            .await
            .ok();

        let mut subscriber = bus.subscribe();
        let event = subscriber.recv().await.unwrap();
        assert_eq!(event.topic, "test");
    }
}
