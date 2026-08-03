//! Phase 1 typed-events integration tests.
//!
//! Covers the contract that producers and consumers depend on:
//! - typed payload round-trips byte-for-byte
//! - mismatched topic / name surface as typed errors, not silent decode-to-default
//! - slow consumer can keep going after `Lagged` via `recv_or_skip`
//! - tenant_id flows through metadata into the wire envelope and filters
//! - replay buffer is opt-in (default constructor doesn't leak across tenants)

use agent_events::{
    EventBus, EventFilter, EventMetadata, TypedEvent, TypedEventError, TypedRecvError,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ConnPayload {
    connection_id: String,
    state: String,
}

impl TypedEvent for ConnPayload {
    const TOPIC: &'static str = "connection";
    const NAME: &'static str = "state_changed";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MessagePayload {
    id: String,
    text: String,
}

impl TypedEvent for MessagePayload {
    const TOPIC: &'static str = "basic_message";
    const NAME: &'static str = "state_changed";
}

#[tokio::test]
async fn round_trip_typed_payload() {
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();
    let meta = EventMetadata::for_tenant("alice");

    let payload = ConnPayload {
        connection_id: "c1".into(),
        state: "Completed".into(),
    };

    bus.emit(&meta, payload.clone()).await.unwrap();

    let event = sub.recv().await.unwrap();
    assert_eq!(event.topic, "connection");
    assert_eq!(event.name, "state_changed");
    assert_eq!(event.agent_id, "alice");

    let decoded: ConnPayload = event.payload().unwrap();
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn topic_mismatch_returns_typed_error() {
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();
    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c1".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    let event = sub.recv().await.unwrap();
    let err = event.payload::<MessagePayload>().unwrap_err();
    match err {
        TypedEventError::TopicMismatch { expected, actual } => {
            assert_eq!(expected, "basic_message");
            assert_eq!(actual, "connection");
        }
        other => panic!("expected TopicMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn name_mismatch_returns_typed_error() {
    // Same topic, different name: define a second connection event variant.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct ConnDeleted {
        connection_id: String,
    }
    impl TypedEvent for ConnDeleted {
        const TOPIC: &'static str = "connection";
        const NAME: &'static str = "deleted";
    }

    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();
    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c1".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    let event = sub.recv().await.unwrap();
    let err = event.payload::<ConnDeleted>().unwrap_err();
    match err {
        TypedEventError::NameMismatch { expected, actual } => {
            assert_eq!(expected, "deleted");
            assert_eq!(actual, "state_changed");
        }
        other => panic!("expected NameMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn recv_or_skip_survives_lagged() {
    // Tiny capacity + no replay so a burst overflows the live broadcast
    // channel — the replay buffer would otherwise hand the subscriber a
    // copy of every event and we'd never observe the lag.
    let bus = EventBus::with_replay_buffer(2, 0);
    let mut sub = bus.subscribe();

    // Push more than capacity without recv'ing — subscriber will lag.
    for i in 0..10 {
        let _ = bus
            .emit(
                &EventMetadata::for_tenant("alice"),
                ConnPayload {
                    connection_id: format!("c{i}"),
                    state: "Completed".into(),
                },
            )
            .await;
    }

    // First call: subscriber lagged, recv_or_skip returns Ok(None), warns.
    let first = sub.recv_or_skip().await.unwrap();
    assert!(first.is_none(), "expected Ok(None) on lag, got {first:?}");

    // Subsequent recvs deliver the surviving (most recent) events. We use
    // try_recv to bound the loop — once the broadcast channel drains, the
    // next try_recv returns Empty rather than blocking forever waiting for
    // a producer that's already done.
    let mut delivered = 0;
    for _ in 0..10 {
        match sub.try_recv() {
            Ok(_) => delivered += 1,
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(e) => panic!("unexpected channel error: {e:?}"),
        }
    }
    assert!(
        delivered > 0,
        "expected to deliver at least one event after recovering from lag"
    );

    // The bus must still be open — recv_or_skip never returned Closed.
    let _ = sub; // drop is fine; assertion is "we got here without panicking"
}

#[tokio::test]
async fn tenant_filter_isolates_events() {
    // The bus now snapshots replay at subscribe time + only delivers
    // post-subscribe events through broadcast — exactly-once. So this
    // test exercises both paths: alice subscribes BEFORE the publishes,
    // so events arrive only via broadcast, and the filter must reject
    // bob's event on that path.
    let bus = EventBus::new(10);
    let mut alice_sub = bus.subscribe_filtered(EventFilter::agent_id("alice"));

    bus.emit(
        &EventMetadata::for_tenant("bob"),
        ConnPayload {
            connection_id: "c-bob".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();
    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c-alice".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    let event = alice_sub.recv().await.unwrap();
    assert_eq!(event.agent_id, "alice");
    let payload: ConnPayload = event.payload().unwrap();
    assert_eq!(payload.connection_id, "c-alice");

    // No bob event should ever reach alice's filtered subscriber.
    let next = tokio::time::timeout(std::time::Duration::from_millis(50), alice_sub.recv()).await;
    assert!(next.is_err(), "alice received bob's event: {next:?}");
}

#[tokio::test]
async fn recv_typed_skips_other_topics() {
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();

    // Mix two topics: subscriber should skip past the message and decode the conn.
    bus.emit(
        &EventMetadata::for_tenant("alice"),
        MessagePayload {
            id: "m1".into(),
            text: "hi".into(),
        },
    )
    .await
    .unwrap();
    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c1".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    let (meta, payload) = sub.recv_typed::<ConnPayload>().await.unwrap();
    assert_eq!(meta.tenant_id, "alice");
    assert_eq!(payload.connection_id, "c1");
}

#[tokio::test]
async fn recv_typed_surfaces_decode_error_when_schema_drifts() {
    // Forge a wire envelope that claims the right topic+name but ships a
    // payload that doesn't match the consumer's struct. Mirrors what would
    // happen if a producer renamed a field without rolling consumers.
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();

    let bad = agent_events::Event::new(
        "alice",
        "connection",
        "state_changed",
        serde_json::json!({ "wrong_field": 42 }),
    );
    bus.publish(bad).await.unwrap();

    let err = sub.recv_typed::<ConnPayload>().await.unwrap_err();
    match err {
        TypedRecvError::Decode(TypedEventError::Json(_)) => {}
        other => panic!("expected Decode/Json error, got {other:?}"),
    }
}

#[tokio::test]
async fn no_double_delivery_after_subscribe() {
    // Regression for the replay+broadcast double-delivery bug.
    //
    // A Subscriber created BEFORE a publish must see the event exactly once
    // (via the broadcast channel), never via the replay buffer. The old code
    // populated both the snapshot and the broadcast channel and then drained
    // both, yielding duplicates.
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();

    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c1".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    // First recv delivers the event.
    let first = sub.recv().await.unwrap();
    assert_eq!(first.payload::<ConnPayload>().unwrap().connection_id, "c1");

    // No second copy may exist for the same publish.
    let second = tokio::time::timeout(std::time::Duration::from_millis(50), sub.recv()).await;
    assert!(
        second.is_err(),
        "subscriber received the same event twice: {second:?}"
    );
}

#[tokio::test]
async fn late_subscriber_gets_replay_only() {
    // A subscriber created AFTER a publish gets the event from the replay
    // snapshot exactly once — never from broadcast (Tokio guarantees the
    // Receiver only sees post-subscribe sends).
    let bus = EventBus::new(10);

    bus.emit(
        &EventMetadata::for_tenant("alice"),
        ConnPayload {
            connection_id: "c-pre".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    // Subscribe AFTER the publish.
    let mut sub = bus.subscribe();

    let first = sub.recv().await.unwrap();
    assert_eq!(
        first.payload::<ConnPayload>().unwrap().connection_id,
        "c-pre"
    );

    // No second copy from the broadcast channel.
    let second = tokio::time::timeout(std::time::Duration::from_millis(50), sub.recv()).await;
    assert!(
        second.is_err(),
        "late subscriber received duplicate of replay event: {second:?}"
    );
}

#[tokio::test]
async fn metadata_trace_id_flows_through() {
    let bus = EventBus::new(10);
    let mut sub = bus.subscribe();
    let meta = EventMetadata::with_trace("alice", "trace-abc");

    bus.emit(
        &meta,
        ConnPayload {
            connection_id: "c1".into(),
            state: "Completed".into(),
        },
    )
    .await
    .unwrap();

    let event = sub.recv().await.unwrap();
    assert_eq!(event.trace_id.as_deref(), Some("trace-abc"));
}
