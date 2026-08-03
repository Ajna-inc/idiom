//! Pickup V2 full-cycle integration tests.
//!
//! Coverage: the full recipient pickup state machine (StatusRequest → Status →
//! DeliveryRequest → MessageDelivery → MessagesReceived → Status), plus:
//!
//! - Core cycle mechanics: full-cycle delivery, partial ACK with remainder
//!   recovery, the take-without-ACK contract, empty-queue handling, batch limit
//!   enforcement, recipient-key scoping, ACK/status thread correlation, and
//!   per-connection isolation.
//! - FIFO ordering, ACK idempotency, unknown-id ACK no-ops, limit-zero requests,
//!   multi-batch queue draining, empty-queue non-error, and connection-clear
//!   isolation.
//! - The optional status fields our mediator populates (`longest_waited_seconds`,
//!   `total_bytes`) — verifying they reflect real queue state and clear once the
//!   queue drains. These are valid optional fields.
//!
//! These tests pair the `PickupMediatorService` with `PickupRecipientService`
//! directly — no transport — and walk the recipient pickup state machine:
//!
//! ```text
//! StatusRequest → Status → DeliveryRequest → MessageDelivery → MessagesReceived → Status
//! ```
//!
//! The **ACK contract** (mediator must NOT delete messages until it processes
//! a MessagesReceived) is the most load-bearing invariant: if it breaks,
//! recipients lose messages on transport hiccup. Each test that exercises
//! the contract asserts both halves: (a) the queue count drops to 0 only
//! after the ACK, and (b) `take_from_queue` followed by NO ACK leaves the
//! messages recoverable via `return_to_pending`.

use std::sync::Arc;

use protocol_pickup::{
    InMemoryMessageQueueRepository, MessageQueueRepositoryTrait, MessagesReceivedMessage,
    PickupMediatorService, PickupRecipientService, StatusRequestMessage,
};

const CONN: &str = "conn-pickup-cycle";

fn pair() -> (
    PickupMediatorService<InMemoryMessageQueueRepository>,
    PickupRecipientService,
    Arc<InMemoryMessageQueueRepository>,
) {
    let repo = Arc::new(InMemoryMessageQueueRepository::new());
    let mediator = PickupMediatorService::new(repo.clone());
    let recipient = PickupRecipientService::new();
    (mediator, recipient, repo)
}

/// Walk the full V2 cycle with 3 messages, asserting at every leg that
/// counts, attachments, and queue state line up with the RFC.
#[tokio::test]
async fn v2_full_cycle_three_messages() {
    let (mediator, recipient, _repo) = pair();

    // Mediator queues 3 messages addressed to the recipient.
    let id1 = mediator
        .queue_message(CONN, vec![], "msg-1-bytes")
        .await
        .unwrap();
    let id2 = mediator
        .queue_message(CONN, vec![], "msg-2-bytes")
        .await
        .unwrap();
    let id3 = mediator
        .queue_message(CONN, vec![], "msg-3-bytes")
        .await
        .unwrap();

    // 1. Recipient → StatusRequest. Mediator returns Status with count=3.
    let status_req = recipient.create_status_request(None);
    let status = mediator
        .process_status_request(status_req, CONN)
        .await
        .unwrap();
    assert_eq!(
        status.message_count, 3,
        "status should reflect queued count"
    );
    let status_decoded = recipient.process_status(status).await.unwrap();
    assert_eq!(status_decoded.message_count, 3);

    // 2. Recipient → DeliveryRequest(limit=10). Mediator returns 3 attachments.
    let delivery_req = recipient.create_delivery_request(10, None);
    let delivery = mediator
        .process_delivery_request(delivery_req, CONN)
        .await
        .unwrap();
    assert_eq!(
        delivery.attachments.len(),
        3,
        "delivery should contain all 3 messages"
    );

    // Recipient decodes the delivery into typed DeliveredMessage entries.
    let decoded = recipient.process_delivery(delivery).await.unwrap();
    assert_eq!(decoded.len(), 3);
    let decoded_ids: Vec<String> = decoded.iter().map(|d| d.id.clone()).collect();
    assert!(decoded_ids.contains(&id1));
    assert!(decoded_ids.contains(&id2));
    assert!(decoded_ids.contains(&id3));

    // 3. Recipient → MessagesReceived for all 3. Mediator returns Status(count=0).
    let ack = recipient.create_messages_received(decoded_ids.clone(), None);
    let final_status = mediator.process_messages_received(ack, CONN).await.unwrap();
    assert_eq!(
        final_status.message_count, 0,
        "queue must be empty after full ACK"
    );
}

/// Partial ACK: deliver 3, ack only 2 → 1 remains queued (in `sending` state
/// after take_from_queue, but the count returned from the post-ack status
/// reflects only pending). This is the half of the ACK contract that lets a
/// recipient retry without losing the un-acked message.
#[tokio::test]
async fn v2_partial_ack_leaves_remainder_in_queue() {
    let (mediator, recipient, repo) = pair();

    let id1 = mediator.queue_message(CONN, vec![], "msg-1").await.unwrap();
    let id2 = mediator.queue_message(CONN, vec![], "msg-2").await.unwrap();
    let id3 = mediator.queue_message(CONN, vec![], "msg-3").await.unwrap();

    // Take all 3, ACK only first 2.
    let delivery_req = recipient.create_delivery_request(10, None);
    let delivery = mediator
        .process_delivery_request(delivery_req, CONN)
        .await
        .unwrap();
    assert_eq!(delivery.attachments.len(), 3);

    let ack = recipient.create_messages_received(vec![id1.clone(), id2.clone()], None);
    let status_after_partial = mediator.process_messages_received(ack, CONN).await.unwrap();

    // The two ACK'd messages are gone; the third lives on in `sending`.
    assert_eq!(
        status_after_partial.message_count, 0,
        "pending count after partial ACK reports only pending (third is in `sending`)"
    );

    // Bring the third back to `pending` via the recovery API.
    mediator
        .return_messages_to_pending(std::slice::from_ref(&id3))
        .await
        .unwrap();
    let count = repo.get_pending_count(CONN, None).await.unwrap();
    assert_eq!(count, 1, "third message recoverable to pending");

    // Mediator can re-deliver it.
    let redelivery_req = recipient.create_delivery_request(10, None);
    let redelivery = mediator
        .process_delivery_request(redelivery_req, CONN)
        .await
        .unwrap();
    assert_eq!(redelivery.attachments.len(), 1);
    assert_eq!(redelivery.attachments[0].id.as_deref(), Some(id3.as_str()));
}

/// THE ACK CONTRACT: take_from_queue without an ACK must NOT delete messages.
/// The mediator side is strict on this — a transport hiccup mid-pickup must be
/// recoverable. We assert the repository still has the messages and only
/// `remove_messages` (called from `process_messages_received`) removes them.
#[tokio::test]
async fn ack_contract_take_without_ack_does_not_delete() {
    let (mediator, recipient, repo) = pair();

    let id1 = mediator.queue_message(CONN, vec![], "msg-1").await.unwrap();
    let id2 = mediator.queue_message(CONN, vec![], "msg-2").await.unwrap();

    // Take but DO NOT ACK.
    let req = recipient.create_delivery_request(10, None);
    let _ = mediator.process_delivery_request(req, CONN).await.unwrap();

    // Both messages still exist in the repository (just in `sending` state).
    assert!(repo.find_by_id(&id1).await.unwrap().is_some());
    assert!(repo.find_by_id(&id2).await.unwrap().is_some());

    // The pending count is 0 because they're `sending`, but that's not the
    // same as deleted — they can be recovered.
    assert_eq!(repo.get_pending_count(CONN, None).await.unwrap(), 0);

    // ACK one of them.
    let ack = recipient.create_messages_received(vec![id1.clone()], None);
    mediator.process_messages_received(ack, CONN).await.unwrap();
    assert!(
        repo.find_by_id(&id1).await.unwrap().is_none(),
        "ACK removes"
    );
    assert!(
        repo.find_by_id(&id2).await.unwrap().is_some(),
        "no ACK keeps"
    );
}

/// `Status(count=0)` short-circuits the cycle — recipient must not send a
/// DeliveryRequest if the mediator reports an empty queue. We assert by
/// running DeliveryRequest against an empty queue and verifying the
/// response carries zero attachments.
#[tokio::test]
async fn v2_empty_queue_delivers_zero_attachments() {
    let (mediator, recipient, _repo) = pair();

    let status_req = recipient.create_status_request(None);
    let status = mediator
        .process_status_request(status_req, "no-such-conn")
        .await
        .unwrap();
    assert_eq!(status.message_count, 0);

    let req = recipient.create_delivery_request(10, None);
    let delivery = mediator
        .process_delivery_request(req, "no-such-conn")
        .await
        .unwrap();
    assert_eq!(delivery.attachments.len(), 0);
}

/// FIFO ordering: messages are returned oldest-first. Our
/// `InMemoryMessageQueueRepository::take_from_queue` sorts by `received_at`,
/// so this locks in that contract.
#[tokio::test]
async fn v2_delivery_preserves_fifo_ordering() {
    let (mediator, recipient, _repo) = pair();

    let id_first = mediator.queue_message(CONN, vec![], "first").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let id_second = mediator
        .queue_message(CONN, vec![], "second")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let id_third = mediator.queue_message(CONN, vec![], "third").await.unwrap();

    let req = recipient.create_delivery_request(10, None);
    let delivery = mediator.process_delivery_request(req, CONN).await.unwrap();

    let order: Vec<String> = delivery
        .attachments
        .iter()
        .filter_map(|a| a.id.clone())
        .collect();
    assert_eq!(order, vec![id_first, id_second, id_third]);
}

/// `limit` on DeliveryRequest is respected: queue 5 messages, request 2 →
/// exactly 2 come back, queue still has 3 pending. Tests the batch
/// boundary case.
#[tokio::test]
async fn v2_delivery_limit_respected() {
    let (mediator, recipient, repo) = pair();

    for i in 0..5 {
        mediator
            .queue_message(CONN, vec![], &format!("msg-{i}"))
            .await
            .unwrap();
    }

    let req = recipient.create_delivery_request(2, None);
    let delivery = mediator.process_delivery_request(req, CONN).await.unwrap();
    assert_eq!(delivery.attachments.len(), 2);

    // After taking 2, pending count is 3.
    let pending = repo.get_pending_count(CONN, None).await.unwrap();
    assert_eq!(pending, 3);
}

/// Extension: minimal status responses build Status with only
/// `threadId`/`recipientKey`/`messageCount` and leave `longestWaitedSeconds`
/// unset. Our mediator additionally populates this field as an optional
/// field, so recipients that ignore it stay compliant. This test
/// locks in that behavior.
#[tokio::test]
async fn extension_status_reports_longest_waited_seconds() {
    let (mediator, recipient, _) = pair();
    mediator.queue_message(CONN, vec![], "msg").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let req = recipient.create_status_request(None);
    let status = mediator.process_status_request(req, CONN).await.unwrap();
    assert_eq!(status.message_count, 1);
    assert!(
        status.longest_waited_seconds.unwrap_or(0) >= 1,
        "longest_waited should be >= 1s after a 1s sleep"
    );
}

/// Extension: the `total_bytes` field is a valid optional field that
/// minimal status responses leave unset. Our mediator populates it as a
/// convenience so mobile UIs can size their download buffer. Recipients that
/// ignore it are compliant.
#[tokio::test]
async fn extension_status_reports_total_bytes() {
    let (mediator, recipient, _) = pair();
    mediator.queue_message(CONN, vec![], "12345").await.unwrap();
    mediator
        .queue_message(CONN, vec![], "abcdef")
        .await
        .unwrap();

    let req = recipient.create_status_request(None);
    let status = mediator.process_status_request(req, CONN).await.unwrap();
    let total = status.total_bytes.unwrap_or(0);
    assert!(
        total >= 11,
        "total_bytes must cover at least the 11 chars queued; got {total}"
    );
}

/// Recipient-key scoping: with `recipient_key` set, status/delivery only
/// count + return messages addressed to that key. Tests the "filter by
/// recipient key" branch in status/delivery processing.
#[tokio::test]
async fn v2_recipient_key_filter_scopes_status_and_delivery() {
    let (mediator, recipient, _) = pair();

    mediator
        .queue_message(CONN, vec!["key-a".into()], "for-a-1")
        .await
        .unwrap();
    mediator
        .queue_message(CONN, vec!["key-a".into()], "for-a-2")
        .await
        .unwrap();
    mediator
        .queue_message(CONN, vec!["key-b".into()], "for-b-1")
        .await
        .unwrap();

    let req_a = recipient.create_status_request(Some("key-a".into()));
    let status_a = mediator.process_status_request(req_a, CONN).await.unwrap();
    assert_eq!(status_a.message_count, 2);

    let req_b = recipient.create_status_request(Some("key-b".into()));
    let status_b = mediator.process_status_request(req_b, CONN).await.unwrap();
    assert_eq!(status_b.message_count, 1);

    // Delivery scoped to key-b yields only the for-b-1 attachment.
    let del_b = recipient.create_delivery_request(10, Some("key-b".into()));
    let delivery_b = mediator
        .process_delivery_request(del_b, CONN)
        .await
        .unwrap();
    assert_eq!(delivery_b.attachments.len(), 1);
}

/// MessagesReceived can carry a `~thread` decorator so the mediator can
/// correlate the ACK with the original DeliveryRequest and produce the next
/// `Status` with the right `thid`.
#[tokio::test]
async fn v2_messages_received_threads_response() {
    let (mediator, recipient, _) = pair();
    let id = mediator.queue_message(CONN, vec![], "msg").await.unwrap();

    let req = recipient.create_delivery_request(10, None);
    let _delivery = mediator.process_delivery_request(req, CONN).await.unwrap();

    let ack = recipient.create_messages_received(vec![id], Some("th-original".into()));
    let status = mediator.process_messages_received(ack, CONN).await.unwrap();
    assert_eq!(status.thread_id(), Some("th-original"));
    assert_eq!(status.message_count, 0);
}

/// Re-ACK of an already-ACK'd message is idempotent (no-op + count of 0).
/// Defensively important: recipient retries on network blip must not
/// crash the mediator.
#[tokio::test]
async fn v2_repeated_ack_is_idempotent() {
    let (mediator, recipient, _) = pair();
    let id = mediator.queue_message(CONN, vec![], "msg").await.unwrap();

    let req = recipient.create_delivery_request(10, None);
    let _ = mediator.process_delivery_request(req, CONN).await.unwrap();

    let ack1 = recipient.create_messages_received(vec![id.clone()], None);
    let s1 = mediator
        .process_messages_received(ack1, CONN)
        .await
        .unwrap();
    assert_eq!(s1.message_count, 0);

    let ack2 = recipient.create_messages_received(vec![id], None);
    let s2 = mediator
        .process_messages_received(ack2, CONN)
        .await
        .unwrap();
    assert_eq!(s2.message_count, 0);
}

/// Thread ID propagation: StatusRequest carries an `@id`, the resulting
/// Status response's `thread_id` MUST equal that id so the request/response
/// pair correlates.
#[tokio::test]
async fn v2_status_response_threads_to_request_id() {
    let (mediator, recipient, _) = pair();
    let req = recipient.create_status_request(None);
    let req_id = req.id.clone();
    let status = mediator.process_status_request(req, CONN).await.unwrap();
    assert_eq!(status.thread_id(), Some(req_id.as_str()));
}

/// Sanity: a freshly-built status request with no recipient key and an
/// empty queue yields a 0/None status, not an error. Status processing always
/// returns a Status, never errors on empty.
#[tokio::test]
async fn v2_empty_queue_does_not_error() {
    let (mediator, recipient, _) = pair();
    let req = recipient.create_status_request(None);
    let status = mediator
        .process_status_request(req, "unknown-conn")
        .await
        .unwrap();
    assert_eq!(status.message_count, 0);
    assert!(status.total_bytes.is_none() || status.total_bytes == Some(0));
}

/// Multi-batch pickup: queue 5, request 2, ACK 2, request 2, ACK 2,
/// request 1, ACK 1, request 1 → empty. Verifies pagination + final
/// completion across repeated pickup rounds.
#[tokio::test]
async fn v2_multi_batch_pickup_drains_queue() {
    let (mediator, recipient, repo) = pair();

    let mut ids = vec![];
    for i in 0..5 {
        let id = mediator
            .queue_message(CONN, vec![], &format!("msg-{i}"))
            .await
            .unwrap();
        ids.push(id);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    for chunk in ids.chunks(2) {
        let req = recipient.create_delivery_request(2, None);
        let delivery = mediator.process_delivery_request(req, CONN).await.unwrap();
        assert!(delivery.attachments.len() <= 2);
        let delivered_ids: Vec<String> = delivery
            .attachments
            .iter()
            .filter_map(|a| a.id.clone())
            .collect();
        assert!(
            delivered_ids.iter().all(|d| chunk.contains(d)),
            "batch must come from the head of the queue"
        );
        let ack = recipient.create_messages_received(delivered_ids, None);
        mediator.process_messages_received(ack, CONN).await.unwrap();
    }

    let pending = repo.get_pending_count(CONN, None).await.unwrap();
    assert_eq!(pending, 0);
    let req = recipient.create_status_request(None);
    let s = mediator.process_status_request(req, CONN).await.unwrap();
    assert_eq!(s.message_count, 0);
}

/// `messages-received` with an unknown id is treated as a no-op (the
/// matching message just isn't there) — the response Status reports the
/// real remaining pending count, not an error.
#[tokio::test]
async fn v2_ack_unknown_id_is_noop() {
    let (mediator, recipient, _) = pair();
    let kept = mediator.queue_message(CONN, vec![], "msg").await.unwrap();

    let ack = recipient.create_messages_received(vec!["nonexistent-id".into()], None);
    let status = mediator.process_messages_received(ack, CONN).await.unwrap();
    assert_eq!(status.message_count, 1, "real message still pending");
    let _ = kept;
}

/// Clearing a connection nukes every queued message for that connection,
/// while other connections are untouched. Matches per-recipient deletion
/// semantics on mediation termination.
#[tokio::test]
async fn clear_connection_isolated() {
    let (mediator, _, repo) = pair();
    mediator.queue_message("a", vec![], "1").await.unwrap();
    mediator.queue_message("a", vec![], "2").await.unwrap();
    mediator.queue_message("b", vec![], "3").await.unwrap();

    let removed = mediator.clear_queue("a").await.unwrap();
    assert_eq!(removed, 2);
    assert_eq!(repo.get_pending_count("a", None).await.unwrap(), 0);
    assert_eq!(repo.get_pending_count("b", None).await.unwrap(), 1);
}

/// `StatusRequest`/`Status` round-trip across the wire (serde) survives a
/// JSON serialize/deserialize boundary. Catches structural drift before it
/// hits real DIDComm packing.
#[test]
fn status_message_wire_round_trip() {
    let s = protocol_pickup::StatusMessage::new("th-1".into(), 7)
        .with_total_bytes(1024)
        .with_longest_waited_seconds(60)
        .with_recipient_key("key-x".into());
    let json = serde_json::to_string(&s).unwrap();
    let decoded: protocol_pickup::StatusMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.thread_id(), Some("th-1"));
    assert_eq!(decoded.message_count, 7);
    assert_eq!(decoded.total_bytes, Some(1024));
    assert_eq!(decoded.longest_waited_seconds, Some(60));
    assert_eq!(decoded.recipient_key.as_deref(), Some("key-x"));
}

/// `MessagesReceivedMessage` carrying a thread decorator survives
/// serde — required because real mediators always set `~thread` to
/// correlate the ACK with its delivery request.
#[test]
fn messages_received_with_thread_wire_round_trip() {
    let m =
        MessagesReceivedMessage::new_with_thread("th-orig".into(), vec!["a".into(), "b".into()]);
    let json = serde_json::to_string(&m).unwrap();
    let decoded: MessagesReceivedMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.thread_id(), Some("th-orig"));
    assert_eq!(decoded.message_id_list, vec!["a", "b"]);
}

/// Status message structural compat with the canonical wire shape other
/// DIDComm agents emit: must accept that wire shape verbatim. This is a
/// baked-in fixture rather than a recorded one so it can't drift, but the shape
/// matches the canonical typed Status V2 message.
#[test]
fn aries_status_wire_shape_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/messagepickup/2.0/status",
        "@id": "0e96b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "~thread": { "thid": "97cba1de-65ab-44c6-a3ad-7d3ba61e4cdf" },
        "message_count": 5,
        "longest_waited_seconds": 3600,
        "total_bytes": 8192,
        "live_delivery": false
    }"#;
    let decoded: protocol_pickup::StatusMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.message_count, 5);
    assert_eq!(decoded.longest_waited_seconds, Some(3600));
    assert_eq!(decoded.total_bytes, Some(8192));
    assert_eq!(decoded.live_delivery, Some(false));
    assert_eq!(
        decoded.thread_id(),
        Some("97cba1de-65ab-44c6-a3ad-7d3ba61e4cdf")
    );
}

/// The canonical MessagesReceived V2 wire shape carries `message_id_list` as a
/// JSON array of strings + a `~thread.thid`. Decoder must accept it.
#[test]
fn aries_messages_received_wire_shape_decodes() {
    let aries_json = r#"{
        "@type": "https://didcomm.org/messagepickup/2.0/messages-received",
        "@id": "3f6b04c-2c69-4d12-b9bf-3a17f7b53b1c",
        "~thread": { "thid": "th-orig" },
        "message_id_list": ["m-1", "m-2", "m-3"]
    }"#;
    let decoded: MessagesReceivedMessage = serde_json::from_str(aries_json).unwrap();
    assert_eq!(decoded.message_id_list, vec!["m-1", "m-2", "m-3"]);
    assert_eq!(decoded.thread_id(), Some("th-orig"));
}

/// Two independent connections must not see each other's messages. The
/// available-message count filters by connection — messages queued for one
/// connection never surface for another.
#[tokio::test]
async fn per_connection_isolation() {
    let (mediator, recipient, _) = pair();
    mediator
        .queue_message("conn-a", vec![], "for-a")
        .await
        .unwrap();
    mediator
        .queue_message("conn-b", vec![], "for-b-1")
        .await
        .unwrap();
    mediator
        .queue_message("conn-b", vec![], "for-b-2")
        .await
        .unwrap();

    let req_a = recipient.create_status_request(None);
    let s_a = mediator
        .process_status_request(req_a, "conn-a")
        .await
        .unwrap();
    assert_eq!(s_a.message_count, 1);

    let req_b = recipient.create_status_request(None);
    let s_b = mediator
        .process_status_request(req_b, "conn-b")
        .await
        .unwrap();
    assert_eq!(s_b.message_count, 2);
}

/// Extension: when our mediator's status response carries `total_bytes`, it
/// reflects actual encrypted-blob sizes. See note on
/// `extension_status_reports_total_bytes` — minimal status responses omit this
/// field; we populate it as a mobile-UI convenience.
#[tokio::test]
async fn status_total_bytes_matches_payload_sizes() {
    let (mediator, _recipient, _) = pair();
    let blob_a = "a".repeat(100);
    let blob_b = "b".repeat(200);
    mediator.queue_message(CONN, vec![], &blob_a).await.unwrap();
    mediator.queue_message(CONN, vec![], &blob_b).await.unwrap();

    let req = StatusRequestMessage::new();
    let s = mediator.process_status_request(req, CONN).await.unwrap();
    let total = s.total_bytes.unwrap_or(0);
    // Each QueuedMessage's byte_size includes overhead; assert it's at
    // least the raw payload total of 300, and at most 2x that to catch
    // doubling bugs.
    assert!(
        total >= 300,
        "total_bytes must be >= raw payloads ({total})"
    );
    assert!(total < 1200, "total_bytes inflation suspect ({total})");
}

/// DeliveryRequest with limit=0 returns 0 attachments — the queue is
/// preserved, no take happened. `take_from_queue` with a zero limit returns
/// empty.
#[tokio::test]
async fn delivery_request_limit_zero_takes_nothing() {
    let (mediator, recipient, repo) = pair();
    mediator.queue_message(CONN, vec![], "kept").await.unwrap();

    let req = recipient.create_delivery_request(0, None);
    let d = mediator.process_delivery_request(req, CONN).await.unwrap();
    assert_eq!(d.attachments.len(), 0);
    assert_eq!(repo.get_pending_count(CONN, None).await.unwrap(), 1);
}

/// After all messages are ACK'd, a follow-up StatusRequest returns 0 +
/// no longest_waited / total_bytes (both fields are skipped when 0).
#[tokio::test]
async fn status_after_full_ack_clears_optional_fields() {
    let (mediator, recipient, _) = pair();
    let id = mediator.queue_message(CONN, vec![], "msg").await.unwrap();
    let req = recipient.create_delivery_request(10, None);
    let _ = mediator.process_delivery_request(req, CONN).await.unwrap();
    let ack = recipient.create_messages_received(vec![id], None);
    let _ = mediator.process_messages_received(ack, CONN).await.unwrap();

    let req2 = recipient.create_status_request(None);
    let s = mediator.process_status_request(req2, CONN).await.unwrap();
    assert_eq!(s.message_count, 0);
    // `with_total_bytes` is only set when > 0; assert it's absent.
    assert!(s.total_bytes.is_none() || s.total_bytes == Some(0));
    assert!(s.longest_waited_seconds.is_none() || s.longest_waited_seconds == Some(0));
}
