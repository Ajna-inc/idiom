//! E2E Mediation Tests
//!
//! End-to-end tests for the Coordinate Mediation Protocol (RFC 0211).
//! Uses event-driven testing approach - NO timeouts where possible!
//!
//! These tests work directly with mediation services to demonstrate
//! the event-driven testing pattern.

use agent_events::{EventBus, EventFilter};
use protocol_coordinate_mediation::{
    events::{topics, types, MediationStateChangedPayload},
    MediationRecipientService, MediationRecord, MediationState, MediatorService,
};
use std::sync::Arc;

/// Helper to wait for mediation state change event
async fn wait_for_mediation_state(
    events: Arc<EventBus>,
    mediation_id: &str,
    target_state: MediationState,
) -> MediationRecord {
    let mut subscriber = events.subscribe_filtered(
        EventFilter::new()
            .with_topic(topics::MEDIATION)
            .with_name(types::STATE_CHANGED),
    );

    let mediation_id = mediation_id.to_string();

    loop {
        match subscriber.recv().await {
            Ok(event) => {
                if let Ok(payload) = event.payload::<MediationStateChangedPayload>() {
                    if payload.mediation_record.id == mediation_id
                        && payload.mediation_record.state == target_state
                    {
                        return payload.mediation_record;
                    }
                }
            }
            Err(e) => {
                panic!("Event bus error while waiting for mediation state: {:?}", e);
            }
        }
    }
}

#[tokio::test]
async fn test_mediation_request_and_grant_with_events() {
    println!("\n========================================");
    println!("TEST: Mediation Request and Grant (Event-Driven)");
    println!("========================================\n");

    // ===========================
    // 1. Setup Event Bus and Services
    // ===========================
    println!("1. Creating event buses and services...");

    let mediator_events = Arc::new(EventBus::new(100));
    let recipient_events = Arc::new(EventBus::new(100));

    let mediator_endpoint = "https://mediator.example.com".to_string();
    let mediator_routing_keys = vec!["did:key:z6Mkk...mediator".to_string()];

    let mediator_service =
        MediatorService::with_defaults(mediator_endpoint.clone(), mediator_routing_keys.clone())
            .with_event_bus(mediator_events.clone(), "mediator-agent".to_string());

    let recipient_service = MediationRecipientService::with_defaults()
        .with_event_bus(recipient_events.clone(), "recipient-agent".to_string());

    println!("   ✅ Services created with event buses");

    // ===========================
    // 2. Recipient Creates Request
    // ===========================
    println!("\n2. Recipient creating mediation request...");

    let connection_id = "conn-123".to_string();

    let (recipient_record, _request_msg) = recipient_service
        .create_request(connection_id.clone())
        .await
        .expect("Failed to create mediation request");

    println!("   Mediation ID: {}", recipient_record.id);
    println!("   State: {:?}", recipient_record.state);

    assert_eq!(
        recipient_record.state,
        MediationState::Requested,
        "Should start in Requested state"
    );

    // ===========================
    // 3. Mediator Processes Request
    // ===========================
    println!("\n3. Mediator processing request...");

    let mediator_record = mediator_service
        .process_request(connection_id.clone())
        .await
        .expect("Failed to process request");

    println!("   Mediator record ID: {}", mediator_record.id);
    println!("   State: {:?}", mediator_record.state);

    assert_eq!(
        mediator_record.state,
        MediationState::Requested,
        "Mediator record should be in Requested state"
    );

    // ===========================
    // 4. Mediator Grants Mediation (WITH EVENT WAITING!)
    // ===========================
    println!("\n4. Mediator granting mediation...");

    // Spawn event waiter BEFORE granting
    let med_id = mediator_record.id.clone();
    let events = mediator_events.clone();
    let mediator_granted_waiter = tokio::spawn(async move {
        wait_for_mediation_state(events, &med_id, MediationState::Granted).await
    });

    // Grant mediation
    let (_granted_record, grant_msg) = mediator_service
        .grant_mediation(&mediator_record.id, "thread-123".to_string())
        .await
        .expect("Failed to grant mediation");

    println!("   Grant endpoint: {}", grant_msg.endpoint);
    println!("   Routing keys: {:?}", grant_msg.routing_keys);

    // Wait for event (NO timeout - pure event-driven!)
    let mediator_granted = mediator_granted_waiter
        .await
        .expect("Event waiter task failed");

    println!("   ✅ Mediation state changed to Granted (via event)");

    assert_eq!(
        mediator_granted.state,
        MediationState::Granted,
        "Should be granted"
    );

    // ===========================
    // 5. Recipient Processes Grant (WITH EVENT WAITING!)
    // ===========================
    println!("\n5. Recipient processing grant...");

    // Spawn event waiter BEFORE processing grant
    let rec_id = recipient_record.id.clone();
    let events = recipient_events.clone();
    let recipient_granted_waiter = tokio::spawn(async move {
        wait_for_mediation_state(events, &rec_id, MediationState::Granted).await
    });

    // Process grant
    let _recipient_granted_record = recipient_service
        .process_grant(&connection_id, &grant_msg)
        .await
        .expect("Failed to process grant");

    // Wait for event (NO timeout!)
    let recipient_granted = recipient_granted_waiter
        .await
        .expect("Event waiter task failed");

    println!("   ✅ Recipient state changed to Granted (via event)");

    assert_eq!(
        recipient_granted.state,
        MediationState::Granted,
        "Should be granted"
    );

    // ===========================
    // 6. Verify Routing Information
    // ===========================
    println!("\n6. Verifying routing information...");

    let (endpoint, routing_keys) = recipient_service
        .get_routing_info(&recipient_granted.id)
        .await
        .expect("Failed to get routing info");

    println!("   Endpoint: {}", endpoint);
    println!("   Routing keys: {:?}", routing_keys);

    assert_eq!(endpoint, mediator_endpoint);
    assert_eq!(routing_keys, mediator_routing_keys);

    println!("\n========================================");
    println!("✅ TEST PASSED");
    println!("========================================");
}

#[tokio::test]
async fn test_mediation_keylist_update() {
    println!("\n========================================");
    println!("TEST: Mediation Keylist Update");
    println!("========================================\n");

    // Setup
    let mediator_events = Arc::new(EventBus::new(100));
    let recipient_events = Arc::new(EventBus::new(100));

    let mediator_service =
        MediatorService::with_defaults("https://mediator.example.com".to_string(), vec![])
            .with_event_bus(mediator_events, "mediator-agent".to_string());

    let recipient_service = MediationRecipientService::with_defaults()
        .with_event_bus(recipient_events, "recipient-agent".to_string());

    // Establish mediation
    let connection_id = "conn-456".to_string();

    let (recipient_record, _) = recipient_service
        .create_request(connection_id.clone())
        .await
        .expect("Failed to create request");

    let mediator_record = mediator_service
        .process_request(connection_id.clone())
        .await
        .expect("Failed to process request");

    let (_, grant_msg) = mediator_service
        .grant_mediation(&mediator_record.id, "thread-456".to_string())
        .await
        .expect("Failed to grant mediation");

    recipient_service
        .process_grant(&connection_id, &grant_msg)
        .await
        .expect("Failed to process grant");

    println!("1. Mediation established");

    // ===========================
    // 2. Add Keys to Keylist
    // ===========================
    println!("\n2. Adding keys to keylist...");

    use protocol_coordinate_mediation::KeylistUpdate;

    let updates = vec![
        KeylistUpdate::add("did:key:z6MkkeyABC123".to_string()),
        KeylistUpdate::add("did:key:z6MkkeyDEF456".to_string()),
    ];

    let update_msg = recipient_service.create_keylist_update(updates);

    // Mediator processes keylist updates
    let results = mediator_service
        .process_keylist_updates(&mediator_record.id, &update_msg.updates)
        .await
        .expect("Failed to process keylist updates");

    println!("   Results: {} updates processed", results.len());

    // Recipient processes response
    recipient_service
        .process_keylist_update_response(&recipient_record.id, &results)
        .await
        .expect("Failed to process keylist response");

    // Verify keys were added
    let keylist = mediator_service
        .get_keylist(&mediator_record.id)
        .await
        .expect("Failed to get keylist");

    println!("   Keys in keylist: {}", keylist.len());
    assert_eq!(keylist.len(), 2, "Should have 2 keys");

    println!("\n========================================");
    println!("✅ TEST PASSED: Keylist Update");
    println!("========================================");
}

#[tokio::test]
async fn test_multiple_recipients() {
    println!("\n========================================");
    println!("TEST: Multiple Recipients");
    println!("========================================\n");

    let mediator_events = Arc::new(EventBus::new(100));

    let mediator_service =
        MediatorService::with_defaults("https://mediator.example.com".to_string(), vec![])
            .with_event_bus(mediator_events, "mediator-agent".to_string());

    // Create recipient 1
    let r1_service = MediationRecipientService::with_defaults();
    let (_r1_record, _) = r1_service
        .create_request("conn-r1".to_string())
        .await
        .expect("Failed to create request");

    let m1_record = mediator_service
        .process_request("conn-r1".to_string())
        .await
        .expect("Failed to process request");

    let (_, grant1) = mediator_service
        .grant_mediation(&m1_record.id, "thread-r1".to_string())
        .await
        .expect("Failed to grant");

    r1_service
        .process_grant("conn-r1", &grant1)
        .await
        .expect("Failed to process grant");

    // Create recipient 2
    let r2_service = MediationRecipientService::with_defaults();
    let (_r2_record, _) = r2_service
        .create_request("conn-r2".to_string())
        .await
        .expect("Failed to create request");

    let m2_record = mediator_service
        .process_request("conn-r2".to_string())
        .await
        .expect("Failed to process request");

    let (_, grant2) = mediator_service
        .grant_mediation(&m2_record.id, "thread-r2".to_string())
        .await
        .expect("Failed to grant");

    r2_service
        .process_grant("conn-r2", &grant2)
        .await
        .expect("Failed to process grant");

    println!("1. Both recipients granted mediation");

    // Verify both mediations are granted
    let all_granted = mediator_service
        .get_all_granted()
        .await
        .expect("Failed to get all granted");

    println!("   Total granted: {}", all_granted.len());
    assert_eq!(all_granted.len(), 2);

    println!("\n========================================");
    println!("✅ TEST PASSED: Multiple Recipients");
    println!("========================================");
}
