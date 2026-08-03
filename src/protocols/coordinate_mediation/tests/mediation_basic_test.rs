//! Basic mediation protocol tests
//!
//! Tests core mediation flows

use protocol_coordinate_mediation::{
    KeylistAction, KeylistRepository, KeylistRepositoryTrait, KeylistUpdate, MediationGrantMessage,
    MediationRecipientService, MediationRepository, MediationRepositoryTrait, MediatorService,
};
use std::sync::Arc;

/// Test creating a mediation request
#[tokio::test]
async fn test_create_mediation_request() {
    let mediation_repo = Arc::new(MediationRepository::new()) as Arc<dyn MediationRepositoryTrait>;
    let keylist_repo = Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

    let recipient_service = MediationRecipientService::new(mediation_repo.clone(), keylist_repo);

    let connection_id = "test-connection-123".to_string();
    let (record, message) = recipient_service
        .create_request(connection_id.clone())
        .await
        .expect("Failed to create mediation request");

    println!("✓ Created mediation request");
    println!("  Record ID: {}", record.id);
    println!("  Connection ID: {}", record.connection_id);
    println!("  Message ID: {}", message.id);

    // Verify record
    assert_eq!(record.connection_id, connection_id);
    assert_eq!(
        record.state,
        protocol_coordinate_mediation::MediationState::Requested
    );
    assert_eq!(
        record.role,
        protocol_coordinate_mediation::MediationRole::Recipient
    );

    // Verify message
    assert_eq!(
        message.msg_type,
        "https://didcomm.org/coordinate-mediation/1.0/mediate-request"
    );
    assert!(!message.id.is_empty());

    println!("✅ Test passed!");
}

/// Test granting mediation
#[tokio::test]
async fn test_grant_mediation() {
    let mediation_repo = Arc::new(MediationRepository::new()) as Arc<dyn MediationRepositoryTrait>;
    let keylist_repo = Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

    let mediator_endpoint = "https://mediator.example.com".to_string();
    let mediator_routing_keys =
        vec!["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string()];

    let mediator_service = MediatorService::new(
        mediation_repo.clone(),
        keylist_repo,
        mediator_endpoint.clone(),
        mediator_routing_keys.clone(),
    );

    // Create a mediation record in Requested state
    let connection_id = "test-connection-456".to_string();
    let record = protocol_coordinate_mediation::MediationRecordBuilder::new(
        connection_id.clone(),
        protocol_coordinate_mediation::MediationRole::Mediator,
    )
    .state(protocol_coordinate_mediation::MediationState::Requested)
    .build();

    mediation_repo
        .save(&record)
        .await
        .expect("Failed to save record");

    // Grant the mediation
    let thread_id = uuid::Uuid::new_v4().to_string();
    let (granted_record, grant_message) = mediator_service
        .grant_mediation(&record.id, thread_id.clone())
        .await
        .expect("Failed to grant mediation");

    println!("✓ Mediator granted mediation");
    println!("  State: {:?}", granted_record.state);
    println!("  Endpoint: {}", grant_message.endpoint);
    println!("  Routing keys: {:?}", grant_message.routing_keys);

    // Verify grant
    assert_eq!(
        granted_record.state,
        protocol_coordinate_mediation::MediationState::Granted
    );
    assert_eq!(grant_message.endpoint, mediator_endpoint);
    assert_eq!(grant_message.routing_keys, mediator_routing_keys);
    assert_eq!(grant_message.thread_id(), Some(thread_id.as_str()));

    println!("✅ Test passed!");
}

/// Test processing grant message (recipient side)
#[tokio::test]
async fn test_process_grant_message() {
    let mediation_repo = Arc::new(MediationRepository::new()) as Arc<dyn MediationRepositoryTrait>;
    let keylist_repo = Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

    let recipient_service = MediationRecipientService::new(mediation_repo.clone(), keylist_repo);

    // Create a mediation request
    let connection_id = "test-connection-789".to_string();
    let (_record, _message) = recipient_service
        .create_request(connection_id.clone())
        .await
        .expect("Failed to create request");

    // Simulate receiving a grant message
    let grant_message = MediationGrantMessage::new(
        uuid::Uuid::new_v4().to_string(),
        "https://mediator.example.com".to_string(),
        vec!["did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string()],
    );

    // Process the grant
    let updated_record = recipient_service
        .process_grant(&connection_id, &grant_message)
        .await
        .expect("Failed to process grant");

    println!("✓ Recipient processed grant");
    println!("  State: {:?}", updated_record.state);
    println!("  Endpoint: {:?}", updated_record.endpoint);

    // Verify updated record
    assert_eq!(
        updated_record.state,
        protocol_coordinate_mediation::MediationState::Granted
    );
    assert_eq!(
        updated_record.endpoint,
        Some(grant_message.endpoint.clone())
    );
    assert_eq!(updated_record.routing_keys, grant_message.routing_keys);

    println!("✅ Test passed!");
}

/// Test keylist update creation
#[tokio::test]
async fn test_create_keylist_update() {
    let mediation_repo = Arc::new(MediationRepository::new()) as Arc<dyn MediationRepositoryTrait>;
    let keylist_repo = Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

    let recipient_service = MediationRecipientService::new(mediation_repo, keylist_repo);

    let recipient_key = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string();

    // Create keylist update message
    let update_msg = recipient_service.create_keylist_update(vec![KeylistUpdate {
        recipient_key: recipient_key.clone(),
        action: KeylistAction::Add,
    }]);

    println!("✓ Created keylist update");
    println!("  Updates: {:?}", update_msg.updates);

    // Verify message
    assert_eq!(
        update_msg.msg_type,
        "https://didcomm.org/coordinate-mediation/1.0/keylist-update"
    );
    assert_eq!(update_msg.updates.len(), 1);
    assert_eq!(update_msg.updates[0].recipient_key, recipient_key);
    assert_eq!(update_msg.updates[0].action, KeylistAction::Add);

    println!("✅ Test passed!");
}

/// Test finding mediation by connection ID
#[tokio::test]
async fn test_find_by_connection_id() {
    let mediation_repo = Arc::new(MediationRepository::new()) as Arc<dyn MediationRepositoryTrait>;
    let keylist_repo = Arc::new(KeylistRepository::new()) as Arc<dyn KeylistRepositoryTrait>;

    let recipient_service = MediationRecipientService::new(mediation_repo, keylist_repo);

    let connection_id = "test-connection-find".to_string();
    let (record, _msg) = recipient_service
        .create_request(connection_id.clone())
        .await
        .expect("Failed to create request");

    // Find by connection ID
    let found = recipient_service
        .find_by_connection_id(&connection_id)
        .await
        .expect("Failed to find");

    assert!(found.is_some());
    let found_record = found.unwrap();
    assert_eq!(found_record.id, record.id);
    assert_eq!(found_record.connection_id, connection_id);

    println!("✅ Find by connection ID works!");
}
