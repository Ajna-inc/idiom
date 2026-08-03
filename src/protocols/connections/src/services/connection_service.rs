use crate::domain::{DidExchangeRole, DidExchangeState};
use crate::messages::{
    DidExchangeCompleteMessage, DidExchangeRequestMessage, DidExchangeResponseMessage,
};
use crate::repository::{ConnectionRecord, ConnectionRecordBuilder, ConnectionRepositoryTrait};
use crate::{ConnectionError, Result};
use protocol_oob::repository::OutOfBandRecord;
use std::sync::Arc;
use tokio::sync::Notify;

#[cfg(feature = "events")]
use crate::events::ConnectionStateChangedPayload;

/// Connection Service
///
/// Handles DID Exchange protocol business logic
pub struct ConnectionService {
    repository: Arc<dyn ConnectionRepositoryTrait>,

    /// Notify waiters when a connection response is processed (their_did set)
    connection_ready_notify: Option<Arc<Notify>>,

    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl ConnectionService {
    pub fn new(repository: Arc<dyn ConnectionRepositoryTrait>) -> Self {
        Self {
            repository,
            connection_ready_notify: None,
            #[cfg(feature = "events")]
            event_bus: None,
            #[cfg(feature = "events")]
            agent_id: "unknown".to_string(),
        }
    }

    /// Set the connection ready notify for instant wake-up when a connection completes
    pub fn with_connection_notify(mut self, notify: Arc<Notify>) -> Self {
        self.connection_ready_notify = Some(notify);
        self
    }

    /// Set the event bus for emitting connection events
    #[cfg(feature = "events")]
    pub fn with_event_bus(
        mut self,
        event_bus: Arc<agent_events::EventBus>,
        agent_id: String,
    ) -> Self {
        self.event_bus = Some(event_bus);
        self.agent_id = agent_id;
        self
    }

    /// Emit a connection state changed event.
    ///
    /// Uses the typed `EventBus::emit` path so:
    /// - the wire `topic` / `name` come from `ConnectionStateChangedPayload`'s
    ///   `TypedEvent` constants (no `format!("{}.{}", ...)` topic typo),
    /// - the payload shape is exactly the typed struct (consumers like
    ///   `agent/tests/helpers/events.rs::wait_for_connection_state` decode
    ///   directly without guessing keys).
    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &ConnectionRecord,
        previous_state: Option<DidExchangeState>,
    ) {
        tracing::debug!(
            "→ [emit_state_changed] Emitting event: state={:?}",
            record.state
        );
        if let Some(bus) = &self.event_bus {
            let payload = ConnectionStateChangedPayload {
                connection_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            if let Err(e) = bus.emit(&meta, payload).await {
                tracing::warn!(error = %e, "Failed to emit connection.state_changed");
            } else {
                tracing::debug!("  ✓ Event published to bus");
            }
        } else {
            tracing::debug!("  ⚠ No event bus attached!");
        }
    }

    /// Create a connection request from an out-of-band invitation
    ///
    /// This is called by the requester (invitee) who received the invitation
    pub async fn create_request(
        &self,
        oob_record: &OutOfBandRecord,
        our_did: String,
        our_label: Option<String>,
    ) -> Result<(ConnectionRecord, DidExchangeRequestMessage)> {
        // Create connection record in RequestSent state
        let mut record = ConnectionRecordBuilder::new(
            DidExchangeRole::Requester,
            DidExchangeState::InvitationReceived,
            uuid::Uuid::new_v4().to_string(), // Will be set to request.thread.thid
            oob_record.invitation.id.clone(), // Parent thread ID is invitation ID
            our_did.clone(),
        )
        .build();

        if let Some(label) = our_label.clone() {
            record.set_our_label(label.clone());
        }

        // Set their label from the invitation (the inviter's label)
        // This is the label they set when creating the invitation
        if let Some(label) = &oob_record.invitation.label {
            record.set_their_label(label.clone());
        }

        // Create request message
        let request = DidExchangeRequestMessage::new(
            our_label.unwrap_or_else(|| "Agent".to_string()),
            our_did,
            oob_record.invitation.id.clone(), // Parent thread ID is invitation ID
        );

        // Update record with actual thread ID from request
        record.thread_id = request.thread_id().to_string();
        record.tags.thread_id = request.thread_id().to_string();
        record.update_state(DidExchangeState::RequestSent);

        // Save the connection record
        self.repository.save(&record).await?;

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(DidExchangeState::InvitationReceived))
            .await;

        Ok((record, request))
    }

    /// Process an incoming connection request
    ///
    /// This is called by the responder (inviter) who receives the request.
    /// Idempotent: if a responder connection already exists for this thread_id,
    /// the existing record is returned (prevents duplicate connections when
    /// mediators replay messages via WS live delivery + queue).
    pub async fn process_request(
        &self,
        request: &DidExchangeRequestMessage,
        oob_record: &OutOfBandRecord,
        our_did: String,
        their_authentication_key_base58: Option<String>,
        their_key_agreement_key_base58: Option<String>,
    ) -> Result<ConnectionRecord> {
        // Verify parent thread ID matches invitation
        let parent_thread_id = request
            .parent_thread_id()
            .ok_or(ConnectionError::MissingParentThreadId)?;

        if parent_thread_id != oob_record.invitation.id {
            return Err(ConnectionError::Protocol(format!(
                "Parent thread ID mismatch: expected {}, got {}",
                oob_record.invitation.id, parent_thread_id
            )));
        }

        // Dedup: if we already processed this request (same thread_id, Responder role),
        // return the existing record rather than creating a duplicate.
        if let Ok(Some(existing)) = self
            .repository
            .find_by_role_and_thread_id(DidExchangeRole::Responder, request.thread_id())
            .await
        {
            tracing::debug!("✓ [process_request] Duplicate request for thread_id={}, returning existing connection id={}",
                request.thread_id(), existing.id);
            return Ok(existing);
        }

        // Create connection record in RequestReceived state
        let mut record = ConnectionRecordBuilder::new(
            DidExchangeRole::Responder,
            DidExchangeState::RequestReceived,
            request.thread_id().to_string(),
            oob_record.invitation.id.clone(), // Parent thread ID is invitation ID
            our_did,
        )
        .their_did(request.did.clone())
        .their_label(request.label.clone())
        .build();

        // Set our label from the invitation if available
        if let Some(label) = &oob_record.invitation.label {
            record.set_our_label(label.clone());
        }

        // Store the Ed25519 authentication public key if provided
        if let Some(key) = their_authentication_key_base58 {
            record.set_their_authentication_key(key);
        }

        // Store the X25519 keyAgreement public key if provided
        if let Some(key) = their_key_agreement_key_base58 {
            record.set_their_key_agreement_key(key);
        }

        // Save the connection record
        self.repository.save(&record).await?;

        tracing::debug!("✓ [process_request] Connection created:");
        tracing::debug!(
            "    id={}, state={:?}, role={:?}, thread_id={}",
            record.id,
            record.state,
            record.role,
            record.thread_id
        );

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, None).await;

        Ok(record)
    }

    /// Create a connection response
    ///
    /// This is called by the responder after processing the request
    pub async fn create_response(
        &self,
        connection_id: &str,
    ) -> Result<(ConnectionRecord, DidExchangeResponseMessage)> {
        let mut record = self
            .repository
            .find_by_id(connection_id)
            .await?
            .ok_or_else(|| ConnectionError::NotFound(connection_id.to_string()))?;

        // Verify state
        if record.state != DidExchangeState::RequestReceived {
            return Err(ConnectionError::InvalidState {
                expected: vec![DidExchangeState::RequestReceived],
                actual: record.state,
            });
        }

        // Verify role
        if record.role != DidExchangeRole::Responder {
            return Err(ConnectionError::InvalidRole {
                expected: DidExchangeRole::Responder,
                actual: record.role,
            });
        }

        // Create response message
        let response =
            DidExchangeResponseMessage::new(record.did.clone(), record.thread_id.clone());

        // Update record state
        record.update_state(DidExchangeState::ResponseSent);
        self.repository.update(&record).await?;

        tracing::debug!("✓ [create_response] Connection updated to ResponseSent:");
        tracing::debug!(
            "    id={}, state={:?}, role={:?}, thread_id={}",
            record.id,
            record.state,
            record.role,
            record.thread_id
        );

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(DidExchangeState::RequestReceived))
            .await;

        Ok((record, response))
    }

    /// Process an incoming connection response
    ///
    /// This is called by the requester after receiving the response
    pub async fn process_response(
        &self,
        response: &DidExchangeResponseMessage,
        their_authentication_key: Option<String>,
        their_key_agreement_key: Option<String>,
    ) -> Result<ConnectionRecord> {
        // Find connection by role and thread ID (requester's record)
        let mut record = self
            .repository
            .find_by_role_and_thread_id(DidExchangeRole::Requester, response.thread_id())
            .await?
            .ok_or_else(|| {
                ConnectionError::NotFound(format!(
                    "thread_id: {} (requester)",
                    response.thread_id()
                ))
            })?;

        // Verify state
        if record.state != DidExchangeState::RequestSent {
            return Err(ConnectionError::InvalidState {
                expected: vec![DidExchangeState::RequestSent],
                actual: record.state,
            });
        }

        // Set their DID from response
        record.set_their_did(response.did.clone());

        // Store their keys if provided (from did_doc~attach)
        if let Some(auth_key) = their_authentication_key {
            record.their_authentication_key_base58 = Some(auth_key);
        }
        if let Some(ka_key) = their_key_agreement_key {
            record.their_key_agreement_key_base58 = Some(ka_key);
        }

        // Update state
        record.update_state(DidExchangeState::ResponseReceived);
        self.repository.update(&record).await?;

        // Signal waiters that a connection response was processed (their_did is now set)
        if let Some(notify) = &self.connection_ready_notify {
            notify.notify_waiters();
        }

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(DidExchangeState::RequestSent))
            .await;

        Ok(record)
    }

    /// Create a connection complete message
    ///
    /// This is called by the requester to finalize the connection
    pub async fn create_complete(
        &self,
        connection_id: &str,
    ) -> Result<(ConnectionRecord, DidExchangeCompleteMessage)> {
        let mut record = self
            .repository
            .find_by_id(connection_id)
            .await?
            .ok_or_else(|| ConnectionError::NotFound(connection_id.to_string()))?;

        // Verify role first
        if record.role != DidExchangeRole::Requester {
            return Err(ConnectionError::InvalidRole {
                expected: DidExchangeRole::Requester,
                actual: record.role,
            });
        }

        // Verify state
        if record.state != DidExchangeState::ResponseReceived {
            return Err(ConnectionError::InvalidState {
                expected: vec![DidExchangeState::ResponseReceived],
                actual: record.state,
            });
        }

        // Create complete message
        let complete = DidExchangeCompleteMessage::new(
            record.thread_id.clone(),
            record.out_of_band_id.clone(),
        );

        // Update state
        record.update_state(DidExchangeState::Completed);
        self.repository.update(&record).await?;

        tracing::debug!("✓ [create_complete] Connection updated to Completed:");
        tracing::debug!(
            "    id={}, state={:?}, role={:?}, thread_id={}",
            record.id,
            record.state,
            record.role,
            record.thread_id
        );

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(DidExchangeState::ResponseReceived))
            .await;

        Ok((record, complete))
    }

    /// Process an incoming connection complete message
    ///
    /// This is called by the responder to finalize the connection
    pub async fn process_complete(
        &self,
        complete: &DidExchangeCompleteMessage,
    ) -> Result<ConnectionRecord> {
        // Find connection by role and thread ID (responder's record)
        let mut record = self
            .repository
            .find_by_role_and_thread_id(DidExchangeRole::Responder, complete.thread_id())
            .await?
            .ok_or_else(|| {
                ConnectionError::NotFound(format!(
                    "thread_id: {} (responder)",
                    complete.thread_id()
                ))
            })?;

        // Verify state
        if record.state != DidExchangeState::ResponseSent {
            return Err(ConnectionError::InvalidState {
                expected: vec![DidExchangeState::ResponseSent],
                actual: record.state,
            });
        }

        // Verify parent thread ID matches
        let parent_thread_id = complete
            .parent_thread_id()
            .ok_or(ConnectionError::MissingParentThreadId)?;

        if parent_thread_id != record.out_of_band_id {
            return Err(ConnectionError::Protocol(format!(
                "Parent thread ID mismatch: expected {}, got {}",
                record.out_of_band_id, parent_thread_id
            )));
        }

        // Update state to completed
        record.update_state(DidExchangeState::Completed);
        self.repository.update(&record).await?;

        // Emit state changed event
        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(DidExchangeState::ResponseSent))
            .await;

        Ok(record)
    }

    /// Get connection by ID
    pub async fn get_by_id(&self, id: &str) -> Result<Option<ConnectionRecord>> {
        self.repository.find_by_id(id).await
    }

    /// Update a connection record
    pub async fn update(&self, record: &ConnectionRecord) -> Result<()> {
        self.repository.update(record).await
    }

    /// Get connection by thread ID
    pub async fn get_by_thread_id(&self, thread_id: &str) -> Result<Option<ConnectionRecord>> {
        self.repository.find_by_thread_id(thread_id).await
    }

    /// Get all completed connections
    pub async fn get_all_completed(&self) -> Result<Vec<ConnectionRecord>> {
        self.repository.find_all_completed().await
    }

    /// Get all connections
    pub async fn get_all(&self) -> Result<Vec<ConnectionRecord>> {
        self.repository.get_all().await
    }

    /// Delete a connection
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.repository.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::ConnectionRepository;
    use protocol_oob::domain::OutOfBandRole;
    use protocol_oob::messages::{InlineService, OutOfBandInvitation, OutOfBandService};

    fn create_test_oob_record() -> OutOfBandRecord {
        let invitation = OutOfBandInvitation::new(vec![OutOfBandService::Inline(InlineService {
            id: "#service-1".to_string(),
            service_type: "did-communication".to_string(),
            service_endpoint: "http://example.com".to_string(),
            recipient_keys: vec!["key1".to_string()],
            routing_keys: vec![],
        })]);

        OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
    }

    #[tokio::test]
    async fn test_create_request() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        let (record, request) = service
            .create_request(
                &oob_record,
                "did:peer:requester".to_string(),
                Some("Alice".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(record.role, DidExchangeRole::Requester);
        assert_eq!(record.state, DidExchangeState::RequestSent);
        assert_eq!(record.did, "did:peer:requester");
        assert_eq!(record.our_label, Some("Alice".to_string()));
        assert_eq!(request.label, "Alice");
        assert_eq!(request.did, "did:peer:requester");
        assert_eq!(
            request.parent_thread_id(),
            Some(oob_record.invitation.id.as_str())
        );
    }

    #[tokio::test]
    async fn test_process_request() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        let request = DidExchangeRequestMessage::new(
            "Bob".to_string(),
            "did:peer:requester".to_string(),
            oob_record.invitation.id.clone(),
        );

        let record = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(record.role, DidExchangeRole::Responder);
        assert_eq!(record.state, DidExchangeState::RequestReceived);
        assert_eq!(record.did, "did:peer:responder");
        assert_eq!(record.their_did, Some("did:peer:requester".to_string()));
        assert_eq!(record.their_label, Some("Bob".to_string()));
    }

    #[tokio::test]
    async fn test_create_response() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:requester".to_string(),
            oob_record.invitation.id.clone(),
        );

        let record = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        let (updated_record, response) = service.create_response(&record.id).await.unwrap();

        assert_eq!(updated_record.state, DidExchangeState::ResponseSent);
        assert_eq!(response.did, "did:peer:responder");
        assert_eq!(response.thread_id(), request.thread_id());
    }

    #[tokio::test]
    async fn test_process_response() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        let (record, _request) = service
            .create_request(
                &oob_record,
                "did:peer:requester".to_string(),
                Some("Alice".to_string()),
            )
            .await
            .unwrap();

        let response = DidExchangeResponseMessage::new(
            "did:peer:responder".to_string(),
            record.thread_id.clone(),
        );

        let updated_record = service
            .process_response(&response, None, None)
            .await
            .unwrap();

        assert_eq!(updated_record.state, DidExchangeState::ResponseReceived);
        assert_eq!(
            updated_record.their_did,
            Some("did:peer:responder".to_string())
        );
    }

    #[tokio::test]
    async fn test_create_complete() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        // Requester creates request
        let (record, _) = service
            .create_request(
                &oob_record,
                "did:peer:requester".to_string(),
                Some("Alice".to_string()),
            )
            .await
            .unwrap();

        // Simulate response
        let response = DidExchangeResponseMessage::new(
            "did:peer:responder".to_string(),
            record.thread_id.clone(),
        );
        let record = service
            .process_response(&response, None, None)
            .await
            .unwrap();

        // Create complete
        let (updated_record, complete) = service.create_complete(&record.id).await.unwrap();

        assert_eq!(updated_record.state, DidExchangeState::Completed);
        assert_eq!(complete.thread_id(), record.thread_id);
        assert_eq!(
            complete.parent_thread_id(),
            Some(oob_record.invitation.id.as_str())
        );
    }

    #[tokio::test]
    async fn test_process_complete() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        // Responder receives request
        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:requester".to_string(),
            oob_record.invitation.id.clone(),
        );

        let record = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        // Responder creates response
        let (record, _) = service.create_response(&record.id).await.unwrap();

        // Process complete message
        let complete = DidExchangeCompleteMessage::new(
            record.thread_id.clone(),
            oob_record.invitation.id.clone(),
        );

        let updated_record = service.process_complete(&complete).await.unwrap();

        assert_eq!(updated_record.state, DidExchangeState::Completed);
    }

    #[tokio::test]
    async fn test_full_protocol_flow() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        // 1. Requester creates request
        let (req_record, request) = service
            .create_request(
                &oob_record,
                "did:peer:requester".to_string(),
                Some("Alice".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(req_record.state, DidExchangeState::RequestSent);

        // 2. Responder processes request
        let resp_record = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(resp_record.state, DidExchangeState::RequestReceived);
        let resp_record_id = resp_record.id.clone();

        // 3. Responder creates response
        let (resp_record_updated, response) =
            service.create_response(&resp_record_id).await.unwrap();

        assert_eq!(resp_record_updated.state, DidExchangeState::ResponseSent);

        // 4. Requester processes response
        let req_record = service
            .process_response(&response, None, None)
            .await
            .unwrap();

        assert_eq!(req_record.state, DidExchangeState::ResponseReceived);

        // 5. Requester creates complete
        let (req_record_completed, complete) =
            service.create_complete(&req_record.id).await.unwrap();

        assert_eq!(req_record_completed.state, DidExchangeState::Completed);

        // 6. Responder processes complete
        let resp_record_completed = service.process_complete(&complete).await.unwrap();

        assert_eq!(resp_record_completed.state, DidExchangeState::Completed);

        // Verify both connections are completed
        let all_completed = service.get_all_completed().await.unwrap();
        assert_eq!(all_completed.len(), 2);
    }

    #[tokio::test]
    async fn test_invalid_state_transition() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:requester".to_string(),
            oob_record.invitation.id.clone(),
        );

        let record = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await
            .unwrap();

        // Try to create complete as responder (invalid role)
        let result = service.create_complete(&record.id).await;

        assert!(result.is_err());
        match result {
            Err(ConnectionError::InvalidRole { expected, actual }) => {
                assert_eq!(expected, DidExchangeRole::Requester);
                assert_eq!(actual, DidExchangeRole::Responder);
            }
            _ => panic!("Expected InvalidRole error, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_missing_parent_thread_id() {
        let repo = Arc::new(ConnectionRepository::new());
        let service = ConnectionService::new(repo.clone());

        let oob_record = create_test_oob_record();

        // Create request with mismatched parent thread ID
        let request = DidExchangeRequestMessage::new(
            "Alice".to_string(),
            "did:peer:requester".to_string(),
            "wrong-invitation-id".to_string(),
        );

        let result = service
            .process_request(
                &request,
                &oob_record,
                "did:peer:responder".to_string(),
                None,
                None,
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(ConnectionError::Protocol(_)) => {}
            _ => panic!("Expected Protocol error"),
        }
    }
}
