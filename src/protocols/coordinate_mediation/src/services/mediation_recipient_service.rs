//! Mediation Recipient Service
//!
//! This service handles the recipient (client) side of the mediation protocol.
//! It allows an agent to request mediation from a mediator, update its keylist,
//! and retrieve routing information.

use crate::{
    domain::{KeylistAction, KeylistResult},
    events::MediationStateChangedPayload,
    KeylistRecord, KeylistRepository, KeylistRepositoryTrait, KeylistUpdate, KeylistUpdateMessage,
    KeylistUpdated, MediationError, MediationGrantMessage, MediationRecord, MediationRecordBuilder,
    MediationRepository, MediationRepositoryTrait, MediationRequestMessage, MediationRole,
    MediationState, Result,
};
use std::sync::Arc;
use tokio::sync::Notify;

/// Service for mediation recipient operations
pub struct MediationRecipientService {
    mediation_repository: Arc<dyn MediationRepositoryTrait>,
    keylist_repository: Arc<dyn KeylistRepositoryTrait>,
    /// Notify waiters when a mediation grant is processed
    grant_notify: Option<Arc<Notify>>,
    /// Event bus for emitting mediation events (optional)
    event_bus: Option<Arc<agent_events::EventBus>>,
    /// Agent ID for event attribution
    agent_id: String,
}

impl MediationRecipientService {
    /// Create a new mediation recipient service
    pub fn new(
        mediation_repository: Arc<dyn MediationRepositoryTrait>,
        keylist_repository: Arc<dyn KeylistRepositoryTrait>,
    ) -> Self {
        Self {
            mediation_repository,
            keylist_repository,
            grant_notify: None,
            event_bus: None,
            agent_id: "unknown".to_string(),
        }
    }

    /// Create a new mediation recipient service with default repositories
    pub fn with_defaults() -> Self {
        Self::new(
            Arc::new(MediationRepository::new()),
            Arc::new(KeylistRepository::new()),
        )
    }

    /// Set the grant notify for instant wake-up when a mediation grant is received
    pub fn with_grant_notify(mut self, notify: Arc<Notify>) -> Self {
        self.grant_notify = Some(notify);
        self
    }

    /// Set the event bus for emitting events
    pub fn with_event_bus(
        mut self,
        event_bus: Arc<agent_events::EventBus>,
        agent_id: String,
    ) -> Self {
        self.event_bus = Some(event_bus);
        self.agent_id = agent_id;
        self
    }

    /// Emit a mediation state changed event via the typed bus.
    async fn emit_state_changed(
        &self,
        record: &MediationRecord,
        previous_state: Option<MediationState>,
    ) {
        if let Some(event_bus) = &self.event_bus {
            let payload = MediationStateChangedPayload {
                mediation_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = event_bus.emit(&meta, payload).await;
        }
    }

    /// Create a mediation request for a connection
    ///
    /// Creates a mediation record in Requested state and returns the request message
    pub async fn create_request(
        &self,
        connection_id: String,
    ) -> Result<(MediationRecord, MediationRequestMessage)> {
        // Create mediation record
        let record = MediationRecordBuilder::new(connection_id, MediationRole::Recipient).build();

        // Save record
        self.mediation_repository.save(&record).await?;

        // Emit state changed event (no previous state for new record)
        self.emit_state_changed(&record, None).await;

        // Create request message
        let message = MediationRequestMessage::new();

        Ok((record, message))
    }

    /// Process a mediation grant response
    ///
    /// Updates the mediation record with endpoint and routing keys
    pub async fn process_grant(
        &self,
        connection_id: &str,
        grant_message: &MediationGrantMessage,
    ) -> Result<MediationRecord> {
        // Find mediation record by connection ID
        let mut record = self
            .mediation_repository
            .find_by_connection_id(connection_id)
            .await?
            .ok_or_else(|| MediationError::ConnectionNotFound(connection_id.to_string()))?;

        // Validate state transition
        if !MediationState::Granted.is_valid_transition_from(&record.state) {
            return Err(MediationError::InvalidStateTransition {
                from: record.state,
                to: MediationState::Granted,
            });
        }

        // Store previous state for event
        let previous_state = record.state;

        // Update record
        record.state = MediationState::Granted;
        record.endpoint = Some(grant_message.endpoint.clone());
        record.routing_keys = grant_message.routing_keys.clone();

        // Save updated record
        self.mediation_repository.update(&record).await?;

        // Signal waiters that a mediation grant was processed
        if let Some(notify) = &self.grant_notify {
            notify.notify_waiters();
        }

        // Emit state changed event
        self.emit_state_changed(&record, Some(previous_state)).await;

        // Routing established — emit `(routing, created)` so UIs that just
        // care about "we now have an endpoint to hand out" can subscribe to a
        // single event instead of filtering mediation.state_changed by
        // `state == Granted`.
        #[cfg(feature = "events")]
        if record.state.is_active() {
            if let Some(bus) = &self.event_bus {
                let payload = crate::events::RoutingCreatedPayload {
                    mediation_record: record.clone(),
                };
                let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
                let _ = bus.emit(&meta, payload).await;
            }
        }

        Ok(record)
    }

    /// Get routing information for a mediation
    ///
    /// Returns (endpoint, routing_keys) tuple if mediation is granted
    pub async fn get_routing_info(&self, mediation_id: &str) -> Result<(String, Vec<String>)> {
        let record = self
            .mediation_repository
            .find_by_id(mediation_id)
            .await?
            .ok_or_else(|| MediationError::NotFound(mediation_id.to_string()))?;

        if !record.state.is_active() {
            return Err(MediationError::InvalidState {
                expected: vec![MediationState::Granted],
                actual: record.state,
            });
        }

        let endpoint = record.endpoint.ok_or_else(|| {
            MediationError::Protocol("No endpoint in granted mediation".to_string())
        })?;

        Ok((endpoint, record.routing_keys))
    }

    /// Create a keylist update request
    ///
    /// Returns the keylist update message to send to the mediator
    pub fn create_keylist_update(&self, updates: Vec<KeylistUpdate>) -> KeylistUpdateMessage {
        KeylistUpdateMessage::new(updates)
    }

    /// Process a keylist update response
    ///
    /// Stores the keylist records based on the response
    pub async fn process_keylist_update_response(
        &self,
        mediation_id: &str,
        updated: &[KeylistUpdated],
    ) -> Result<()> {
        for entry in updated {
            let record = KeylistRecord::new(
                mediation_id.to_string(),
                entry.recipient_key.clone(),
                entry.action,
                entry.result,
            );

            // If the action was successful and it was an Add, save the keylist entry
            // If it was a Remove, delete the entry
            match (entry.action, entry.result) {
                (KeylistAction::Add, KeylistResult::Success) => {
                    self.keylist_repository.save(&record).await?;
                }
                (KeylistAction::Remove, KeylistResult::Success) => {
                    self.keylist_repository
                        .delete_by_recipient_key(mediation_id, &entry.recipient_key)
                        .await?;
                }
                _ => {
                    // Save the record even if it failed, for auditing
                    self.keylist_repository.save(&record).await?;
                }
            }
        }

        Ok(())
    }

    /// Get all keylist entries for a mediation
    pub async fn get_keylist(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        self.keylist_repository
            .find_by_mediation_id(mediation_id)
            .await
    }

    /// Find mediation by connection ID
    pub async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Option<MediationRecord>> {
        self.mediation_repository
            .find_by_connection_id(connection_id)
            .await
    }

    /// Get all granted mediations
    pub async fn get_all_granted(&self) -> Result<Vec<MediationRecord>> {
        self.mediation_repository.find_all_granted().await
    }

    /// Update a mediation record
    ///
    /// Used to persist changes like the registered_recipient_key
    pub async fn update(&self, record: &MediationRecord) -> Result<()> {
        self.mediation_repository.update(record).await
    }

    /// Delete a mediation record by ID
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.mediation_repository.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_request() {
        let service = MediationRecipientService::with_defaults();
        let (record, message) = service
            .create_request("conn-123".to_string())
            .await
            .unwrap();

        assert_eq!(record.connection_id, "conn-123");
        assert_eq!(record.state, MediationState::Requested);
        assert_eq!(record.role, MediationRole::Recipient);
        assert_eq!(message.msg_type, MediationRequestMessage::TYPE);
    }

    #[tokio::test]
    async fn test_process_grant() {
        let service = MediationRecipientService::with_defaults();

        // Create request first
        let (_record, _) = service
            .create_request("conn-123".to_string())
            .await
            .unwrap();

        // Create grant message
        let grant_message = MediationGrantMessage::new(
            "thread-123".to_string(),
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );

        // Process grant
        let updated_record = service
            .process_grant("conn-123", &grant_message)
            .await
            .unwrap();

        assert_eq!(updated_record.state, MediationState::Granted);
        assert_eq!(
            updated_record.endpoint.unwrap(),
            "https://mediator.example.com"
        );
        assert_eq!(updated_record.routing_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_get_routing_info() {
        let service = MediationRecipientService::with_defaults();

        // Create and grant mediation
        let (record, _) = service
            .create_request("conn-123".to_string())
            .await
            .unwrap();

        let grant_message = MediationGrantMessage::new(
            "thread-123".to_string(),
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );

        service
            .process_grant("conn-123", &grant_message)
            .await
            .unwrap();

        // Get routing info
        let (endpoint, routing_keys) = service.get_routing_info(&record.id).await.unwrap();

        assert_eq!(endpoint, "https://mediator.example.com");
        assert_eq!(routing_keys.len(), 1);
    }
}
