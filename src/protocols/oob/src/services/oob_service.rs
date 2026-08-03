use std::sync::Arc;

use crate::domain::{OutOfBandRole, OutOfBandState};
use crate::error::{OutOfBandError, Result};
use crate::messages::{
    HandshakeReuseAcceptedMessage, HandshakeReuseMessage, OutOfBandInvitation,
    OutOfBandService as ServiceType,
};
use crate::repository::oob_repository::OutOfBandRepositoryTrait;
use crate::repository::{OutOfBandRecord, OutOfBandRepository};

/// Core business logic for Out-of-Band protocol
///
/// This service handles the creation and processing of Out-of-Band invitations,
/// handshake reuse, and state management.
pub struct OutOfBandService {
    repository: Arc<OutOfBandRepository>,
    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,
    #[cfg(feature = "events")]
    agent_id: String,
}

impl OutOfBandService {
    /// Create a new OutOfBandService
    pub fn new(repository: Arc<OutOfBandRepository>) -> Self {
        Self {
            repository,
            #[cfg(feature = "events")]
            event_bus: None,
            #[cfg(feature = "events")]
            agent_id: "unknown".to_string(),
        }
    }

    /// Attach the typed event bus and a tenant id. After this, every state
    /// transition emits `OutOfBandStateChangedPayload`; the handshake-reuse
    /// path additionally emits `HandshakeReusedPayload`.
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

    /// Emit `(oob, state_changed)` for the given record + previous state.
    /// No-op when the bus isn't attached or the `events` feature is off.
    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &OutOfBandRecord,
        previous_state: Option<OutOfBandState>,
    ) {
        if let Some(bus) = &self.event_bus {
            let payload = crate::events::OutOfBandStateChangedPayload {
                oob_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(not(feature = "events"))]
    async fn emit_state_changed(
        &self,
        _record: &OutOfBandRecord,
        _previous_state: Option<OutOfBandState>,
    ) {
    }

    /// Emit `(oob, handshake_reused)`. Called by `process_handshake_reuse`
    /// (via the future handshake-reuse handler) after the inbound
    /// `~thread.pthid` resolves to an existing connection.
    #[cfg(feature = "events")]
    async fn emit_handshake_reused(
        &self,
        record: &OutOfBandRecord,
        reuse_thread_id: &str,
        connection_id: &str,
    ) {
        if let Some(bus) = &self.event_bus {
            let payload = crate::events::HandshakeReusedPayload {
                reuse_thread_id: reuse_thread_id.to_string(),
                oob_record: record.clone(),
                connection_id: connection_id.to_string(),
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(not(feature = "events"))]
    async fn emit_handshake_reused(
        &self,
        _record: &OutOfBandRecord,
        _reuse_thread_id: &str,
        _connection_id: &str,
    ) {
    }

    /// Create a new Out-of-Band invitation
    ///
    /// # Arguments
    /// * `services` - Service endpoints (DIDs or inline services)
    /// * `label` - Human-readable label for the inviter
    /// * `goal_code` - Optional machine-readable goal
    /// * `goal` - Optional human-readable goal
    /// * `handshake_protocols` - Optional list of supported handshake protocols
    /// * `multi_use` - Whether this invitation can be used multiple times
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_invitation(
        &self,
        services: Vec<ServiceType>,
        label: Option<String>,
        goal_code: Option<String>,
        goal: Option<String>,
        handshake_protocols: Option<Vec<String>>,
        multi_use: bool,
    ) -> Result<OutOfBandRecord> {
        // Validate invitation
        if handshake_protocols.is_none() {
            return Err(OutOfBandError::NoHandshakeOrRequests);
        }

        // Create invitation message
        let mut invitation = OutOfBandInvitation::new(services);

        if let Some(label) = label {
            invitation = invitation.with_label(label);
        }

        if let Some(goal_code) = goal_code {
            if let Some(goal) = goal {
                invitation = invitation.with_goal(goal_code, goal);
            }
        }

        if let Some(protocols) = handshake_protocols {
            invitation = invitation.with_handshake_protocols(protocols);
        }

        // Create record
        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
            .with_state(OutOfBandState::AwaitResponse)
            .with_reusable(multi_use);

        // Save to repository
        self.repository.save(&record).await?;

        // Initial state-changed (previous = None): consumers can subscribe
        // to the same event stream for both creation and transitions.
        self.emit_state_changed(&record, None).await;

        Ok(record)
    }

    /// Receive and process an Out-of-Band invitation
    ///
    /// # Arguments
    /// * `invitation` - The received invitation message
    /// * `auto_accept` - Whether to auto-accept connections from this invitation
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn receive_invitation(
        &self,
        invitation: OutOfBandInvitation,
        auto_accept: Option<bool>,
    ) -> Result<OutOfBandRecord> {
        // Check if we already have this invitation
        let existing = self
            .repository
            .find_by_invitation_id(&invitation.id, OutOfBandRole::Receiver)
            .await?;

        if let Some(existing) = existing {
            return Ok(existing);
        }

        // Create new record
        let mut record = OutOfBandRecord::new(invitation, OutOfBandRole::Receiver)
            .with_state(OutOfBandState::PrepareResponse);

        if let Some(auto_accept) = auto_accept {
            record = record.with_auto_accept_connection(auto_accept);
        }

        // Save to repository
        self.repository.save(&record).await?;

        self.emit_state_changed(&record, None).await;

        Ok(record)
    }

    /// Create a handshake reuse message
    ///
    /// # Arguments
    /// * `invitation_id` - The invitation ID to reuse
    ///
    /// # Returns
    /// The handshake reuse message
    pub async fn create_handshake_reuse(
        &self,
        invitation_id: &str,
    ) -> Result<HandshakeReuseMessage> {
        // Find the invitation record
        let record = self
            .repository
            .find_by_invitation_id(invitation_id, OutOfBandRole::Receiver)
            .await?
            .ok_or_else(|| OutOfBandError::RecordNotFound(invitation_id.to_string()))?;

        // Validate state
        record.assert_state(&[OutOfBandState::PrepareResponse])?;

        // Create handshake reuse message
        let message = HandshakeReuseMessage::new(record.invitation.id.clone());

        Ok(message)
    }

    /// Process a handshake reuse message
    ///
    /// # Arguments
    /// * `message` - The received handshake reuse message
    /// * `connection_id` - The connection ID to reuse
    ///
    /// # Returns
    /// The handshake reuse accepted message
    pub async fn process_handshake_reuse(
        &self,
        message: &HandshakeReuseMessage,
        connection_id: String,
    ) -> Result<HandshakeReuseAcceptedMessage> {
        // Find the invitation record
        let parent_thread_id = message
            .thread
            .parent_thread_id
            .as_ref()
            .ok_or(OutOfBandError::MissingParentThreadId)?;

        let mut record = self
            .repository
            .find_by_invitation_id(parent_thread_id, OutOfBandRole::Sender)
            .await?
            .ok_or_else(|| OutOfBandError::RecordNotFound(parent_thread_id.clone()))?;

        // Check if invitation is reusable or if this is the first use
        // This check must happen before state validation because single-use invitations
        // transition to Done after first use
        if !record.reusable && record.reuse_connection_id.is_some() {
            return Err(OutOfBandError::ConnectionAlreadyExists);
        }

        // Validate state
        record.assert_state(&[OutOfBandState::AwaitResponse])?;

        // Update record
        let previous_state = Some(record.state);
        record.reuse_connection_id = Some(connection_id.clone());
        let transitioned = if !record.reusable {
            record.update_state(OutOfBandState::Done);
            true
        } else {
            false
        };

        self.repository.update(&record).await?;

        if transitioned {
            self.emit_state_changed(&record, previous_state).await;
        }

        // RFC 0434 handshake-reuse: the inbound `~thread.pthid` resolved to an
        // existing connection. Emit the dedicated reuse event so consumers
        // can render "reused existing connection" UI without filtering
        // state-changed by `reuse_connection_id != None`.
        self.emit_handshake_reused(&record, &message.thread.thread_id, &connection_id)
            .await;

        // Create handshake reuse accepted message
        let accepted = HandshakeReuseAcceptedMessage::new(
            message.thread.thread_id.clone(),
            parent_thread_id.clone(),
        );

        Ok(accepted)
    }

    /// Find an Out-of-Band record by ID
    pub async fn find_by_id(&self, id: &str) -> Result<Option<OutOfBandRecord>> {
        self.repository.find_by_id(id).await
    }

    /// Find an Out-of-Band record by invitation ID
    pub async fn find_by_invitation_id(
        &self,
        invitation_id: &str,
        role: OutOfBandRole,
    ) -> Result<Option<OutOfBandRecord>> {
        self.repository
            .find_by_invitation_id(invitation_id, role)
            .await
    }

    /// Find records by recipient key fingerprint
    pub async fn find_by_recipient_key(
        &self,
        recipient_key_fingerprint: &str,
    ) -> Result<Vec<OutOfBandRecord>> {
        self.repository
            .find_by_recipient_key(recipient_key_fingerprint)
            .await
    }

    /// Get all Out-of-Band records
    pub async fn get_all(&self) -> Result<Vec<OutOfBandRecord>> {
        self.repository.get_all().await
    }

    /// Delete an Out-of-Band record
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.repository.delete(id).await
    }

    /// Mark an invitation as done
    pub async fn mark_done(&self, invitation_id: &str, role: OutOfBandRole) -> Result<()> {
        let mut record = self
            .repository
            .find_by_invitation_id(invitation_id, role)
            .await?
            .ok_or_else(|| OutOfBandError::RecordNotFound(invitation_id.to_string()))?;

        let previous_state = Some(record.state);
        record.update_state(OutOfBandState::Done);
        self.repository.update(&record).await?;

        self.emit_state_changed(&record, previous_state).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::InlineService;

    fn create_test_service() -> Arc<OutOfBandService> {
        let repo = Arc::new(OutOfBandRepository::new());
        Arc::new(OutOfBandService::new(repo))
    }

    #[tokio::test]
    async fn test_create_invitation() {
        let service = create_test_service();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                Some("test".to_string()),
                Some("Testing".to_string()),
                Some(handshake_protocols),
                false,
            )
            .await
            .unwrap();

        assert_eq!(record.role, OutOfBandRole::Sender);
        assert_eq!(record.state, OutOfBandState::AwaitResponse);
        assert!(!record.reusable);
        assert_eq!(record.invitation.label, Some("Test Agent".to_string()));
    }

    #[tokio::test]
    async fn test_create_invitation_multi_use() {
        let service = create_test_service();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                true,
            )
            .await
            .unwrap();

        assert!(record.reusable);
    }

    #[tokio::test]
    async fn test_create_invitation_no_handshake_fails() {
        let service = create_test_service();

        let services = vec![ServiceType::Did("did:example:123".to_string())];

        let result = service
            .create_invitation(services, Some("Test".to_string()), None, None, None, false)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::NoHandshakeOrRequests
        ));
    }

    #[tokio::test]
    async fn test_receive_invitation() {
        let service = create_test_service();

        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())])
                .with_label("Test Agent".to_string())
                .with_handshake_protocols(vec!["https://didcomm.org/didexchange/1.1".to_string()]);

        let record = service
            .receive_invitation(invitation.clone(), Some(true))
            .await
            .unwrap();

        assert_eq!(record.role, OutOfBandRole::Receiver);
        assert_eq!(record.state, OutOfBandState::PrepareResponse);
        assert_eq!(record.auto_accept_connection, Some(true));
        assert_eq!(record.invitation.id, invitation.id);
    }

    #[tokio::test]
    async fn test_receive_invitation_duplicate() {
        let service = create_test_service();

        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())])
                .with_label("Test Agent".to_string());

        // First receive
        let record1 = service
            .receive_invitation(invitation.clone(), None)
            .await
            .unwrap();

        // Second receive should return same record
        let record2 = service
            .receive_invitation(invitation.clone(), None)
            .await
            .unwrap();

        assert_eq!(record1.id, record2.id);
    }

    #[tokio::test]
    async fn test_create_handshake_reuse() {
        let service = create_test_service();

        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())]);

        let _record = service
            .receive_invitation(invitation.clone(), None)
            .await
            .unwrap();

        let reuse_message = service
            .create_handshake_reuse(&invitation.id)
            .await
            .unwrap();

        assert_eq!(
            reuse_message.thread.parent_thread_id,
            Some(invitation.id.clone())
        );
    }

    #[tokio::test]
    async fn test_process_handshake_reuse() {
        let service = create_test_service();

        // Create invitation as sender
        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let sender_record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                false,
            )
            .await
            .unwrap();

        // Create handshake reuse message
        let reuse_message = HandshakeReuseMessage::new(sender_record.invitation.id.clone());

        // Process handshake reuse
        let accepted = service
            .process_handshake_reuse(&reuse_message, "connection-123".to_string())
            .await
            .unwrap();

        assert_eq!(
            accepted.thread.parent_thread_id,
            Some(sender_record.invitation.id.clone())
        );

        // Verify record was updated
        let updated = service
            .find_by_invitation_id(&sender_record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            updated.reuse_connection_id,
            Some("connection-123".to_string())
        );
        assert_eq!(updated.state, OutOfBandState::Done);
    }

    #[tokio::test]
    async fn test_process_handshake_reuse_multi_use() {
        let service = create_test_service();

        // Create multi-use invitation
        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let sender_record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                true,
            )
            .await
            .unwrap();

        // First reuse
        let reuse1 = HandshakeReuseMessage::new(sender_record.invitation.id.clone());
        service
            .process_handshake_reuse(&reuse1, "connection-1".to_string())
            .await
            .unwrap();

        // Second reuse should work for multi-use invitations
        let reuse2 = HandshakeReuseMessage::new(sender_record.invitation.id.clone());
        let result = service
            .process_handshake_reuse(&reuse2, "connection-2".to_string())
            .await;

        assert!(result.is_ok());

        // Verify state is still AwaitResponse
        let updated = service
            .find_by_invitation_id(&sender_record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.state, OutOfBandState::AwaitResponse);
    }

    #[tokio::test]
    async fn test_process_handshake_reuse_single_use_fails() {
        let service = create_test_service();

        // Create single-use invitation
        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let sender_record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                false,
            )
            .await
            .unwrap();

        // First reuse
        let reuse1 = HandshakeReuseMessage::new(sender_record.invitation.id.clone());
        service
            .process_handshake_reuse(&reuse1, "connection-1".to_string())
            .await
            .unwrap();

        // Second reuse should fail
        let reuse2 = HandshakeReuseMessage::new(sender_record.invitation.id.clone());
        let result = service
            .process_handshake_reuse(&reuse2, "connection-2".to_string())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::ConnectionAlreadyExists
        ));
    }

    #[tokio::test]
    async fn test_find_by_recipient_key() {
        let service = create_test_service();

        // Create invitation with inline service
        let inline_service = InlineService::new(
            "#inline-0".to_string(),
            vec!["did:key:z6MkpTHR123".to_string()],
            vec![],
            "https://example.com".to_string(),
        );

        let invitation = OutOfBandInvitation::new(vec![ServiceType::Inline(inline_service)]);

        service.receive_invitation(invitation, None).await.unwrap();

        let records = service
            .find_by_recipient_key("did:key:z6MkpTHR123")
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn test_mark_done() {
        let service = create_test_service();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                false,
            )
            .await
            .unwrap();

        service
            .mark_done(&record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap();

        let updated = service
            .find_by_invitation_id(&record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.state, OutOfBandState::Done);
    }

    #[tokio::test]
    async fn test_delete() {
        let service = create_test_service();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = service
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                None,
                None,
                Some(handshake_protocols),
                false,
            )
            .await
            .unwrap();

        service.delete(&record.id).await.unwrap();

        let found = service.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }
}
