use std::sync::Arc;

use crate::domain::OutOfBandRole;
use crate::error::Result;
use crate::messages::{
    HandshakeReuseAcceptedMessage, HandshakeReuseMessage, OutOfBandInvitation,
    OutOfBandService as ServiceType,
};
use crate::repository::{OutOfBandRecord, OutOfBandRepository};
use crate::services::OutOfBandService;

/// Public API for Out-of-Band protocol
///
/// This provides a clean, ergonomic interface for using the OOB protocol.
/// It wraps the OutOfBandService and provides simplified methods for common operations.
pub struct OutOfBandApi {
    service: Arc<OutOfBandService>,
}

impl OutOfBandApi {
    /// Create a new OutOfBandApi with the given repository
    pub fn new(repository: Arc<OutOfBandRepository>) -> Self {
        let service = Arc::new(OutOfBandService::new(repository));
        Self { service }
    }

    /// Create a new OutOfBandApi with the given service
    pub fn with_service(service: Arc<OutOfBandService>) -> Self {
        Self { service }
    }

    /// Create a new Out-of-Band invitation
    ///
    /// # Arguments
    /// * `services` - Service endpoints (DIDs or inline services)
    /// * `label` - Optional human-readable label for the inviter
    /// * `handshake_protocols` - Optional list of supported handshake protocols
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_invitation(
        &self,
        services: Vec<ServiceType>,
        label: Option<String>,
        handshake_protocols: Option<Vec<String>>,
    ) -> Result<OutOfBandRecord> {
        self.service
            .create_invitation(services, label, None, None, handshake_protocols, false)
            .await
    }

    /// Create a multi-use Out-of-Band invitation
    ///
    /// # Arguments
    /// * `services` - Service endpoints (DIDs or inline services)
    /// * `label` - Optional human-readable label for the inviter
    /// * `handshake_protocols` - Optional list of supported handshake protocols
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_multi_use_invitation(
        &self,
        services: Vec<ServiceType>,
        label: Option<String>,
        handshake_protocols: Option<Vec<String>>,
    ) -> Result<OutOfBandRecord> {
        self.service
            .create_invitation(services, label, None, None, handshake_protocols, true)
            .await
    }

    /// Create an invitation with a goal
    ///
    /// # Arguments
    /// * `services` - Service endpoints (DIDs or inline services)
    /// * `label` - Optional human-readable label for the inviter
    /// * `goal_code` - Machine-readable goal code
    /// * `goal` - Human-readable goal description
    /// * `handshake_protocols` - Optional list of supported handshake protocols
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn create_invitation_with_goal(
        &self,
        services: Vec<ServiceType>,
        label: Option<String>,
        goal_code: String,
        goal: String,
        handshake_protocols: Option<Vec<String>>,
    ) -> Result<OutOfBandRecord> {
        self.service
            .create_invitation(
                services,
                label,
                Some(goal_code),
                Some(goal),
                handshake_protocols,
                false,
            )
            .await
    }

    /// Receive and process an Out-of-Band invitation
    ///
    /// # Arguments
    /// * `invitation` - The received invitation message
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn receive_invitation(
        &self,
        invitation: OutOfBandInvitation,
    ) -> Result<OutOfBandRecord> {
        self.service.receive_invitation(invitation, None).await
    }

    /// Receive and process an Out-of-Band invitation with auto-accept
    ///
    /// # Arguments
    /// * `invitation` - The received invitation message
    /// * `auto_accept` - Whether to auto-accept connections from this invitation
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn receive_invitation_with_auto_accept(
        &self,
        invitation: OutOfBandInvitation,
        auto_accept: bool,
    ) -> Result<OutOfBandRecord> {
        self.service
            .receive_invitation(invitation, Some(auto_accept))
            .await
    }

    /// Receive an invitation from a URL
    ///
    /// # Arguments
    /// * `url` - The invitation URL (containing ?oob=... parameter)
    ///
    /// # Returns
    /// The created OutOfBandRecord
    pub async fn receive_invitation_from_url(&self, url: &str) -> Result<OutOfBandRecord> {
        let invitation = OutOfBandInvitation::from_url(url)
            .map_err(|e| crate::error::OutOfBandError::InvalidInvitationUrl(e.to_string()))?;
        self.receive_invitation(invitation).await
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
        self.service.create_handshake_reuse(invitation_id).await
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
        self.service
            .process_handshake_reuse(message, connection_id)
            .await
    }

    /// Find an Out-of-Band record by ID
    pub async fn find_by_id(&self, id: &str) -> Result<Option<OutOfBandRecord>> {
        self.service.find_by_id(id).await
    }

    /// Find an Out-of-Band record by invitation ID
    pub async fn find_by_invitation_id(
        &self,
        invitation_id: &str,
        role: OutOfBandRole,
    ) -> Result<Option<OutOfBandRecord>> {
        self.service
            .find_by_invitation_id(invitation_id, role)
            .await
    }

    /// Find records by recipient key fingerprint
    pub async fn find_by_recipient_key(
        &self,
        recipient_key_fingerprint: &str,
    ) -> Result<Vec<OutOfBandRecord>> {
        self.service
            .find_by_recipient_key(recipient_key_fingerprint)
            .await
    }

    /// Get all Out-of-Band records
    pub async fn get_all(&self) -> Result<Vec<OutOfBandRecord>> {
        self.service.get_all().await
    }

    /// Delete an Out-of-Band record
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.service.delete(id).await
    }

    /// Mark an invitation as done
    pub async fn mark_done(&self, invitation_id: &str, role: OutOfBandRole) -> Result<()> {
        self.service.mark_done(invitation_id, role).await
    }

    /// Get the invitation URL for sharing
    ///
    /// # Arguments
    /// * `record` - The OutOfBandRecord containing the invitation
    /// * `domain` - The base domain for the URL (e.g., "https://example.com")
    ///
    /// # Returns
    /// A URL string that can be shared (e.g., via QR code)
    pub fn get_invitation_url(&self, record: &OutOfBandRecord, domain: &str) -> Result<String> {
        record
            .invitation
            .to_url(domain)
            .map_err(|e| crate::error::OutOfBandError::InvalidInvitationUrl(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OutOfBandState;

    fn create_test_api() -> OutOfBandApi {
        let repo = Arc::new(OutOfBandRepository::new());
        OutOfBandApi::new(repo)
    }

    #[tokio::test]
    async fn test_create_invitation() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        assert_eq!(record.role, OutOfBandRole::Sender);
        assert_eq!(record.state, OutOfBandState::AwaitResponse);
        assert!(!record.reusable);
    }

    #[tokio::test]
    async fn test_create_multi_use_invitation() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_multi_use_invitation(
                services,
                Some("Test Agent".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        assert!(record.reusable);
    }

    #[tokio::test]
    async fn test_create_invitation_with_goal() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_invitation_with_goal(
                services,
                Some("Test Agent".to_string()),
                "issue-vc".to_string(),
                "To issue a credential".to_string(),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        assert_eq!(record.invitation.goal_code, Some("issue-vc".to_string()));
        assert_eq!(
            record.invitation.goal,
            Some("To issue a credential".to_string())
        );
    }

    #[tokio::test]
    async fn test_receive_invitation() {
        let api = create_test_api();

        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())])
                .with_label("Test Agent".to_string());

        let record = api.receive_invitation(invitation.clone()).await.unwrap();

        assert_eq!(record.role, OutOfBandRole::Receiver);
        assert_eq!(record.state, OutOfBandState::PrepareResponse);
        assert_eq!(record.invitation.id, invitation.id);
    }

    #[tokio::test]
    async fn test_receive_invitation_with_auto_accept() {
        let api = create_test_api();

        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())]);

        let record = api
            .receive_invitation_with_auto_accept(invitation, true)
            .await
            .unwrap();

        assert_eq!(record.auto_accept_connection, Some(true));
    }

    #[tokio::test]
    async fn test_receive_invitation_from_url() {
        let api = create_test_api();

        // Create an invitation
        let invitation =
            OutOfBandInvitation::new(vec![ServiceType::Did("did:example:123".to_string())])
                .with_label("Test Agent".to_string());

        let url = invitation.to_url("https://example.com").unwrap();

        // Receive from URL
        let record = api.receive_invitation_from_url(&url).await.unwrap();

        assert_eq!(record.invitation.id, invitation.id);
        assert_eq!(record.invitation.label, invitation.label);
    }

    #[tokio::test]
    async fn test_get_invitation_url() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_invitation(
                services,
                Some("Test".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        let url = api
            .get_invitation_url(&record, "https://example.com")
            .unwrap();

        assert!(url.starts_with("https://example.com?oob="));
    }

    #[tokio::test]
    async fn test_find_operations() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_invitation(
                services,
                Some("Test".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        // Find by ID
        let found = api.find_by_id(&record.id).await.unwrap();
        assert!(found.is_some());

        // Find by invitation ID
        let found = api
            .find_by_invitation_id(&record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap();
        assert!(found.is_some());

        // Get all
        let all = api.get_all().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_mark_done_and_delete() {
        let api = create_test_api();

        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let record = api
            .create_invitation(
                services,
                Some("Test".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        // Mark done
        api.mark_done(&record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap();

        let updated = api
            .find_by_invitation_id(&record.invitation.id, OutOfBandRole::Sender)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.state, OutOfBandState::Done);

        // Delete
        api.delete(&record.id).await.unwrap();

        let found = api.find_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_handshake_reuse_flow() {
        let api = create_test_api();

        // Create sender invitation
        let services = vec![ServiceType::Did("did:example:123".to_string())];
        let handshake_protocols = vec!["https://didcomm.org/didexchange/1.1".to_string()];

        let sender_record = api
            .create_invitation(
                services,
                Some("Test Agent".to_string()),
                Some(handshake_protocols),
            )
            .await
            .unwrap();

        // Receiver gets invitation
        let receiver_record = api
            .receive_invitation(sender_record.invitation.clone())
            .await
            .unwrap();

        // Create handshake reuse
        let reuse_message = api
            .create_handshake_reuse(&receiver_record.invitation.id)
            .await
            .unwrap();

        // Process handshake reuse
        let accepted = api
            .process_handshake_reuse(&reuse_message, "connection-123".to_string())
            .await
            .unwrap();

        assert_eq!(
            accepted.thread.parent_thread_id,
            Some(sender_record.invitation.id)
        );
    }
}
