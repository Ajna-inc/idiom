use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{OutOfBandRole, OutOfBandState};
use crate::error::{OutOfBandError, Result};
use crate::messages::OutOfBandInvitation;

/// Keys associated with inline services in the invitation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineServiceKey {
    /// KMS key ID for this recipient key
    #[serde(rename = "kmsKeyId")]
    pub kms_key_id: String,

    /// Fingerprint of the recipient key
    #[serde(rename = "recipientKeyFingerprint")]
    pub recipient_key_fingerprint: String,
}

impl InlineServiceKey {
    /// Create a new inline service key
    pub fn new(kms_key_id: String, recipient_key_fingerprint: String) -> Self {
        Self {
            kms_key_id,
            recipient_key_fingerprint,
        }
    }
}

/// Tags for efficient querying of Out-of-Band records
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutOfBandTags {
    /// Role in this invitation exchange
    pub role: OutOfBandRole,

    /// Current state
    pub state: OutOfBandState,

    /// Invitation message ID
    #[serde(rename = "invitationId")]
    pub invitation_id: String,

    /// Recipient key fingerprints for this invitation
    #[serde(rename = "recipientKeyFingerprints")]
    pub recipient_key_fingerprints: Vec<String>,

    /// Thread ID (optional, for tracking)
    #[serde(rename = "threadId", skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

impl OutOfBandTags {
    /// Create tags from invitation
    pub fn from_invitation(
        invitation: &OutOfBandInvitation,
        role: OutOfBandRole,
        state: OutOfBandState,
    ) -> Self {
        Self {
            role,
            state,
            invitation_id: invitation.id.clone(),
            recipient_key_fingerprints: Vec::new(),
            thread_id: None,
        }
    }

    /// Add recipient key fingerprint
    pub fn add_recipient_key_fingerprint(&mut self, fingerprint: String) {
        if !self.recipient_key_fingerprints.contains(&fingerprint) {
            self.recipient_key_fingerprints.push(fingerprint);
        }
    }
}

impl Default for OutOfBandTags {
    fn default() -> Self {
        Self {
            role: OutOfBandRole::Sender,
            state: OutOfBandState::Initial,
            invitation_id: String::new(),
            recipient_key_fingerprints: Vec::new(),
            thread_id: None,
        }
    }
}

/// Out-of-Band Record - persisted state for an invitation
///
/// This record tracks the lifecycle of an out-of-band invitation,
/// from creation through connection establishment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutOfBandRecord {
    /// Unique record identifier
    pub id: String,

    /// The out-of-band invitation message
    pub invitation: OutOfBandInvitation,

    /// Role in this invitation exchange
    pub role: OutOfBandRole,

    /// Current state
    pub state: OutOfBandState,

    /// Whether this invitation can be used multiple times
    pub reusable: bool,

    /// Auto-accept connections from this invitation
    #[serde(
        rename = "autoAcceptConnection",
        skip_serializing_if = "Option::is_none"
    )]
    pub auto_accept_connection: Option<bool>,

    /// Associated mediator ID
    #[serde(rename = "mediatorId", skip_serializing_if = "Option::is_none")]
    pub mediator_id: Option<String>,

    /// Alias for created connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Connection ID for handshake reuse
    #[serde(rename = "reuseConnectionId", skip_serializing_if = "Option::is_none")]
    pub reuse_connection_id: Option<String>,

    /// Keys associated with inline services
    #[serde(rename = "invitationInlineServiceKeys")]
    pub invitation_inline_service_keys: Vec<InlineServiceKey>,

    /// Creation timestamp
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    /// Last updated timestamp
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,

    /// Storage tags for queries
    #[serde(skip)]
    pub tags: OutOfBandTags,
}

impl OutOfBandRecord {
    /// Create a new Out-of-Band record
    pub fn new(invitation: OutOfBandInvitation, role: OutOfBandRole) -> Self {
        let now = Utc::now();
        let mut tags = OutOfBandTags::from_invitation(&invitation, role, OutOfBandState::Initial);

        // Extract recipient key fingerprints from inline services
        for service in invitation.get_inline_services() {
            for recipient_key in &service.recipient_keys {
                // For now, use the key itself as fingerprint (in production, compute proper fingerprint)
                tags.add_recipient_key_fingerprint(recipient_key.clone());
            }
        }

        Self {
            id: Uuid::new_v4().to_string(),
            invitation,
            role,
            state: OutOfBandState::Initial,
            reusable: false,
            auto_accept_connection: None,
            mediator_id: None,
            alias: None,
            reuse_connection_id: None,
            invitation_inline_service_keys: Vec::new(),
            created_at: now,
            updated_at: now,
            tags,
        }
    }

    /// Create a new record with ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    /// Set state
    pub fn with_state(mut self, state: OutOfBandState) -> Self {
        self.state = state;
        self.tags.state = state;
        self
    }

    /// Set reusable flag
    pub fn with_reusable(mut self, reusable: bool) -> Self {
        self.reusable = reusable;
        self
    }

    /// Set auto-accept connection
    pub fn with_auto_accept_connection(mut self, auto_accept: bool) -> Self {
        self.auto_accept_connection = Some(auto_accept);
        self
    }

    /// Set mediator ID
    pub fn with_mediator_id(mut self, mediator_id: String) -> Self {
        self.mediator_id = Some(mediator_id);
        self
    }

    /// Set alias
    pub fn with_alias(mut self, alias: String) -> Self {
        self.alias = Some(alias);
        self
    }

    /// Add inline service key
    pub fn add_inline_service_key(&mut self, key: InlineServiceKey) {
        self.invitation_inline_service_keys.push(key.clone());
        self.tags
            .add_recipient_key_fingerprint(key.recipient_key_fingerprint);
    }

    /// Assert expected role
    pub fn assert_role(&self, expected: OutOfBandRole) -> Result<()> {
        if self.role != expected {
            return Err(OutOfBandError::InvalidRole {
                expected,
                actual: self.role,
            });
        }
        Ok(())
    }

    /// Assert expected state(s)
    pub fn assert_state(&self, expected: &[OutOfBandState]) -> Result<()> {
        if !expected.contains(&self.state) {
            return Err(OutOfBandError::InvalidState {
                expected: expected.to_vec(),
                actual: self.state,
            });
        }
        Ok(())
    }

    /// Update state and sync tags
    pub fn update_state(&mut self, new_state: OutOfBandState) {
        self.state = new_state;
        self.tags.state = new_state;
        self.updated_at = Utc::now();
    }

    /// Check if record is in terminal state
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Get invitation ID
    pub fn invitation_id(&self) -> &str {
        &self.invitation.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::OutOfBandService;

    #[test]
    fn test_inline_service_key_creation() {
        let key = InlineServiceKey::new("key-123".to_string(), "fingerprint-456".to_string());

        assert_eq!(key.kms_key_id, "key-123");
        assert_eq!(key.recipient_key_fingerprint, "fingerprint-456");
    }

    #[test]
    fn test_inline_service_key_serialization() {
        let key = InlineServiceKey::new("key-123".to_string(), "fingerprint-456".to_string());

        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("\"kmsKeyId\""));
        assert!(json.contains("\"recipientKeyFingerprint\""));

        let deserialized: InlineServiceKey = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, key);
    }

    #[test]
    fn test_tags_creation() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let tags = OutOfBandTags::from_invitation(
            &invitation,
            OutOfBandRole::Sender,
            OutOfBandState::AwaitResponse,
        );

        assert_eq!(tags.role, OutOfBandRole::Sender);
        assert_eq!(tags.state, OutOfBandState::AwaitResponse);
        assert_eq!(tags.invitation_id, invitation.id);
    }

    #[test]
    fn test_tags_add_recipient_key() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let mut tags = OutOfBandTags::from_invitation(
            &invitation,
            OutOfBandRole::Sender,
            OutOfBandState::AwaitResponse,
        );

        tags.add_recipient_key_fingerprint("fp1".to_string());
        tags.add_recipient_key_fingerprint("fp2".to_string());
        tags.add_recipient_key_fingerprint("fp1".to_string()); // Duplicate

        assert_eq!(tags.recipient_key_fingerprints.len(), 2);
        assert!(tags.recipient_key_fingerprints.contains(&"fp1".to_string()));
        assert!(tags.recipient_key_fingerprints.contains(&"fp2".to_string()));
    }

    #[test]
    fn test_record_creation() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Test".to_string());

        let record = OutOfBandRecord::new(invitation.clone(), OutOfBandRole::Sender);

        assert!(!record.id.is_empty());
        assert_eq!(record.invitation.id, invitation.id);
        assert_eq!(record.role, OutOfBandRole::Sender);
        assert_eq!(record.state, OutOfBandState::Initial);
        assert!(!record.reusable);
        assert!(record.auto_accept_connection.is_none());
    }

    #[test]
    fn test_record_builder() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
            .with_id("custom-id".to_string())
            .with_state(OutOfBandState::AwaitResponse)
            .with_reusable(true)
            .with_auto_accept_connection(true)
            .with_mediator_id("mediator-123".to_string())
            .with_alias("My Invitation".to_string());

        assert_eq!(record.id, "custom-id");
        assert_eq!(record.state, OutOfBandState::AwaitResponse);
        assert!(record.reusable);
        assert_eq!(record.auto_accept_connection, Some(true));
        assert_eq!(record.mediator_id, Some("mediator-123".to_string()));
        assert_eq!(record.alias, Some("My Invitation".to_string()));
    }

    #[test]
    fn test_add_inline_service_key() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let mut record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);

        record.add_inline_service_key(InlineServiceKey::new(
            "key-1".to_string(),
            "fp-1".to_string(),
        ));
        record.add_inline_service_key(InlineServiceKey::new(
            "key-2".to_string(),
            "fp-2".to_string(),
        ));

        assert_eq!(record.invitation_inline_service_keys.len(), 2);
        assert_eq!(record.tags.recipient_key_fingerprints.len(), 2);
    }

    #[test]
    fn test_assert_role_valid() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);

        assert!(record.assert_role(OutOfBandRole::Sender).is_ok());
    }

    #[test]
    fn test_assert_role_invalid() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);

        let result = record.assert_role(OutOfBandRole::Receiver);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::InvalidRole { .. }
        ));
    }

    #[test]
    fn test_assert_state_valid() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
            .with_state(OutOfBandState::AwaitResponse);

        assert!(record
            .assert_state(&[OutOfBandState::AwaitResponse])
            .is_ok());
        assert!(record
            .assert_state(&[OutOfBandState::Initial, OutOfBandState::AwaitResponse])
            .is_ok());
    }

    #[test]
    fn test_assert_state_invalid() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
            .with_state(OutOfBandState::AwaitResponse);

        let result = record.assert_state(&[OutOfBandState::Done]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutOfBandError::InvalidState { .. }
        ));
    }

    #[test]
    fn test_update_state() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let mut record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);
        let created_at = record.created_at;

        // Small delay to ensure updated_at changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        record.update_state(OutOfBandState::AwaitResponse);

        assert_eq!(record.state, OutOfBandState::AwaitResponse);
        assert_eq!(record.tags.state, OutOfBandState::AwaitResponse);
        assert!(record.updated_at > created_at);
    }

    #[test]
    fn test_is_terminal() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);
        assert!(!record.is_terminal());

        let record = record.with_state(OutOfBandState::Done);
        assert!(record.is_terminal());
    }

    #[test]
    fn test_record_serialization() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Test".to_string());

        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
            .with_reusable(true)
            .with_auto_accept_connection(true);

        let json = serde_json::to_string(&record).unwrap();

        // Verify camelCase field names
        assert!(json.contains("\"createdAt\""));
        assert!(json.contains("\"updatedAt\""));
        assert!(json.contains("\"autoAcceptConnection\""));
        assert!(json.contains("\"mediatorId\"") || !json.contains("\"mediator_id\""));

        // Deserialize
        let deserialized: OutOfBandRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.role, record.role);
        assert_eq!(deserialized.state, record.state);
    }

    #[test]
    fn test_invitation_id_getter() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        let invitation_id = invitation.id.clone();
        let record = OutOfBandRecord::new(invitation, OutOfBandRole::Sender);

        assert_eq!(record.invitation_id(), invitation_id);
    }
}
