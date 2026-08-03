use crate::domain::{ProofExchangeRole, ProofExchangeState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Proof Exchange Record
///
/// Represents a Present Proof exchange with full state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofExchangeRecord {
    /// Unique identifier for this proof exchange
    pub id: String,

    /// Thread ID from the request-presentation message
    #[serde(rename = "threadId")]
    pub thread_id: String,

    /// Associated connection ID (if exchanged over a connection)
    #[serde(rename = "connectionId", skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,

    /// Role in the Present Proof protocol
    pub role: ProofExchangeRole,

    /// Current state of the proof exchange
    pub state: ProofExchangeState,

    /// Serialized AnonCreds PresentationRequest JSON
    #[serde(
        rename = "presentationRequestJson",
        skip_serializing_if = "Option::is_none"
    )]
    pub presentation_request_json: Option<String>,

    /// Serialized AnonCreds Presentation JSON
    #[serde(rename = "presentationJson", skip_serializing_if = "Option::is_none")]
    pub presentation_json: Option<String>,

    /// Whether the presentation was successfully verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,

    /// Error message if the exchange failed
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Creation timestamp
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl ProofExchangeRecord {
    /// Create a new proof exchange record
    pub fn new(role: ProofExchangeRole, state: ProofExchangeState, thread_id: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            thread_id,
            connection_id: None,
            role,
            state,
            presentation_request_json: None,
            presentation_json: None,
            verified: None,
            error_message: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the connection ID
    pub fn set_connection_id(&mut self, connection_id: String) {
        self.connection_id = Some(connection_id);
        self.updated_at = Utc::now();
    }

    /// Set the presentation request JSON
    pub fn set_presentation_request(&mut self, json: String) {
        self.presentation_request_json = Some(json);
        self.updated_at = Utc::now();
    }

    /// Set the presentation JSON
    pub fn set_presentation(&mut self, json: String) {
        self.presentation_json = Some(json);
        self.updated_at = Utc::now();
    }

    /// Set the verified flag
    pub fn set_verified(&mut self, verified: bool) {
        self.verified = Some(verified);
        self.updated_at = Utc::now();
    }

    /// Update the exchange state
    pub fn update_state(&mut self, new_state: ProofExchangeState) {
        self.state = new_state;
        self.updated_at = Utc::now();
    }

    /// Set error message and transition to Abandoned
    pub fn set_error(&mut self, error: String) {
        self.error_message = Some(error);
        self.state = ProofExchangeState::Abandoned;
        self.updated_at = Utc::now();
    }

    /// Check if the exchange is done
    pub fn is_done(&self) -> bool {
        self.state == ProofExchangeState::Done
    }

    /// Check if the exchange is active (not terminal)
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_creation() {
        let record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
            "thread-123".to_string(),
        );

        assert_eq!(record.role, ProofExchangeRole::Verifier);
        assert_eq!(record.state, ProofExchangeState::RequestSent);
        assert_eq!(record.thread_id, "thread-123");
        assert!(record.connection_id.is_none());
        assert!(record.presentation_request_json.is_none());
        assert!(record.presentation_json.is_none());
        assert!(record.verified.is_none());
        assert!(record.error_message.is_none());
    }

    #[test]
    fn test_update_state() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
            "thread-1".to_string(),
        );

        let initial_updated_at = record.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));

        record.update_state(ProofExchangeState::PresentationReceived);

        assert_eq!(record.state, ProofExchangeState::PresentationReceived);
        assert!(record.updated_at > initial_updated_at);
    }

    #[test]
    fn test_set_presentation_request() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
            "thread-1".to_string(),
        );

        record.set_presentation_request(r#"{"name":"test"}"#.to_string());
        assert_eq!(
            record.presentation_request_json,
            Some(r#"{"name":"test"}"#.to_string())
        );
    }

    #[test]
    fn test_set_verified() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::PresentationReceived,
            "thread-1".to_string(),
        );

        record.set_verified(true);
        assert_eq!(record.verified, Some(true));
    }

    #[test]
    fn test_set_error() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
            "thread-1".to_string(),
        );

        record.set_error("Verification failed".to_string());
        assert_eq!(
            record.error_message,
            Some("Verification failed".to_string())
        );
        assert_eq!(record.state, ProofExchangeState::Abandoned);
    }

    #[test]
    fn test_is_done() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
            "thread-1".to_string(),
        );

        assert!(!record.is_done());

        record.update_state(ProofExchangeState::Done);
        assert!(record.is_done());
    }

    #[test]
    fn test_is_active() {
        let record = ProofExchangeRecord::new(
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
            "thread-1".to_string(),
        );
        assert!(record.is_active());

        let mut done_record = record.clone();
        done_record.update_state(ProofExchangeState::Done);
        assert!(!done_record.is_active());

        let mut abandoned_record = record.clone();
        abandoned_record.set_error("Failed".to_string());
        assert!(!abandoned_record.is_active());
    }

    #[test]
    fn test_serialization() {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::Done,
            "thread-1".to_string(),
        );
        record.set_connection_id("conn-1".to_string());
        record.set_presentation_request(r#"{"name":"test"}"#.to_string());
        record.set_verified(true);

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("threadId"));
        assert!(json.contains("connectionId"));
        assert!(json.contains("presentationRequestJson"));

        let deserialized: ProofExchangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.thread_id, record.thread_id);
        assert_eq!(deserialized.connection_id, record.connection_id);
        assert_eq!(deserialized.verified, record.verified);
    }

    #[test]
    fn test_backward_compatibility() {
        // Test that records without optional fields can be deserialized
        let json = r#"{
            "id": "test-id",
            "threadId": "thread-1",
            "role": "verifier",
            "state": "RequestSent",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        }"#;

        let record: ProofExchangeRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.id, "test-id");
        assert!(record.connection_id.is_none());
        assert!(record.presentation_request_json.is_none());
        assert!(record.presentation_json.is_none());
        assert!(record.verified.is_none());
    }
}
