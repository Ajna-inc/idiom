use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::{AttributeInfo, PredicateInfo, Presentation, PresentationRequest};
use anoncreds_core::{AnonCredsHolderService, AnonCredsVerifierService};

use crate::domain::{ProofExchangeRole, ProofExchangeState};
use crate::messages::{AckMessage, AckStatus, PresentationMessage, RequestPresentationMessage};
use crate::repository::{ProofExchangeRecord, ProofExchangeRepositoryTrait};
use crate::{ProofError, Result};

/// Proof Exchange Service
///
/// Handles Present Proof 3.0 protocol business logic, coordinating
/// between the AnonCreds holder/verifier services and the proof exchange repository.
pub struct ProofExchangeService {
    /// AnonCreds holder service (for Prover operations)
    holder: Arc<AnonCredsHolderService>,
    /// AnonCreds verifier service (for Verifier operations)
    verifier: Arc<AnonCredsVerifierService>,
    /// Repository for persisting proof exchange records
    repository: Arc<dyn ProofExchangeRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl ProofExchangeService {
    /// Create a new proof exchange service
    pub fn new(
        holder: Arc<AnonCredsHolderService>,
        verifier: Arc<AnonCredsVerifierService>,
        repository: Arc<dyn ProofExchangeRepositoryTrait>,
    ) -> Self {
        Self {
            holder,
            verifier,
            repository,
            #[cfg(feature = "events")]
            event_bus: None,
            #[cfg(feature = "events")]
            agent_id: "unknown".to_string(),
        }
    }

    /// Set the event bus for emitting proof exchange events
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

    /// Emit a proof state changed event via the typed bus.
    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &ProofExchangeRecord,
        previous_state: Option<ProofExchangeState>,
    ) {
        if let Some(bus) = &self.event_bus {
            let payload = crate::events::ProofStateChangedPayload {
                proof_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(not(feature = "events"))]
    async fn emit_state_changed(
        &self,
        _record: &ProofExchangeRecord,
        _previous_state: Option<ProofExchangeState>,
    ) {
        // Events feature not enabled
    }

    // -----------------------------------------------------------------------
    // Verifier operations
    // -----------------------------------------------------------------------

    /// Create a proof request (Verifier side)
    ///
    /// Creates a PresentationRequest using the AnonCreds verifier service,
    /// stores a ProofExchangeRecord in RequestSent state, and returns
    /// the record along with a DIDComm OutboundMessage.
    pub async fn create_request(
        &self,
        name: &str,
        version: &str,
        requested_attributes: HashMap<String, AttributeInfo>,
        requested_predicates: HashMap<String, PredicateInfo>,
        connection_id: Option<String>,
    ) -> Result<(ProofExchangeRecord, RequestPresentationMessage)> {
        // Create the AnonCreds presentation request
        let pres_request = AnonCredsVerifierService::create_presentation_request(
            name,
            version,
            requested_attributes,
            requested_predicates,
        )
        .map_err(|e| ProofError::AnonCreds(e.to_string()))?;

        let pres_request_json = serde_json::to_string(&pres_request)?;

        // Create the DIDComm message
        let request_msg = RequestPresentationMessage::new(pres_request_json.clone());

        // Create the proof exchange record
        let thread_id = request_msg.id.clone();
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Verifier,
            ProofExchangeState::RequestSent,
            thread_id,
        );
        record.set_presentation_request(pres_request_json);

        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id);
        }

        // Save the record
        self.repository.save(&record).await?;

        // Emit event
        self.emit_state_changed(&record, None).await;

        tracing::debug!(
            "Created proof request: exchange_id={}, thread_id={}",
            record.id,
            record.thread_id
        );

        Ok((record, request_msg))
    }

    /// Process an incoming presentation (Verifier side)
    ///
    /// Stores the presentation and transitions to PresentationReceived state.
    pub async fn process_presentation(
        &self,
        presentation_msg: &PresentationMessage,
    ) -> Result<ProofExchangeRecord> {
        // Find the exchange by thread ID (Verifier role)
        let mut record = self
            .repository
            .find_by_role_and_thread_id(ProofExchangeRole::Verifier, &presentation_msg.thread_id)
            .await?
            .ok_or_else(|| {
                ProofError::NotFound(format!(
                    "thread_id: {} (verifier)",
                    presentation_msg.thread_id
                ))
            })?;

        // Verify state
        if record.state != ProofExchangeState::RequestSent {
            return Err(ProofError::InvalidState {
                expected: vec![ProofExchangeState::RequestSent],
                actual: record.state,
            });
        }

        // Store the presentation
        record.set_presentation(presentation_msg.presentation_json.clone());
        record.update_state(ProofExchangeState::PresentationReceived);
        self.repository.update(&record).await?;

        // Emit event
        self.emit_state_changed(&record, Some(ProofExchangeState::RequestSent))
            .await;

        tracing::debug!(
            "Presentation received: exchange_id={}, state={:?}",
            record.id,
            record.state
        );

        Ok(record)
    }

    /// Verify a presentation (Verifier side)
    ///
    /// Verifies the stored presentation against the stored proof request
    /// using the AnonCreds verifier service.
    pub async fn verify_presentation(&self, exchange_id: &str) -> Result<bool> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| ProofError::NotFound(exchange_id.to_string()))?;

        // Verify role and state
        if record.role != ProofExchangeRole::Verifier {
            return Err(ProofError::InvalidRole {
                expected: ProofExchangeRole::Verifier,
                actual: record.role,
            });
        }

        if record.state != ProofExchangeState::PresentationReceived {
            return Err(ProofError::InvalidState {
                expected: vec![ProofExchangeState::PresentationReceived],
                actual: record.state,
            });
        }

        // Deserialize the presentation request and presentation
        let pres_request_json = record
            .presentation_request_json
            .as_ref()
            .ok_or_else(|| ProofError::Protocol("Missing presentation request".to_string()))?;
        let pres_request: PresentationRequest = serde_json::from_str(pres_request_json)?;

        let presentation_json = record
            .presentation_json
            .as_ref()
            .ok_or_else(|| ProofError::Protocol("Missing presentation".to_string()))?;
        let presentation: Presentation = serde_json::from_str(presentation_json)?;

        // Verify using AnonCreds
        let verified = self
            .verifier
            .verify_presentation(&presentation, &pres_request)
            .await
            .map_err(|e| ProofError::VerificationFailed(e.to_string()))?;

        // Update record
        record.set_verified(verified);
        record.update_state(ProofExchangeState::Done);
        self.repository.update(&record).await?;

        // Emit event
        self.emit_state_changed(&record, Some(ProofExchangeState::PresentationReceived))
            .await;

        tracing::debug!(
            "Presentation verified: exchange_id={}, verified={}",
            record.id,
            verified
        );

        Ok(verified)
    }

    /// Extract revealed attributes from a verified presentation (Verifier side)
    pub fn get_revealed_attributes(
        &self,
        record: &ProofExchangeRecord,
    ) -> Result<HashMap<String, String>> {
        let presentation_json = record
            .presentation_json
            .as_ref()
            .ok_or_else(|| ProofError::Protocol("Missing presentation".to_string()))?;
        let presentation: Presentation = serde_json::from_str(presentation_json)?;

        Ok(AnonCredsVerifierService::extract_revealed_attributes(
            &presentation,
        ))
    }

    // -----------------------------------------------------------------------
    // Prover operations
    // -----------------------------------------------------------------------

    /// Process an incoming proof request (Prover side)
    ///
    /// Stores the request and creates a ProofExchangeRecord in RequestReceived state.
    pub async fn process_request(
        &self,
        request_msg: &RequestPresentationMessage,
        thread_id: &str,
        connection_id: Option<String>,
    ) -> Result<ProofExchangeRecord> {
        let mut record = ProofExchangeRecord::new(
            ProofExchangeRole::Prover,
            ProofExchangeState::RequestReceived,
            thread_id.to_string(),
        );
        record.set_presentation_request(request_msg.proof_request_json.clone());

        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id);
        }

        // Save the record
        self.repository.save(&record).await?;

        // Emit event
        self.emit_state_changed(&record, None).await;

        tracing::debug!(
            "Proof request received: exchange_id={}, thread_id={}",
            record.id,
            record.thread_id
        );

        Ok(record)
    }

    /// Accept a proof request and create a presentation (Prover side)
    ///
    /// Uses the AnonCreds holder service to create a presentation for
    /// the stored proof request, using the provided credential map.
    ///
    /// # Arguments
    /// * `exchange_id` - The proof exchange record ID
    /// * `credential_map` - Map of referent -> (credential_id, revealed)
    /// * `self_attested` - Optional self-attested attributes
    pub async fn accept_request(
        &self,
        exchange_id: &str,
        credential_map: &HashMap<String, (String, bool)>,
        self_attested: Option<HashMap<String, String>>,
    ) -> Result<(ProofExchangeRecord, PresentationMessage)> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| ProofError::NotFound(exchange_id.to_string()))?;

        // Verify role and state
        if record.role != ProofExchangeRole::Prover {
            return Err(ProofError::InvalidRole {
                expected: ProofExchangeRole::Prover,
                actual: record.role,
            });
        }

        if record.state != ProofExchangeState::RequestReceived {
            return Err(ProofError::InvalidState {
                expected: vec![ProofExchangeState::RequestReceived],
                actual: record.state,
            });
        }

        // Deserialize the presentation request
        let pres_request_json = record
            .presentation_request_json
            .as_ref()
            .ok_or_else(|| ProofError::Protocol("Missing presentation request".to_string()))?;
        let pres_request: PresentationRequest = serde_json::from_str(pres_request_json)?;

        // Create the presentation using AnonCreds
        let presentation = self
            .holder
            .create_presentation(&pres_request, credential_map, self_attested)
            .await
            .map_err(|e| ProofError::AnonCreds(e.to_string()))?;

        let presentation_json = serde_json::to_string(&presentation)?;

        // Create the DIDComm message
        let presentation_msg =
            PresentationMessage::new(record.thread_id.clone(), presentation_json.clone());

        // Update record
        record.set_presentation(presentation_json);
        record.update_state(ProofExchangeState::PresentationSent);
        self.repository.update(&record).await?;

        // Emit event
        self.emit_state_changed(&record, Some(ProofExchangeState::RequestReceived))
            .await;

        tracing::debug!(
            "Presentation created: exchange_id={}, state={:?}",
            record.id,
            record.state
        );

        Ok((record, presentation_msg))
    }

    /// Process an incoming ack (Prover side)
    ///
    /// Transitions the exchange to Done state.
    pub async fn process_ack(&self, ack: &AckMessage) -> Result<ProofExchangeRecord> {
        // Find the exchange by thread ID (Prover role)
        let mut record = self
            .repository
            .find_by_role_and_thread_id(ProofExchangeRole::Prover, &ack.thread_id)
            .await?
            .ok_or_else(|| {
                ProofError::NotFound(format!("thread_id: {} (prover)", ack.thread_id))
            })?;

        // Verify state
        if record.state != ProofExchangeState::PresentationSent {
            return Err(ProofError::InvalidState {
                expected: vec![ProofExchangeState::PresentationSent],
                actual: record.state,
            });
        }

        // Update state based on ack status
        match ack.status {
            AckStatus::Ok => {
                record.set_verified(true);
                record.update_state(ProofExchangeState::Done);
            }
            AckStatus::Fail => {
                record.set_verified(false);
                record.set_error("Verifier rejected the presentation".to_string());
            }
            AckStatus::Pending => {
                // Keep in current state, verifier is still processing
                tracing::debug!("Ack status PENDING, keeping current state");
                return Ok(record);
            }
        }

        self.repository.update(&record).await?;

        // Emit event
        self.emit_state_changed(&record, Some(ProofExchangeState::PresentationSent))
            .await;

        tracing::debug!(
            "Ack processed: exchange_id={}, state={:?}",
            record.id,
            record.state
        );

        Ok(record)
    }

    // -----------------------------------------------------------------------
    // Query operations
    // -----------------------------------------------------------------------

    /// Get a proof exchange by ID
    pub async fn get_by_id(&self, id: &str) -> Result<Option<ProofExchangeRecord>> {
        self.repository.find_by_id(id).await
    }

    /// Get a proof exchange by thread ID
    pub async fn get_by_thread_id(&self, thread_id: &str) -> Result<Option<ProofExchangeRecord>> {
        self.repository.find_by_thread_id(thread_id).await
    }

    /// Get all proof exchanges
    pub async fn get_all(&self) -> Result<Vec<ProofExchangeRecord>> {
        self.repository.get_all().await
    }

    /// Get all proof exchanges for a connection
    pub async fn get_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Vec<ProofExchangeRecord>> {
        self.repository.find_by_connection_id(connection_id).await
    }

    /// Delete a proof exchange
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.repository.delete(id).await
    }

    /// Abandon a proof exchange — transitions to Abandoned state with a reason.
    /// No-ops if the exchange is already terminal so callers can safely retry.
    pub async fn abandon_exchange(&self, exchange_id: &str, reason: &str) -> Result<()> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| ProofError::NotFound(exchange_id.to_string()))?;

        if record.state.is_terminal() {
            return Ok(());
        }

        let prev_state = record.state;
        record.set_error(reason.to_string());
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(prev_state)).await;
        tracing::debug!(exchange_id = %record.id, reason = %reason, "abandoned proof exchange");
        Ok(())
    }

    /// Find credentials matching a proof request (Prover side)
    ///
    /// Takes the presentation request JSON string and returns a map of
    /// referent -> list of matching credential IDs.
    pub async fn find_credentials_for_request(
        &self,
        presentation_request_json: &str,
    ) -> Result<HashMap<String, Vec<String>>> {
        let pres_request: PresentationRequest = serde_json::from_str(presentation_request_json)?;

        self.holder
            .find_credentials_for_request(&pres_request)
            .await
            .map_err(|e| ProofError::AnonCreds(e.to_string()))
    }

    /// Find credentials for a stored proof exchange (Prover side)
    ///
    /// Convenience method that looks up the exchange record and finds
    /// credentials matching the stored proof request.
    pub async fn find_credentials_for_exchange(
        &self,
        exchange_id: &str,
    ) -> Result<HashMap<String, Vec<String>>> {
        let record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| ProofError::NotFound(exchange_id.to_string()))?;

        let pres_request_json = record
            .presentation_request_json
            .as_ref()
            .ok_or_else(|| ProofError::Protocol("Missing presentation request".to_string()))?;

        self.find_credentials_for_request(pres_request_json).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::ProofExchangeRepository;
    use anoncreds_core::InMemoryRegistry;

    fn create_test_service() -> ProofExchangeService {
        let registry = Arc::new(InMemoryRegistry::new());
        let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));
        let verifier = Arc::new(AnonCredsVerifierService::new(registry));
        let repo = Arc::new(ProofExchangeRepository::new());

        ProofExchangeService::new(holder, verifier, repo)
    }

    #[tokio::test]
    async fn test_create_request() {
        let service = create_test_service();

        let mut attrs = HashMap::new();
        attrs.insert(
            "attr1_referent".to_string(),
            AttributeInfo {
                name: Some("name".to_string()),
                names: None,
                restrictions: None,
                non_revoked: None,
            },
        );

        let (record, msg) = service
            .create_request("test-proof", "1.0", attrs, HashMap::new(), None)
            .await
            .unwrap();

        assert_eq!(record.role, ProofExchangeRole::Verifier);
        assert_eq!(record.state, ProofExchangeState::RequestSent);
        assert!(record.presentation_request_json.is_some());
        assert!(!msg.proof_request_json.is_empty());
    }

    #[tokio::test]
    async fn test_create_request_with_connection() {
        let service = create_test_service();

        let (record, _) = service
            .create_request(
                "test",
                "1.0",
                HashMap::new(),
                HashMap::new(),
                Some("conn-123".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(record.connection_id, Some("conn-123".to_string()));
    }

    #[tokio::test]
    async fn test_process_request() {
        let service = create_test_service();

        let request_msg = RequestPresentationMessage::new(
            r#"{"name":"test","version":"1.0","nonce":"123","requested_attributes":{},"requested_predicates":{}}"#
                .to_string(),
        );

        let record = service
            .process_request(&request_msg, &request_msg.id, Some("conn-1".to_string()))
            .await
            .unwrap();

        assert_eq!(record.role, ProofExchangeRole::Prover);
        assert_eq!(record.state, ProofExchangeState::RequestReceived);
        assert!(record.presentation_request_json.is_some());
        assert_eq!(record.connection_id, Some("conn-1".to_string()));
    }

    #[tokio::test]
    async fn test_process_presentation() {
        let service = create_test_service();

        // First create a request as Verifier
        let (verifier_record, _) = service
            .create_request("test", "1.0", HashMap::new(), HashMap::new(), None)
            .await
            .unwrap();

        // Simulate receiving a presentation
        let presentation_msg = PresentationMessage::new(
            verifier_record.thread_id.clone(),
            r#"{"proof":{},"requested_proof":{"revealed_attrs":{},"revealed_attr_groups":{},"self_attested_attrs":{},"unrevealed_attrs":{},"predicates":{}},"identifiers":[]}"#.to_string(),
        );

        let updated = service
            .process_presentation(&presentation_msg)
            .await
            .unwrap();

        assert_eq!(updated.state, ProofExchangeState::PresentationReceived);
        assert!(updated.presentation_json.is_some());
    }

    #[tokio::test]
    async fn test_process_presentation_wrong_state() {
        let service = create_test_service();

        // Create a request and then process the presentation twice
        let (verifier_record, _) = service
            .create_request("test", "1.0", HashMap::new(), HashMap::new(), None)
            .await
            .unwrap();

        let presentation_msg =
            PresentationMessage::new(verifier_record.thread_id.clone(), "{}".to_string());

        // First time should succeed
        service
            .process_presentation(&presentation_msg)
            .await
            .unwrap();

        // Second time should fail (already in PresentationReceived state)
        let result = service.process_presentation(&presentation_msg).await;
        assert!(result.is_err());
        match result {
            Err(ProofError::InvalidState { .. }) => {}
            _ => panic!("Expected InvalidState error"),
        }
    }

    #[tokio::test]
    async fn test_process_ack() {
        let service = create_test_service();

        // Create a proof exchange as Prover in PresentationSent state
        let request_msg = RequestPresentationMessage::new("{}".to_string());
        let thread_id = request_msg.id.clone();

        let mut record = service
            .process_request(&request_msg, &thread_id, None)
            .await
            .unwrap();

        // Manually set to PresentationSent (since we can't create a real presentation without credentials)
        record.update_state(ProofExchangeState::PresentationSent);
        service.repository.update(&record).await.unwrap();

        // Process ack
        let ack = AckMessage::new(thread_id, AckStatus::Ok);
        let updated = service.process_ack(&ack).await.unwrap();

        assert_eq!(updated.state, ProofExchangeState::Done);
        assert_eq!(updated.verified, Some(true));
    }

    #[tokio::test]
    async fn test_process_ack_fail() {
        let service = create_test_service();

        let request_msg = RequestPresentationMessage::new("{}".to_string());
        let thread_id = request_msg.id.clone();

        let mut record = service
            .process_request(&request_msg, &thread_id, None)
            .await
            .unwrap();

        record.update_state(ProofExchangeState::PresentationSent);
        service.repository.update(&record).await.unwrap();

        let ack = AckMessage::new(thread_id, AckStatus::Fail);
        let updated = service.process_ack(&ack).await.unwrap();

        assert_eq!(updated.state, ProofExchangeState::Abandoned);
        assert_eq!(updated.verified, Some(false));
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let service = create_test_service();

        let (record, _) = service
            .create_request("test", "1.0", HashMap::new(), HashMap::new(), None)
            .await
            .unwrap();

        let found = service.get_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_get_by_thread_id() {
        let service = create_test_service();

        let (record, _) = service
            .create_request("test", "1.0", HashMap::new(), HashMap::new(), None)
            .await
            .unwrap();

        let found = service.get_by_thread_id(&record.thread_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().thread_id, record.thread_id);
    }

    #[tokio::test]
    async fn test_delete() {
        let service = create_test_service();

        let (record, _) = service
            .create_request("test", "1.0", HashMap::new(), HashMap::new(), None)
            .await
            .unwrap();

        service.delete(&record.id).await.unwrap();

        let found = service.get_by_id(&record.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_full_verifier_flow() {
        let service = create_test_service();

        // 1. Verifier creates request
        let mut attrs = HashMap::new();
        attrs.insert(
            "name_referent".to_string(),
            AttributeInfo {
                name: Some("name".to_string()),
                names: None,
                restrictions: None,
                non_revoked: None,
            },
        );

        let (record, _request_msg) = service
            .create_request(
                "id-check",
                "1.0",
                attrs,
                HashMap::new(),
                Some("conn-1".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(record.state, ProofExchangeState::RequestSent);

        // 2. Verifier receives presentation
        let presentation_msg = PresentationMessage::new(
            record.thread_id.clone(),
            r#"{"proof":{},"requested_proof":{"revealed_attrs":{},"revealed_attr_groups":{},"self_attested_attrs":{},"unrevealed_attrs":{},"predicates":{}},"identifiers":[]}"#.to_string(),
        );

        let record = service
            .process_presentation(&presentation_msg)
            .await
            .unwrap();
        assert_eq!(record.state, ProofExchangeState::PresentationReceived);
        assert!(record.presentation_json.is_some());
    }
}
