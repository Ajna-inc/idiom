use crate::domain::{CredentialExchangeRole, CredentialExchangeState};
use crate::messages::{
    IssueCredentialMessage, OfferCredentialMessage, ProposeCredentialMessage,
    RequestCredentialMessage,
};
use crate::repository::{CredentialExchangeRecord, CredentialExchangeRepositoryTrait};
use crate::{CredentialError, Result};
use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService};
use didcomm::messaging::OutboundMessage;
use std::collections::HashMap;
use std::sync::Arc;

/// Credential Exchange Service
///
/// Orchestrates the Issue Credential v3 protocol, coordinating between
/// AnonCreds issuer/holder services and the credential exchange repository.
pub struct CredentialExchangeService {
    issuer: Arc<AnonCredsIssuerService>,
    holder: Arc<AnonCredsHolderService>,
    repository: Arc<dyn CredentialExchangeRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl CredentialExchangeService {
    pub fn new(
        issuer: Arc<AnonCredsIssuerService>,
        holder: Arc<AnonCredsHolderService>,
        repository: Arc<dyn CredentialExchangeRepositoryTrait>,
    ) -> Self {
        Self {
            issuer,
            holder,
            repository,
            #[cfg(feature = "events")]
            event_bus: None,
            #[cfg(feature = "events")]
            agent_id: "unknown".to_string(),
        }
    }

    /// Set the event bus for emitting credential exchange state-change events.
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

    /// Emit a credential-exchange state-changed event via the typed bus.
    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &CredentialExchangeRecord,
        previous_state: Option<CredentialExchangeState>,
    ) {
        if let Some(bus) = &self.event_bus {
            let payload = crate::events::CredentialStateChangedPayload {
                credential_exchange_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(not(feature = "events"))]
    async fn emit_state_changed(
        &self,
        _record: &CredentialExchangeRecord,
        _previous_state: Option<CredentialExchangeState>,
    ) {
        // Events feature not enabled.
    }

    /// Find an exchange record by thread ID
    pub async fn find_exchange_by_thread_id(
        &self,
        thread_id: &str,
    ) -> Result<Option<CredentialExchangeRecord>> {
        self.repository.find_by_thread_id(thread_id).await
    }

    /// Find an exchange record by ID
    pub async fn find_exchange_by_id(
        &self,
        exchange_id: &str,
    ) -> Result<Option<CredentialExchangeRecord>> {
        self.repository.find_by_id(exchange_id).await
    }

    /// Create a credential proposal (Holder side, initiator).
    ///
    /// Builds a `ProposeCredentialMessage` and creates a new exchange record
    /// in `ProposalSent` state. The proposal JSON typically carries the
    /// `schema_id` and `cred_def_id` the holder wants the issuer to offer.
    pub async fn create_proposal(
        &self,
        connection_id: Option<&str>,
        schema_id: Option<&str>,
        cred_def_id: Option<&str>,
        comment: Option<String>,
    ) -> Result<(CredentialExchangeRecord, ProposeCredentialMessage)> {
        let proposal_value = serde_json::json!({
            "schema_id": schema_id,
            "cred_def_id": cred_def_id,
        });
        let proposal_json = serde_json::to_string(&proposal_value)?;

        let mut propose_msg = ProposeCredentialMessage::new(proposal_json.clone());
        if let Some(c) = comment {
            propose_msg = propose_msg.with_comment(c);
        }

        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Holder,
            CredentialExchangeState::ProposalSent,
            propose_msg.thread_id.clone(),
        );
        record.schema_id = schema_id.map(|s| s.to_string());
        record.cred_def_id = cred_def_id.map(|s| s.to_string());
        record.credential_proposal_json = Some(proposal_json);
        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id.to_string());
        }

        self.repository.save(&record).await?;
        self.emit_state_changed(&record, None).await;
        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "Created credential proposal, exchange in ProposalSent state"
        );
        Ok((record, propose_msg))
    }

    /// Store an inbound credential proposal (Issuer side).
    ///
    /// Called by the propose-credential handler when an unsolicited proposal
    /// arrives. Creates a fresh exchange record in `ProposalReceived` state
    /// so the issuer can later decide to counter with an offer or abandon.
    pub async fn store_proposal(
        &self,
        connection_id: Option<&str>,
        propose_msg: &ProposeCredentialMessage,
    ) -> Result<CredentialExchangeRecord> {
        // Idempotency: if we already saw this thread_id, return the existing record.
        if let Some(existing) = self
            .repository
            .find_by_thread_id(&propose_msg.thread_id)
            .await?
        {
            return Ok(existing);
        }

        // Parse schema_id / cred_def_id from the proposal attachment if present
        let parsed: serde_json::Value =
            serde_json::from_str(&propose_msg.credential_proposal_json).unwrap_or_default();
        let schema_id = parsed
            .get("schema_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let cred_def_id = parsed
            .get("cred_def_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::ProposalReceived,
            propose_msg.thread_id.clone(),
        );
        record.schema_id = schema_id;
        record.cred_def_id = cred_def_id;
        record.credential_proposal_json = Some(propose_msg.credential_proposal_json.clone());
        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id.to_string());
        }

        self.repository.save(&record).await?;
        self.emit_state_changed(&record, None).await;
        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "Stored credential proposal, exchange in ProposalReceived state"
        );
        Ok(record)
    }

    /// Counter a stored proposal with an offer (Issuer side).
    ///
    /// Resolves the exchange by id, builds an AnonCreds offer for the
    /// `schema_id` / `cred_def_id` (which may override the proposed ones),
    /// updates the record to `OfferSent`, and returns the offer DIDComm
    /// message threaded against the proposal.
    pub async fn accept_proposal(
        &self,
        exchange_id: &str,
        schema_id: &str,
        cred_def_id: &str,
    ) -> Result<OfferCredentialMessage> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::ProposalReceived {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::ProposalReceived],
                actual: record.state,
            });
        }
        if record.role != CredentialExchangeRole::Issuer {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Issuer,
                actual: record.role,
            });
        }

        let cred_offer = self
            .issuer
            .create_credential_offer(schema_id, cred_def_id)
            .await?;
        let offer_json = serde_json::to_string(&cred_offer)?;

        // Reuse the existing thread_id so the offer correlates with the proposal.
        let mut offer_msg = OfferCredentialMessage::new(offer_json.clone());
        offer_msg.thread_id = record.thread_id.clone();

        record.schema_id = Some(schema_id.to_string());
        record.cred_def_id = Some(cred_def_id.to_string());
        record.credential_offer_json = Some(offer_json);
        record.update_state(CredentialExchangeState::OfferSent);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::ProposalReceived))
            .await;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "Sent counter-offer for proposal, exchange in OfferSent state"
        );
        Ok(offer_msg)
    }

    /// Create a credential offer (Issuer side)
    ///
    /// Creates an AnonCreds credential offer and a DIDComm offer-credential message.
    /// The exchange record is stored in OfferSent state.
    ///
    /// # Arguments
    /// * `connection_id` - Optional connection ID to associate with the exchange
    /// * `schema_id` - Schema ID for the credential
    /// * `cred_def_id` - Credential definition ID
    ///
    /// # Returns
    /// A tuple of (exchange record, offer DIDComm message)
    pub async fn create_offer(
        &self,
        connection_id: Option<&str>,
        schema_id: &str,
        cred_def_id: &str,
    ) -> Result<(CredentialExchangeRecord, OfferCredentialMessage)> {
        // Create AnonCreds offer
        let cred_offer = self
            .issuer
            .create_credential_offer(schema_id, cred_def_id)
            .await?;

        let offer_json = serde_json::to_string(&cred_offer)?;

        // Create DIDComm message
        let offer_msg = OfferCredentialMessage::new(offer_json.clone());

        // Create exchange record
        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
            offer_msg.thread_id.clone(),
        );
        record.schema_id = Some(schema_id.to_string());
        record.cred_def_id = Some(cred_def_id.to_string());
        record.credential_offer_json = Some(offer_json);

        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id.to_string());
        }

        self.repository.save(&record).await?;
        self.emit_state_changed(&record, None).await;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            schema_id = %schema_id,
            cred_def_id = %cred_def_id,
            "Created credential offer, exchange in OfferSent state"
        );

        Ok((record, offer_msg))
    }

    /// Accept a credential offer (Holder side)
    ///
    /// Creates an AnonCreds credential request in response to a stored offer.
    /// The exchange record transitions to RequestSent state.
    ///
    /// # Arguments
    /// * `exchange_id` - ID of the exchange record (must be in OfferReceived state)
    /// * `entropy` - Prover entropy for the credential request
    ///
    /// # Returns
    /// The request DIDComm message to send to the issuer
    pub async fn accept_offer(
        &self,
        exchange_id: &str,
        entropy: &str,
    ) -> Result<RequestCredentialMessage> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        // Validate state
        if record.state != CredentialExchangeState::OfferReceived {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::OfferReceived],
                actual: record.state,
            });
        }

        // Validate role
        if record.role != CredentialExchangeRole::Holder {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Holder,
                actual: record.role,
            });
        }

        let offer_json = record.credential_offer_json.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential offer stored on exchange".to_string())
        })?;

        let cred_offer: anoncreds_core::types::CredentialOffer = serde_json::from_str(offer_json)?;

        let cred_def_id = record.cred_def_id.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential definition ID on exchange record".to_string())
        })?;

        // Create credential request
        let cred_request = self
            .holder
            .create_credential_request(&record.thread_id, &cred_offer, cred_def_id, entropy)
            .await?;

        let request_json = serde_json::to_string(&cred_request)?;

        // Create DIDComm message
        let request_msg =
            RequestCredentialMessage::new(record.thread_id.clone(), request_json.clone());

        // Update exchange record
        record.credential_request_json = Some(request_json);
        record.update_state(CredentialExchangeState::RequestSent);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::OfferReceived))
            .await;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "Created credential request, exchange in RequestSent state"
        );

        Ok(request_msg)
    }

    /// Store a credential request on an exchange record (Issuer side)
    ///
    /// Called by the RequestCredentialHandler when a request is received.
    /// Transitions the exchange to RequestReceived state.
    pub async fn store_request(
        &self,
        exchange_id: &str,
        credential_request_json: &str,
    ) -> Result<()> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::OfferSent {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::OfferSent],
                actual: record.state,
            });
        }

        record.credential_request_json = Some(credential_request_json.to_string());
        record.update_state(CredentialExchangeState::RequestReceived);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::OfferSent))
            .await;

        Ok(())
    }

    /// Persist the attributes to auto-issue on the exchange record (issuer side).
    /// Storing them on the record — rather than only in an in-memory map — lets
    /// auto-issue survive a restart and work when a captured request is replayed
    /// against a seeded `OfferSent` exchange (the issuance benchmark path).
    pub async fn set_auto_issue_attributes(
        &self,
        exchange_id: &str,
        attributes: HashMap<String, String>,
    ) -> Result<()> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;
        record.auto_issue_attributes = Some(attributes);
        record.updated_at = chrono::Utc::now();
        self.repository.update(&record).await?;
        Ok(())
    }

    /// Accept a credential request and issue the credential (Issuer side)
    ///
    /// Creates an AnonCreds credential and returns a DIDComm issue-credential message.
    /// The exchange record transitions to CredentialIssued state.
    ///
    /// # Arguments
    /// * `exchange_id` - ID of the exchange record (must be in RequestReceived state)
    /// * `attributes` - Credential attribute name-value pairs
    ///
    /// # Returns
    /// The outbound DIDComm message to send to the holder
    pub async fn accept_request(
        &self,
        exchange_id: &str,
        attributes: HashMap<String, String>,
    ) -> Result<OutboundMessage> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        // Validate state
        if record.state != CredentialExchangeState::RequestReceived {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::RequestReceived],
                actual: record.state,
            });
        }

        // Validate role
        if record.role != CredentialExchangeRole::Issuer {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Issuer,
                actual: record.role,
            });
        }

        let offer_json = record.credential_offer_json.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential offer stored on exchange".to_string())
        })?;
        let request_json = record.credential_request_json.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential request stored on exchange".to_string())
        })?;
        let cred_def_id = record.cred_def_id.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential definition ID on exchange record".to_string())
        })?;

        let cred_offer: anoncreds_core::types::CredentialOffer = serde_json::from_str(offer_json)?;
        let cred_request: anoncreds_core::types::CredentialRequest =
            serde_json::from_str(request_json)?;

        // Issue credential
        let credential = self
            .issuer
            .create_credential(cred_def_id, &cred_offer, &cred_request, attributes)
            .await?;

        let credential_json = serde_json::to_string(&credential)?;

        // Create DIDComm message
        let issue_msg =
            IssueCredentialMessage::new(record.thread_id.clone(), credential_json.clone());
        let didcomm_msg = issue_msg.to_didcomm_message();

        // Update exchange record
        record.credential_json = Some(credential_json);
        record.update_state(CredentialExchangeState::CredentialIssued);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::RequestReceived))
            .await;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "Issued credential, exchange in CredentialIssued state"
        );

        Ok(OutboundMessage {
            message: didcomm_msg,
            to: String::new(),   // To be filled by caller/dispatcher
            from: String::new(), // To be filled by caller/dispatcher
            connection_id: record.connection_id.clone(),
        })
    }

    /// Process a received credential (Holder side)
    ///
    /// Processes the AnonCreds credential (completes the blind signature)
    /// and stores it. The exchange transitions to Done state.
    ///
    /// # Arguments
    /// * `exchange_id` - ID of the exchange record
    /// * `credential_json` - The received credential JSON
    ///
    /// # Returns
    /// The credential ID after storing
    pub async fn process_credential(
        &self,
        exchange_id: &str,
        credential_json: &str,
    ) -> Result<String> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        // Validate state - can be RequestSent (holder side) or CredentialReceived
        if record.state != CredentialExchangeState::RequestSent {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::RequestSent],
                actual: record.state,
            });
        }

        // Validate role
        if record.role != CredentialExchangeRole::Holder {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Holder,
                actual: record.role,
            });
        }

        let cred_def_id = record.cred_def_id.as_ref().ok_or_else(|| {
            CredentialError::Protocol("No credential definition ID on exchange record".to_string())
        })?;

        // Deserialize and process the credential
        let mut credential: anoncreds_core::types::Credential =
            serde_json::from_str(credential_json)?;

        let credential_id = self
            .holder
            .process_credential(&record.thread_id, &mut credential, cred_def_id)
            .await?;

        // Update exchange record
        record.credential_json = Some(credential_json.to_string());
        record.credential_id = Some(credential_id.clone());
        record.update_state(CredentialExchangeState::Done);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::RequestSent))
            .await;

        tracing::debug!(
            exchange_id = %record.id,
            credential_id = %credential_id,
            "Processed credential, exchange is Done"
        );

        Ok(credential_id)
    }

    /// Process an inbound ack (issuer side): the holder acknowledged receipt of
    /// the issued credential. Transitions the exchange to `Done`. Idempotent —
    /// if the record is already `Done` this is a no-op success.
    pub async fn process_ack(&self, thread_id: &str) -> Result<CredentialExchangeRecord> {
        let mut record = self
            .repository
            .find_by_thread_id(thread_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(format!("thread_id: {}", thread_id)))?;

        if record.state == CredentialExchangeState::Done {
            return Ok(record);
        }

        let previous = record.state;
        record.update_state(CredentialExchangeState::Done);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(previous)).await;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %thread_id,
            "Processed credential ack, exchange is Done"
        );

        Ok(record)
    }

    /// Get the repository (for use by handlers and tests)
    pub fn repository(&self) -> &Arc<dyn CredentialExchangeRepositoryTrait> {
        &self.repository
    }

    /// Get all exchange records
    pub async fn get_all_exchanges(&self) -> Result<Vec<CredentialExchangeRecord>> {
        self.repository.get_all().await
    }

    /// Abandon an exchange (set to Abandoned state with error message)
    pub async fn abandon_exchange(&self, exchange_id: &str, reason: &str) -> Result<()> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state.is_terminal() {
            return Err(CredentialError::InvalidState {
                expected: vec![
                    CredentialExchangeState::OfferSent,
                    CredentialExchangeState::OfferReceived,
                    CredentialExchangeState::RequestSent,
                    CredentialExchangeState::RequestReceived,
                    CredentialExchangeState::CredentialIssued,
                    CredentialExchangeState::CredentialReceived,
                ],
                actual: record.state,
            });
        }

        let previous = record.state;
        record.set_error(reason.to_string());
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(previous)).await;

        tracing::debug!(
            exchange_id = %record.id,
            reason = %reason,
            "Abandoned credential exchange"
        );

        Ok(())
    }
}

#[cfg(all(test, feature = "events"))]
mod event_tests {
    use super::*;
    use crate::events::CredentialStateChangedPayload;
    use crate::repository::CredentialExchangeRepository;
    use agent_events::EventBus;
    use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, InMemoryRegistry};

    /// A state transition (create_offer) must publish a
    /// `credential_exchange.state_changed` event when a bus is wired.
    #[tokio::test]
    async fn create_offer_emits_state_changed() {
        let registry = Arc::new(InMemoryRegistry::new());
        let issuer = Arc::new(AnonCredsIssuerService::new(registry.clone()));
        let holder = Arc::new(AnonCredsHolderService::new(registry.clone()));
        let schema = issuer
            .create_schema("did:example:issuer", "EvtCred", "1.0", vec!["name".into()])
            .await
            .unwrap();
        let cred_def = issuer
            .create_credential_definition("did:example:issuer", &schema.schema_id, "default", false)
            .await
            .unwrap();

        let bus = Arc::new(EventBus::new(16));
        let mut sub = bus.subscribe();
        let svc = CredentialExchangeService::new(
            issuer,
            holder,
            Arc::new(CredentialExchangeRepository::new()),
        )
        .with_event_bus(bus.clone(), "tenant-1".into());

        let (record, _msg) = svc
            .create_offer(Some("conn"), &schema.schema_id, &cred_def.cred_def_id)
            .await
            .unwrap();

        let env = sub.recv().await.expect("event published");
        assert_eq!(env.topic, crate::events::topics::CREDENTIAL_EXCHANGE);
        assert_eq!(env.name, crate::events::types::STATE_CHANGED);
        let decoded: CredentialStateChangedPayload = env.payload().unwrap();
        assert_eq!(
            decoded.credential_exchange_record.state,
            CredentialExchangeState::OfferSent
        );
        assert_eq!(decoded.credential_exchange_record.id, record.id);
        assert_eq!(decoded.previous_state, None);
    }
}
