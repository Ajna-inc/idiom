//! Signing coordinator - manages signing sessions, collects signatures, issues tokens
//!
//! The coordinator is responsible for:
//! - Creating and tracking signing sessions
//! - Collecting consent and partial signatures from participants
//! - Combining signatures when threshold is reached
//! - Creating sealed secrets via HPKE
//! - Issuing authorization tokens with monotonic counters

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use agent_core::traits::{Query, Record, StorageProvider};

use crate::counter::MonotonicCounterManager;
use crate::errors::{Result, SigningProtocolError};
use crate::hpke::HpkeBase;
use crate::models::*;
use crate::state::SigningSessionState;
use crate::storage;

/// The signing coordinator manages session lifecycle and signature aggregation
pub struct SigningCoordinator {
    /// Our DID (coordinator identity)
    our_did: String,
    /// Storage provider for persisting sessions
    storage: Arc<dyn StorageProvider>,
    /// In-memory session cache
    sessions: RwLock<HashMap<String, SigningSession>>,
    /// Monotonic counter manager for token replay protection
    counter_manager: Arc<MonotonicCounterManager>,
    /// Optional typed event bus. When set, every state transition + consent
    /// + partial-signature acceptance + threshold-met + session-completed
    /// emits its corresponding `protocol_signing::events::*` payload.
    event_bus: Option<Arc<agent_events::EventBus>>,
}

impl SigningCoordinator {
    /// Create a new coordinator
    pub fn new(our_did: String, storage: Arc<dyn StorageProvider>) -> Self {
        let counter_manager = Arc::new(MonotonicCounterManager::new(storage.clone()));
        Self {
            our_did,
            storage,
            sessions: RwLock::new(HashMap::new()),
            counter_manager,
            event_bus: None,
        }
    }

    /// Attach the typed event bus. After this, every transition fires
    /// `(signing, *)` events.
    pub fn with_event_bus(mut self, event_bus: Arc<agent_events::EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Internal helper — emit a typed signing event tagged with `our_did`.
    /// Tenant id reuses `our_did` since the coordinator is per-tenant.
    async fn emit<E: agent_events::TypedEvent>(&self, payload: E) {
        if let Some(bus) = &self.event_bus {
            let meta = agent_events::EventMetadata::for_tenant(&self.our_did);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    /// Get our DID
    pub fn our_did(&self) -> &str {
        &self.our_did
    }

    /// Get the counter manager
    pub fn counter_manager(&self) -> &MonotonicCounterManager {
        &self.counter_manager
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Create a new signing session
    pub async fn create_session(
        &self,
        session_id: String,
        thread_id: String,
        object: SignableObject,
        suite: Suite,
        constraints: Option<Constraints>,
        mode: SessionMode,
        threshold: Option<ThresholdConfig>,
        participants: Vec<SessionParticipant>,
    ) -> Result<SigningSession> {
        let now = chrono::Utc::now().to_rfc3339();

        let session = SigningSession {
            session_id: session_id.clone(),
            thread_id,
            object,
            suite,
            constraints,
            mode,
            threshold,
            state: SigningSessionState::Proposed,
            participants,
            coordinator_did: self.our_did.clone(),
            created_at: now.clone(),
            updated_at: now,
            expires_at: None,
            combined_signature: None,
        };

        // Persist to storage
        self.save_session(&session).await?;

        // Cache in memory
        self.sessions
            .write()
            .await
            .insert(session_id, session.clone());

        Ok(session)
    }

    /// Get a session by ID (from cache or storage)
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SigningSession>> {
        // Check cache first
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(session_id) {
                return Ok(Some(session.clone()));
            }
        }

        // Load from storage
        match self
            .storage
            .find(storage::CATEGORY_SESSION, session_id)
            .await
            .map_err(|e| SigningProtocolError::StorageError(e.to_string()))?
        {
            Some(record) => {
                let session: SigningSession = serde_json::from_slice(&record.value)?;
                // Cache it
                self.sessions
                    .write()
                    .await
                    .insert(session_id.to_string(), session.clone());
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Get a session, returning error if not found
    pub async fn require_session(&self, session_id: &str) -> Result<SigningSession> {
        self.get_session(session_id)
            .await?
            .ok_or_else(|| SigningProtocolError::SessionNotFound(session_id.to_string()))
    }

    /// Transition a session to a new state
    pub async fn transition_state(
        &self,
        session_id: &str,
        new_state: SigningSessionState,
    ) -> Result<SigningSession> {
        let mut session = self.require_session(session_id).await?;

        if !session.state.can_transition_to(new_state) {
            return Err(SigningProtocolError::InvalidStateTransition {
                from: session.state.to_string(),
                to: new_state.to_string(),
            });
        }

        let previous_state = session.state;
        session.state = new_state;
        session.updated_at = chrono::Utc::now().to_rfc3339();

        self.save_session(&session).await?;
        self.sessions
            .write()
            .await
            .insert(session_id.to_string(), session.clone());

        // Emit typed (signing, state_changed) per transition.
        self.emit(crate::events::SigningStateChangedPayload {
            session: session.clone(),
            previous_state: Some(previous_state),
        })
        .await;

        Ok(session)
    }

    /// Get all active (non-terminal) sessions
    pub async fn active_sessions(&self) -> Result<Vec<SigningSession>> {
        let query = Query::new();
        let records = self
            .storage
            .find_all(storage::CATEGORY_SESSION, &query)
            .await
            .map_err(|e| SigningProtocolError::StorageError(e.to_string()))?;

        let mut sessions = Vec::new();
        for record in records {
            let session: SigningSession = serde_json::from_slice(&record.value)?;
            if session.state.is_active() {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    // ========================================================================
    // Consent & Signature Collection
    // ========================================================================

    /// Record consent from a participant.
    /// Returns true when all required participants have consented.
    pub async fn accept_consent(
        &self,
        session_id: &str,
        signer_did: &str,
        key_binding: KeyBinding,
    ) -> Result<bool> {
        let mut session = self.require_session(session_id).await?;

        // Find the participant
        let participant = session
            .participants
            .iter_mut()
            .find(|p| p.did == signer_did)
            .ok_or_else(|| SigningProtocolError::UnknownSigner(signer_did.to_string()))?;

        participant.consented = true;
        participant.key_binding = Some(key_binding);

        session.updated_at = chrono::Utc::now().to_rfc3339();
        self.save_session(&session).await?;
        self.sessions
            .write()
            .await
            .insert(session_id.to_string(), session.clone());

        // Emit (signing, consent_received) — event for each recorded consent.
        self.emit(crate::events::ConsentReceivedPayload {
            session_id: session_id.to_string(),
            signer_did: signer_did.to_string(),
        })
        .await;

        // Check if all required consents are in
        let consented_count = session.participants.iter().filter(|p| p.consented).count() as u32;
        let required = self.required_signatures(&session);

        Ok(consented_count >= required)
    }

    /// Record a partial signature from a participant.
    /// Returns true when the threshold of signatures has been reached.
    pub async fn accept_partial_signature(
        &self,
        session_id: &str,
        signer_did: &str,
        signature: String,
    ) -> Result<bool> {
        let mut session = self.require_session(session_id).await?;

        // Find the participant
        let participant = session
            .participants
            .iter_mut()
            .find(|p| p.did == signer_did)
            .ok_or_else(|| SigningProtocolError::UnknownSigner(signer_did.to_string()))?;

        if participant.signed {
            return Err(SigningProtocolError::DuplicateSigner(
                signer_did.to_string(),
            ));
        }

        participant.signed = true;
        participant.signature = Some(signature);

        session.updated_at = chrono::Utc::now().to_rfc3339();
        self.save_session(&session).await?;
        self.sessions
            .write()
            .await
            .insert(session_id.to_string(), session.clone());

        // Emit (signing, partial_signature_received) — single round; multi-
        // round suites (FROST etc.) carry `round` once they're added.
        self.emit(crate::events::PartialSignatureReceivedPayload {
            session_id: session_id.to_string(),
            signer_did: signer_did.to_string(),
            round: None,
        })
        .await;

        // Check if threshold is reached
        let signed_count = session.participants.iter().filter(|p| p.signed).count() as u32;
        let required = self.required_signatures(&session);

        // Threshold transition: emit (signing, threshold_met) the first time
        // signed_count reaches required. Idempotent — repeated calls beyond
        // the threshold won't double-emit because `participant.signed` is
        // already true above and bails earlier on `DuplicateSigner`.
        if signed_count == required {
            self.emit(crate::events::ThresholdMetPayload {
                session_id: session_id.to_string(),
                required_signatures: required,
                received_signatures: signed_count,
            })
            .await;
        }

        Ok(signed_count >= required)
    }

    /// Combine partial signatures.
    /// For "none" aggregation (simple collection), concatenates all signatures.
    /// Returns the combined signature (base64-encoded).
    pub async fn combine_signatures(&self, session_id: &str) -> Result<String> {
        let mut session = self.require_session(session_id).await?;

        let signatures: Vec<&str> = session
            .participants
            .iter()
            .filter_map(|p| p.signature.as_deref())
            .collect();

        if signatures.is_empty() {
            return Err(SigningProtocolError::ThresholdNotMet {
                have: 0,
                need: self.required_signatures(&session),
            });
        }

        // For "none" aggregation, create a JSON array of all partial signatures
        let combined = serde_json::to_string(&signatures)
            .map_err(|e| SigningProtocolError::SerializationError(e.to_string()))?;
        let combined_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            combined.as_bytes(),
        );

        session.combined_signature = Some(combined_b64.clone());
        session.updated_at = chrono::Utc::now().to_rfc3339();
        self.save_session(&session).await?;
        self.sessions
            .write()
            .await
            .insert(session_id.to_string(), session.clone());

        // Emit (signing, session_completed) once the combined signature is
        // available. Note this is independent of `transition_state`-driven
        // state-changed; consumers that only care about "session is done +
        // here's the signature" can subscribe to this single event.
        self.emit(crate::events::SessionCompletedPayload {
            session,
            final_signature: combined_b64.clone(),
        })
        .await;

        Ok(combined_b64)
    }

    // ========================================================================
    // Sealed Secrets
    // ========================================================================

    /// Create an HPKE sealed secret for a recipient.
    ///
    /// # Arguments
    /// * `recipient_pk` - Recipient's X25519 public key (32 bytes)
    /// * `plaintext` - The secret data to encrypt
    /// * `aad` - Additional authenticated data (typically session_id + device)
    pub fn create_sealed_secret(
        &self,
        recipient_pk: &[u8; 32],
        plaintext: &[u8],
        session_id: &str,
        device: &str,
        ticket_digest: &str,
    ) -> Result<SealedSecret> {
        let aad_data = serde_json::to_vec(&serde_json::json!({
            "ticket_digest": ticket_digest,
            "session_id": session_id,
            "device": device,
        }))
        .map_err(|e| SigningProtocolError::SerializationError(e.to_string()))?;

        let (eph_pk, ciphertext) = HpkeBase::seal(recipient_pk, plaintext, &aad_data)?;

        Ok(SealedSecret {
            envelope_type: SealedSecret::TYPE.to_string(),
            suite: SealedSecret::SUITE.to_string(),
            aad: HpkeAad {
                ticket_digest: ticket_digest.to_string(),
                session_id: session_id.to_string(),
                device: device.to_string(),
            },
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            ),
            enc: HpkeEncParams {
                ek_pub: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &eph_pk),
                ..Default::default()
            },
        })
    }

    /// Unseal an HPKE sealed secret using the recipient's secret key.
    pub fn unseal_secret(&self, sealed: &SealedSecret, recipient_sk: &[u8; 32]) -> Result<Vec<u8>> {
        let aad_data = serde_json::to_vec(&serde_json::json!({
            "ticket_digest": sealed.aad.ticket_digest,
            "session_id": sealed.aad.session_id,
            "device": sealed.aad.device,
        }))
        .map_err(|e| SigningProtocolError::SerializationError(e.to_string()))?;

        let eph_pk_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sealed.enc.ek_pub,
        )
        .map_err(|e| SigningProtocolError::HpkeError(format!("base64 decode ek_pub: {}", e)))?;
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sealed.ciphertext,
        )
        .map_err(|e| SigningProtocolError::HpkeError(format!("base64 decode ciphertext: {}", e)))?;

        let eph_pk: [u8; 32] = eph_pk_bytes.try_into().map_err(|_| {
            SigningProtocolError::HpkeError("invalid ephemeral public key length".into())
        })?;

        HpkeBase::unseal(recipient_sk, &eph_pk, &ciphertext_bytes, &aad_data)
    }

    // ========================================================================
    // Authorization Tokens
    // ========================================================================

    /// Issue an authorization token for a subject.
    /// The token includes a monotonic counter for replay protection.
    pub async fn issue_token(
        &self,
        session_id: &str,
        scope: &str,
        device: &str,
        subject_did: &str,
    ) -> Result<AuthorizationToken> {
        let ctr = self.counter_manager.next(subject_did, device).await?;

        let token = AuthorizationToken {
            typ: "signing-ticket".to_string(),
            session_id: session_id.to_string(),
            scope: scope.to_string(),
            device: device.to_string(),
            ctr,
            exp: None,
            cap: 1,
        };

        Ok(token)
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Get the number of required signatures for a session
    fn required_signatures(&self, session: &SigningSession) -> u32 {
        match &session.threshold {
            Some(t) => t.n,
            None => 1, // single-signer
        }
    }

    /// Persist a session to storage
    async fn save_session(&self, session: &SigningSession) -> Result<()> {
        let value = serde_json::to_vec(session)?;
        let record = Record::new(storage::CATEGORY_SESSION, &session.session_id, value)
            .add_tag(storage::tags::STATE, session.state.to_string())
            .add_tag(storage::tags::COORDINATOR_DID, &session.coordinator_did)
            .add_tag(storage::tags::THREAD_ID, &session.thread_id);

        // Try update first, fall back to save for new records
        match self.storage.update(&record).await {
            Ok(()) => Ok(()),
            Err(_) => self
                .storage
                .save(&record)
                .await
                .map_err(|e| SigningProtocolError::StorageError(e.to_string())),
        }
    }
}
