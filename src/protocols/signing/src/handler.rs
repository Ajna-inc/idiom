//! DIDComm message handler for the Signing Protocol 1.0
//!
//! Implements the `MessageHandler` trait from `didcomm_messaging`.
//! Routes incoming messages to the appropriate handler method based on type.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};
use tracing::{debug, error, info, warn};

use crate::coordinator::SigningCoordinator;
use crate::errors::{Result, SigningProtocolError};
use crate::messages::*;
use crate::state::SigningSessionState;
use crate::types::*;

/// Message handler for the DIDComm Signing Protocol 1.0
pub struct SigningProtocolHandler {
    coordinator: Arc<SigningCoordinator>,
}

impl SigningProtocolHandler {
    /// Create a new handler with the given coordinator
    pub fn new(coordinator: Arc<SigningCoordinator>) -> Self {
        Self { coordinator }
    }

    /// Get the coordinator
    pub fn coordinator(&self) -> &SigningCoordinator {
        &self.coordinator
    }

    fn require_claimed_sender<'a>(
        &self,
        inbound: &'a InboundMessage,
        claimed_did: &str,
    ) -> Result<&'a str> {
        if !inbound.context.authenticated {
            return Err(SigningProtocolError::Unauthorized(
                "signing protocol requires authcrypt".to_string(),
            ));
        }
        let sender = inbound.context.from.as_deref().ok_or_else(|| {
            SigningProtocolError::Unauthorized("authenticated sender is missing".to_string())
        })?;
        if sender != claimed_did {
            return Err(SigningProtocolError::Unauthorized(format!(
                "claimed signer {claimed_did} does not match authenticated sender {sender}"
            )));
        }
        Ok(sender)
    }

    // ========================================================================
    // Message Handlers
    // ========================================================================

    async fn handle_propose_signing(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: ProposeSigning = serde_json::from_value(inbound.message.body.clone())?;
        let from = inbound.context.from.as_deref().unwrap_or("unknown");

        info!(session_id = %body.session_id, from = %from, "Received propose-signing");

        // Create a session in Proposed state
        let participants = if let Some(ref threshold) = body.threshold {
            threshold
                .signers
                .iter()
                .map(|did| crate::models::SessionParticipant {
                    did: did.clone(),
                    key_binding: None,
                    connection_id: None,
                    consented: false,
                    signed: false,
                    signature: None,
                })
                .collect()
        } else {
            vec![crate::models::SessionParticipant {
                did: from.to_string(),
                key_binding: None,
                connection_id: inbound.context.connection_id.clone(),
                consented: false,
                signed: false,
                signature: None,
            }]
        };

        let mode = body.mode.unwrap_or(crate::models::SessionMode {
            mode_type: if body.threshold.is_some() {
                "threshold"
            } else {
                "single"
            }
            .to_string(),
        });

        self.coordinator
            .create_session(
                body.session_id.clone(),
                inbound.message.thread_id().to_string(),
                body.object,
                body.suite,
                body.constraints,
                mode,
                body.threshold,
                participants,
            )
            .await?;

        // Coordinator acknowledges the proposal
        let ack_body = Ack {
            session_id: body.session_id,
            status: "proposed".to_string(),
        };

        Ok(Some(self.create_response(
            &inbound.message,
            PIURI_ACK,
            &ack_body,
        )?))
    }

    async fn handle_request_signing(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: RequestSigning = serde_json::from_value(inbound.message.body.clone())?;
        let from = inbound.context.from.as_deref().unwrap_or("unknown");

        info!(session_id = %body.session_id, from = %from, "Received request-signing");

        // Store the session locally (as a signer receiving a request)
        let participants = if let Some(ref threshold) = body.threshold {
            threshold
                .signers
                .iter()
                .map(|did| crate::models::SessionParticipant {
                    did: did.clone(),
                    key_binding: None,
                    connection_id: None,
                    consented: false,
                    signed: false,
                    signature: None,
                })
                .collect()
        } else {
            vec![crate::models::SessionParticipant {
                did: self.coordinator.our_did().to_string(),
                key_binding: None,
                connection_id: inbound.context.connection_id.clone(),
                consented: false,
                signed: false,
                signature: None,
            }]
        };

        self.coordinator
            .create_session(
                body.session_id.clone(),
                inbound.message.thread_id().to_string(),
                body.object,
                body.suite,
                body.constraints,
                body.mode,
                body.threshold,
                participants,
            )
            .await?;

        // Transition to Requested
        self.coordinator
            .transition_state(&body.session_id, SigningSessionState::Requested)
            .await?;

        // Don't auto-respond with consent — that requires user/application approval
        // The application layer should call approve_signing_request() which sends consent
        Ok(None)
    }

    async fn handle_consent(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: Consent = serde_json::from_value(inbound.message.body.clone())?;
        self.require_claimed_sender(inbound, &body.signer_did)?;
        if body.key_binding.controller != body.signer_did {
            return Err(SigningProtocolError::Unauthorized(
                "key binding controller does not match signer".to_string(),
            ));
        }
        let session = self.coordinator.require_session(&body.session_id).await?;
        if body.accepted_suite.id != session.suite.id {
            return Err(SigningProtocolError::SignatureError(
                "accepted suite does not match signing session".to_string(),
            ));
        }

        info!(session_id = %body.session_id, signer = %body.signer_did, "Received consent");

        let all_consented = self
            .coordinator
            .accept_consent(&body.session_id, &body.signer_did, body.key_binding)
            .await?;

        if all_consented {
            debug!(session_id = %body.session_id, "All required consents received, transitioning to Signing");
            self.coordinator
                .transition_state(&body.session_id, SigningSessionState::Consented)
                .await?;
            self.coordinator
                .transition_state(&body.session_id, SigningSessionState::Signing)
                .await?;
        }

        // No auto-response — signers will send partial-signature next
        Ok(None)
    }

    async fn handle_partial_signature(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: PartialSignature = serde_json::from_value(inbound.message.body.clone())?;
        self.require_claimed_sender(inbound, &body.signer_did)?;
        let session = self.coordinator.require_session(&body.session_id).await?;
        if body.suite.id != session.suite.id || body.object_digest != session.object.digest.value {
            return Err(SigningProtocolError::SignatureError(
                "partial signature is not bound to this suite and object".to_string(),
            ));
        }
        let expected_index = session
            .participants
            .iter()
            .position(|participant| participant.did == body.signer_did)
            .map(|index| index as u32 + 1)
            .ok_or_else(|| SigningProtocolError::UnknownSigner(body.signer_did.clone()))?;
        if body.signer_index != expected_index {
            return Err(SigningProtocolError::SignatureError(
                "partial signature signer index does not match participant".to_string(),
            ));
        }
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.signature)
            .map_err(|_| {
                SigningProtocolError::SignatureError("invalid signature encoding".to_string())
            })?;
        if signature_bytes.is_empty() {
            return Err(SigningProtocolError::SignatureError(
                "empty partial signature".to_string(),
            ));
        }

        info!(session_id = %body.session_id, signer = %body.signer_did, "Received partial-signature");

        let threshold_reached = self
            .coordinator
            .accept_partial_signature(&body.session_id, &body.signer_did, body.signature)
            .await?;

        if threshold_reached {
            info!(session_id = %body.session_id, "Threshold reached, combining signatures");
            self.coordinator
                .transition_state(&body.session_id, SigningSessionState::Combining)
                .await?;

            let combined = self
                .coordinator
                .combine_signatures(&body.session_id)
                .await?;

            let session = self.coordinator.require_session(&body.session_id).await?;
            let participant_count = session.participants.iter().filter(|p| p.signed).count() as u32;

            // Send Combine message back to the sender
            let combine_body = Combine {
                session_id: body.session_id.clone(),
                combined_signature: combined,
                suite: session.suite.clone(),
                object_digest: session.object.digest.value.clone(),
                participant_count,
            };

            self.coordinator
                .transition_state(&body.session_id, SigningSessionState::Distributing)
                .await?;

            return Ok(Some(self.create_response(
                &inbound.message,
                PIURI_COMBINE,
                &combine_body,
            )?));
        }

        Ok(None)
    }

    async fn handle_combine(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: Combine = serde_json::from_value(inbound.message.body.clone())?;

        info!(session_id = %body.session_id, "Received combine result");

        // Store the combined signature
        if let Some(mut session) = self.coordinator.get_session(&body.session_id).await? {
            session.combined_signature = Some(body.combined_signature);
            session.updated_at = chrono::Utc::now().to_rfc3339();
        }

        // Send ack
        let ack_body = Ack {
            session_id: body.session_id,
            status: "OK".to_string(),
        };

        Ok(Some(self.create_response(
            &inbound.message,
            PIURI_ACK,
            &ack_body,
        )?))
    }

    async fn handle_provide_artifacts(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: ProvideArtifacts = serde_json::from_value(inbound.message.body.clone())?;

        info!(session_id = %body.session_id, sealed_secrets = body.sealed_secrets.len(), "Received artifacts");

        // Application layer should process sealed secrets
        // (e.g., unseal DB key using our X25519 secret key)

        let ack_body = Ack {
            session_id: body.session_id,
            status: "OK".to_string(),
        };

        Ok(Some(self.create_response(
            &inbound.message,
            PIURI_ACK,
            &ack_body,
        )?))
    }

    async fn handle_issue_token(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: IssueToken = serde_json::from_value(inbound.message.body.clone())?;

        info!(session_id = %body.session_id, "Received authorization token");

        // The token is designed for detached use, so authcrypt transport alone
        // is not a substitute for verifying `body.token.sig`. No verifier is
        // currently injected into this handler; fail closed before consuming
        // the replay counter rather than accepting arbitrary signature text.
        Err(SigningProtocolError::TokenVerificationFailed(
            "authorization-token signature verifier is not configured".to_string(),
        ))
    }

    async fn handle_ack(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: Ack = serde_json::from_value(inbound.message.body.clone())?;

        debug!(session_id = %body.session_id, status = %body.status, "Received ack");

        // Check if we can transition to Completed
        if let Some(session) = self.coordinator.get_session(&body.session_id).await? {
            if session.state == SigningSessionState::Distributing {
                // Could track per-participant acks, but for simplicity transition on first ack
                let _ = self
                    .coordinator
                    .transition_state(&body.session_id, SigningSessionState::Completed)
                    .await;
            }
        }

        Ok(None)
    }

    async fn handle_decline(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: Decline = serde_json::from_value(inbound.message.body.clone())?;

        warn!(session_id = %body.session_id, decliner = %body.decliner_did, reason = ?body.reason, "Received decline");

        let _ = self
            .coordinator
            .transition_state(&body.session_id, SigningSessionState::Declined)
            .await;

        Ok(None)
    }

    async fn handle_problem_report(&self, inbound: &InboundMessage) -> Result<Option<Message>> {
        let body: ProblemReport = serde_json::from_value(inbound.message.body.clone())?;

        error!(
            session_id = %body.session_id,
            reporter = %body.reporter_did,
            code = %body.code,
            description = %body.description,
            "Received problem report"
        );

        let _ = self
            .coordinator
            .transition_state(&body.session_id, SigningSessionState::Failed)
            .await;

        Ok(None)
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Create a DIDComm response message
    fn create_response<T: serde::Serialize>(
        &self,
        request: &Message,
        msg_type: &str,
        body: &T,
    ) -> Result<Message> {
        let body_value = serde_json::to_value(body)?;

        let mut response = Message::builder(msg_type)
            .body(body_value)
            .from(self.coordinator.our_did())
            .build();

        // Set thread ID to correlate with the request
        response.thread = Some(didcomm::core::Thread {
            thid: Some(request.thread_id().to_string()),
            pthid: None,
            sender_order: None,
            received_orders: None,
        });

        Ok(response)
    }
}

// ============================================================================
// MessageHandler trait implementation
// ============================================================================

#[async_trait]
impl MessageHandler for SigningProtocolHandler {
    fn supported_types(&self) -> Vec<String> {
        SUPPORTED_TYPES.iter().map(|s| s.to_string()).collect()
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let msg_type = inbound.message.msg_type.clone();
        let from = inbound.context.from.clone();
        let connection_id = inbound.context.connection_id.clone();

        debug!(msg_type = %msg_type, "Handling signing protocol message");

        if !inbound.context.authenticated || inbound.context.from.is_none() {
            return Err(MessageHandlerError::ProcessingFailed(
                "signing protocol requires an authenticated sender".to_string(),
            ));
        }

        let result = match msg_type.as_str() {
            PIURI_PROPOSE_SIGNING => self.handle_propose_signing(&inbound).await,
            PIURI_REQUEST_SIGNING => self.handle_request_signing(&inbound).await,
            PIURI_CONSENT => self.handle_consent(&inbound).await,
            PIURI_PARTIAL_SIGNATURE => self.handle_partial_signature(&inbound).await,
            PIURI_COMBINE => self.handle_combine(&inbound).await,
            PIURI_PROVIDE_ARTIFACTS => self.handle_provide_artifacts(&inbound).await,
            PIURI_ISSUE_TOKEN => self.handle_issue_token(&inbound).await,
            PIURI_ACK => self.handle_ack(&inbound).await,
            PIURI_DECLINE => self.handle_decline(&inbound).await,
            PIURI_PROBLEM_REPORT => self.handle_problem_report(&inbound).await,
            _ => Err(SigningProtocolError::InvalidMessageType(msg_type.clone())),
        };

        match result {
            Ok(Some(response)) => {
                let to = from.unwrap_or_default();
                Ok(Some(OutboundMessage {
                    message: response,
                    to,
                    from: self.coordinator.our_did().to_string(),
                    connection_id,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                error!(msg_type = %msg_type, error = %e, "Error handling signing protocol message");
                Err(MessageHandlerError::ProcessingFailed(e.to_string()))
            }
        }
    }
}
