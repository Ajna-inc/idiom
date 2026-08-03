//! Offer Credential Handler
//!
//! Handles incoming credential offer messages (holder side). Stores the offer
//! and creates an exchange record in OfferReceived state. When auto-accept is
//! enabled, immediately answers with a credential request (the DIDComm
//! acceptance step) so the full offer→request→issue→store flow proceeds without
//! a manual accept.

use crate::domain::{CredentialExchangeRole, CredentialExchangeState};
use crate::messages::OfferCredentialMessage;
use crate::repository::CredentialExchangeRecord;
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Entropy used for the holder's auto-generated credential request.
const AUTO_ACCEPT_ENTROPY: &str = "idiom-holder-entropy";

/// Handler for incoming offer-credential messages (holder side).
pub struct OfferCredentialHandler {
    service: Arc<CredentialExchangeService>,
    auto_accept: bool,
}

impl OfferCredentialHandler {
    /// `auto_accept`: when true, respond to every offer with a credential
    /// request automatically (real DIDComm acceptance).
    pub fn new(service: Arc<CredentialExchangeService>, auto_accept: bool) -> Self {
        Self {
            service,
            auto_accept,
        }
    }

    /// Shared handling: store the offer, and (if auto-accept) return a request.
    async fn handle_offer(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!(
            msg_type = %inbound.message.msg_type,
            msg_id = %inbound.message.id,
            "Received offer-credential message"
        );

        let offer = OfferCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let offer_value: serde_json::Value = serde_json::from_str(&offer.credential_offer_json)
            .map_err(|e| {
                MessageHandlerError::InvalidMessage(format!(
                    "Failed to parse credential offer JSON: {}",
                    e
                ))
            })?;

        let schema_id = offer_value
            .get("schema_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let cred_def_id = offer_value
            .get("cred_def_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
            offer.thread_id.clone(),
        );
        record.schema_id = schema_id;
        record.cred_def_id = cred_def_id;
        record.credential_offer_json = Some(offer.credential_offer_json);
        if let Some(connection_id) = &inbound.context.connection_id {
            record.set_connection_id(connection_id.clone());
        }

        self.service.repository().save(&record).await.map_err(|e| {
            MessageHandlerError::ProcessingFailed(format!(
                "Failed to save credential exchange record: {}",
                e
            ))
        })?;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            auto_accept = self.auto_accept,
            "Created credential exchange record in OfferReceived state"
        );

        if !self.auto_accept {
            // Holder must explicitly accept the offer.
            return Ok(None);
        }

        // Auto-accept: build a credential request and send it back to the issuer.
        let request_msg = self
            .service
            .accept_offer(&record.id, AUTO_ACCEPT_ENTROPY)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Auto-accept: failed to create credential request: {}",
                    e
                ))
            })?;

        Ok(Some(OutboundMessage {
            message: request_msg.to_didcomm_message(),
            to: inbound.context.from.clone().unwrap_or_default(),
            from: inbound.context.to.clone().unwrap_or_default(),
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MessageHandler for OfferCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![OfferCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.handle_offer(inbound).await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl MessageHandler for OfferCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![OfferCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.handle_offer(inbound).await
    }
}
