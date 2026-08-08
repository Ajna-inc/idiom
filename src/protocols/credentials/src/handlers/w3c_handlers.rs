//! W3C / JWT-VC / SD-JWT DIDComm credential handlers.
//!
//! Each handler owns the shared Issue-Credential message type (offer / request
//! / issue / ack). Because the DIDComm handler registry keys one handler per
//! message type, these handlers *dispatch by attachment format*:
//!
//! * a W3C-family format id (`aries/ld-proof-vc*`, `aries/jwt-vc*`,
//!   `vc+sd-jwt*`) that a registered [`W3cCredentialExchangeService`] format
//!   supports → handled here;
//! * anything else (e.g. `anoncreds/*`) → delegated to the optional `fallback`
//!   handler (the AnonCreds handler, when present), so AnonCreds behaviour is
//!   preserved unchanged.

use crate::formats::DidCommCredentialFormat;
use crate::messages::{
    AckMessage, IssueCredentialMessage, OfferCredentialMessage, RequestCredentialMessage,
};
use crate::services::W3cCredentialExchangeService;
use async_trait::async_trait;
use didcomm::core::Message as DidcommMessage;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Optional delegate handler for non-W3C (AnonCreds) messages of the same type.
type Fallback = Option<Arc<dyn MessageHandler>>;

/// Read the first attachment format id from an inbound message (body `formats`
/// decorator first, then the v3 `attachments` array).
fn first_format_id(message: &DidcommMessage) -> Option<String> {
    if let Some(fmt) = message
        .body
        .get("formats")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|f| f.get("format"))
        .and_then(|v| v.as_str())
    {
        return Some(fmt.to_string());
    }
    message
        .attachments
        .as_ref()
        .and_then(|a| a.first())
        .and_then(|att| att.format.clone())
}

/// Whether this W3C service should handle the message, given its format id.
fn is_w3c_for(service: &W3cCredentialExchangeService, message: &DidcommMessage) -> bool {
    match first_format_id(message) {
        Some(id) => {
            DidCommCredentialFormat::from_format_id(&id).is_some() && service.supports_format_id(&id)
        }
        None => false,
    }
}

// ── offer (holder side) ──────────────────────────────────────────────────────

/// Handles inbound offer-credential messages for W3C formats. Stores the offer
/// (`OfferReceived`) and, when `auto_accept`, answers with a credential request.
pub struct W3cOfferCredentialHandler {
    service: Arc<W3cCredentialExchangeService>,
    auto_accept: bool,
    fallback: Fallback,
}

impl W3cOfferCredentialHandler {
    pub fn new(service: Arc<W3cCredentialExchangeService>, auto_accept: bool) -> Self {
        Self {
            service,
            auto_accept,
            fallback: None,
        }
    }

    /// Attach a delegate handler used for non-W3C (AnonCreds) offers.
    pub fn with_fallback(mut self, fallback: Arc<dyn MessageHandler>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    async fn handle_offer(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        if !is_w3c_for(&self.service, &inbound.message) {
            return match &self.fallback {
                Some(h) => h.handle(inbound).await,
                None => Ok(None),
            };
        }

        let offer = OfferCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let record = self
            .service
            .store_offer(inbound.context.connection_id.as_deref(), &offer)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        if !self.auto_accept {
            return Ok(None);
        }

        let request_msg = self
            .service
            .accept_offer(&record.id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        Ok(Some(OutboundMessage {
            message: request_msg.to_didcomm_message(),
            to: inbound.context.from.clone().unwrap_or_default(),
            from: inbound.context.to.clone().unwrap_or_default(),
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}

// ── request (issuer side) ────────────────────────────────────────────────────

/// Handles inbound request-credential messages for W3C formats. Stores the
/// request (`RequestReceived`) and, when `auto_issue`, signs + returns the
/// issued credential.
pub struct W3cRequestCredentialHandler {
    service: Arc<W3cCredentialExchangeService>,
    auto_issue: bool,
    fallback: Fallback,
}

impl W3cRequestCredentialHandler {
    pub fn new(service: Arc<W3cCredentialExchangeService>, auto_issue: bool) -> Self {
        Self {
            service,
            auto_issue,
            fallback: None,
        }
    }

    pub fn with_fallback(mut self, fallback: Arc<dyn MessageHandler>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    async fn handle_request(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        if !is_w3c_for(&self.service, &inbound.message) {
            return match &self.fallback {
                Some(h) => h.handle(inbound).await,
                None => Ok(None),
            };
        }

        let request = RequestCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let record = self
            .service
            .find_exchange_by_thread_id(&request.thread_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "No credential exchange for thread: {}",
                    request.thread_id
                ))
            })?;

        self.service
            .store_request(&record.id, &request.credential_request_json)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        if !self.auto_issue {
            return Ok(None);
        }

        let mut outbound = self
            .service
            .accept_request(&record.id, None)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;
        outbound.to = inbound.context.from.clone().unwrap_or_default();
        outbound.from = inbound.context.to.clone().unwrap_or_default();
        Ok(Some(outbound))
    }
}

// ── issue (holder side) ──────────────────────────────────────────────────────

/// Handles inbound issue-credential messages for W3C formats. Verifies +
/// records the credential (`Done`) and returns an ack.
pub struct W3cIssueCredentialHandler {
    service: Arc<W3cCredentialExchangeService>,
    fallback: Fallback,
}

impl W3cIssueCredentialHandler {
    pub fn new(service: Arc<W3cCredentialExchangeService>) -> Self {
        Self {
            service,
            fallback: None,
        }
    }

    pub fn with_fallback(mut self, fallback: Arc<dyn MessageHandler>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    async fn handle_issue(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        if !is_w3c_for(&self.service, &inbound.message) {
            return match &self.fallback {
                Some(h) => h.handle(inbound).await,
                None => Ok(None),
            };
        }

        let issue_msg = IssueCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let record = self
            .service
            .find_exchange_by_thread_id(&issue_msg.thread_id)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "No credential exchange for thread: {}",
                    issue_msg.thread_id
                ))
            })?;

        self.service
            .process_credential(&record.id, &issue_msg.credential_json)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let ack = AckMessage::ok(issue_msg.thread_id.clone());
        Ok(Some(OutboundMessage {
            message: ack.to_didcomm_message(),
            to: inbound.context.from.clone().unwrap_or_default(),
            from: inbound.context.to.clone().unwrap_or_default(),
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}

// ── trait impls (native + wasm) ──────────────────────────────────────────────

macro_rules! impl_message_handler {
    ($ty:ty, $types:expr, $method:ident) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[async_trait]
        impl MessageHandler for $ty {
            fn supported_types(&self) -> Vec<String> {
                $types
            }
            async fn handle(
                &self,
                inbound: InboundMessage,
            ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
                self.$method(inbound).await
            }
        }

        #[cfg(target_arch = "wasm32")]
        #[async_trait(?Send)]
        impl MessageHandler for $ty {
            fn supported_types(&self) -> Vec<String> {
                $types
            }
            async fn handle(
                &self,
                inbound: InboundMessage,
            ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
                self.$method(inbound).await
            }
        }
    };
}

impl_message_handler!(
    W3cOfferCredentialHandler,
    vec![OfferCredentialMessage::TYPE.to_string()],
    handle_offer
);
impl_message_handler!(
    W3cRequestCredentialHandler,
    vec![RequestCredentialMessage::TYPE.to_string()],
    handle_request
);
impl_message_handler!(
    W3cIssueCredentialHandler,
    vec![IssueCredentialMessage::TYPE.to_string()],
    handle_issue
);
