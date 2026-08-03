//! Propose Credential Handler (Issuer side)
//!
//! Receives a `propose-credential` message from a holder, stores it as a
//! new exchange in `ProposalReceived` state, and returns no immediate
//! response — the issuer application layer decides whether to counter
//! with an offer (via `CredentialExchangeService::accept_proposal`) or
//! abandon the exchange.

use crate::messages::ProposeCredentialMessage;
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

pub struct ProposeCredentialHandler {
    service: Arc<CredentialExchangeService>,
}

impl ProposeCredentialHandler {
    pub fn new(service: Arc<CredentialExchangeService>) -> Self {
        Self { service }
    }

    async fn process(&self, inbound: InboundMessage) -> Result<(), MessageHandlerError> {
        let propose_msg = ProposeCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let connection_id = inbound.context.connection_id.clone();
        let record = self
            .service
            .store_proposal(connection_id.as_deref(), &propose_msg)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        tracing::info!(
            exchange_id = %record.id,
            thread_id = %record.thread_id,
            "received propose-credential, exchange in ProposalReceived"
        );
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MessageHandler for ProposeCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProposeCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.process(inbound).await?;
        Ok(None)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl MessageHandler for ProposeCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![ProposeCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        self.process(inbound).await?;
        Ok(None)
    }
}
