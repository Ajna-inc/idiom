//! Issue Credential Handler
//!
//! Handles incoming issue-credential messages (holder side).
//! Processes the credential and stores it.

use crate::messages::{AckMessage, IssueCredentialMessage};
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::sync::Arc;

/// Handler for incoming issue-credential messages (holder side)
///
/// When the holder receives a credential, this handler:
/// 1. Finds the exchange record by thread ID
/// 2. Processes the credential via AnonCreds
/// 3. Stores the processed credential
/// 4. Returns an ack message
pub struct IssueCredentialHandler {
    service: Arc<CredentialExchangeService>,
}

impl IssueCredentialHandler {
    pub fn new(service: Arc<CredentialExchangeService>) -> Self {
        Self { service }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MessageHandler for IssueCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![IssueCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!(
            msg_type = %inbound.message.msg_type,
            msg_id = %inbound.message.id,
            "Received issue-credential message"
        );

        let issue_msg = IssueCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let thread_id = &issue_msg.thread_id;

        // Find the exchange record by thread ID
        let record = self
            .service
            .find_exchange_by_thread_id(thread_id)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to find credential exchange: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "No credential exchange found for thread: {}",
                    thread_id
                ))
            })?;

        // Store the credential on the exchange and process it
        let credential_id = self
            .service
            .process_credential(&record.id, &issue_msg.credential_json)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to process credential: {}",
                    e
                ))
            })?;

        tracing::debug!(
            exchange_id = %record.id,
            credential_id = %credential_id,
            "Processed and stored credential, exchange is Done"
        );

        // Send ack message
        let ack = AckMessage::ok(thread_id.clone());
        let ack_didcomm = ack.to_didcomm_message();

        let from = inbound.context.to.clone().unwrap_or_default();
        let to = inbound.context.from.clone().unwrap_or_default();

        Ok(Some(OutboundMessage {
            message: ack_didcomm,
            to,
            from,
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl MessageHandler for IssueCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![IssueCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!(
            msg_type = %inbound.message.msg_type,
            msg_id = %inbound.message.id,
            "Received issue-credential message"
        );

        let issue_msg = IssueCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let thread_id = &issue_msg.thread_id;

        let record = self
            .service
            .find_exchange_by_thread_id(thread_id)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to find credential exchange: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "No credential exchange found for thread: {}",
                    thread_id
                ))
            })?;

        let credential_id = self
            .service
            .process_credential(&record.id, &issue_msg.credential_json)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to process credential: {}",
                    e
                ))
            })?;

        tracing::debug!(
            exchange_id = %record.id,
            credential_id = %credential_id,
            "Processed and stored credential, exchange is Done"
        );

        let ack = AckMessage::ok(thread_id.clone());
        let ack_didcomm = ack.to_didcomm_message();

        let from = inbound.context.to.clone().unwrap_or_default();
        let to = inbound.context.from.clone().unwrap_or_default();

        Ok(Some(OutboundMessage {
            message: ack_didcomm,
            to,
            from,
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}
