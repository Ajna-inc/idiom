//! Request Credential Handler
//!
//! Handles incoming credential request messages (issuer side).
//! Issues the credential and returns an issue-credential message.

use crate::messages::RequestCredentialMessage;
use crate::services::CredentialExchangeService;
use async_trait::async_trait;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use std::collections::HashMap;
use std::sync::Arc;

/// Handler for incoming request-credential messages (issuer side)
///
/// When the issuer receives a credential request, this handler:
/// 1. Finds the exchange record by thread ID
/// 2. Stores the credential request
/// 3. If auto_issue is enabled, issues the credential and returns it
pub struct RequestCredentialHandler {
    service: Arc<CredentialExchangeService>,
    /// Credential attributes to issue (cred_def_id -> attributes)
    /// In production, this would be resolved dynamically.
    auto_issue_attributes: Arc<tokio::sync::RwLock<HashMap<String, HashMap<String, String>>>>,
}

impl RequestCredentialHandler {
    pub fn new(service: Arc<CredentialExchangeService>) -> Self {
        Self {
            service,
            auto_issue_attributes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Register attributes to auto-issue for a credential exchange
    pub async fn register_auto_issue_attributes(
        &self,
        exchange_id: &str,
        attributes: HashMap<String, String>,
    ) {
        let mut map = self.auto_issue_attributes.write().await;
        map.insert(exchange_id.to_string(), attributes);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl MessageHandler for RequestCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![RequestCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!(
            msg_type = %inbound.message.msg_type,
            msg_id = %inbound.message.id,
            "Received request-credential message"
        );

        let request = RequestCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let thread_id = &request.thread_id;

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

        // Store the credential request on the exchange record
        self.service
            .store_request(&record.id, &request.credential_request_json)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to store credential request: {}",
                    e
                ))
            })?;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %thread_id,
            "Stored credential request, exchange in RequestReceived state"
        );

        // Attributes to auto-issue: prefer the ones persisted on the exchange
        // record (survive restart + replay), then fall back to the in-memory map
        // registered in the same process.
        let auto_attrs = match record.auto_issue_attributes.clone() {
            Some(attrs) => Some(attrs),
            None => {
                let map = self.auto_issue_attributes.read().await;
                map.get(&record.id).cloned()
            }
        };

        if let Some(attributes) = auto_attrs {
            tracing::debug!(
                exchange_id = %record.id,
                "Auto-issuing credential"
            );

            let mut outbound = self
                .service
                .accept_request(&record.id, attributes)
                .await
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to issue credential: {}",
                        e
                    ))
                })?;

            // Route the issue back to the holder: `to` = the request's sender,
            // `from` = us. accept_request leaves these empty for the handler to
            // fill from the inbound context (mirrors the connection/workflow
            // handlers) — otherwise pack_response fails to resolve an empty DID.
            outbound.to = inbound.context.from.clone().unwrap_or_default();
            outbound.from = inbound.context.to.clone().unwrap_or_default();

            // Clean up auto-issue attributes
            {
                let mut map = self.auto_issue_attributes.write().await;
                map.remove(&record.id);
            }

            return Ok(Some(outbound));
        }

        // No auto-issue - issuer must explicitly accept the request
        Ok(None)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl MessageHandler for RequestCredentialHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![RequestCredentialMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        tracing::debug!(
            msg_type = %inbound.message.msg_type,
            msg_id = %inbound.message.id,
            "Received request-credential message"
        );

        let request = RequestCredentialMessage::from_didcomm_message(&inbound.message)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let thread_id = &request.thread_id;

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

        self.service
            .store_request(&record.id, &request.credential_request_json)
            .await
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to store credential request: {}",
                    e
                ))
            })?;

        tracing::debug!(
            exchange_id = %record.id,
            thread_id = %thread_id,
            "Stored credential request, exchange in RequestReceived state"
        );

        let auto_attrs = {
            let map = self.auto_issue_attributes.read().await;
            map.get(&record.id).cloned()
        };

        if let Some(attributes) = auto_attrs {
            tracing::debug!(
                exchange_id = %record.id,
                "Auto-issuing credential"
            );

            let outbound = self
                .service
                .accept_request(&record.id, attributes)
                .await
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to issue credential: {}",
                        e
                    ))
                })?;

            {
                let mut map = self.auto_issue_attributes.write().await;
                map.remove(&record.id);
            }

            return Ok(Some(outbound));
        }

        Ok(None)
    }
}
