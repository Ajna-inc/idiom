//! Message Dispatcher
//!
//! Handles routing of inbound and outbound DIDComm messages

use crate::error::{AgentError, Result};
use crate::transport::{EncryptedMessage, TransportManager};
use std::sync::Arc;

/// Message Dispatcher for routing DIDComm messages
pub struct MessageDispatcher {
    transport: Arc<TransportManager>,
}

impl MessageDispatcher {
    /// Create a new MessageDispatcher
    pub fn new(transport: Arc<TransportManager>) -> Self {
        Self { transport }
    }

    /// Dispatch an outbound message
    pub async fn dispatch_outbound(
        &self,
        message: EncryptedMessage,
        endpoint: &str,
    ) -> Result<Option<String>> {
        self.transport
            .send_message(message, endpoint)
            .await
            .map_err(|e| AgentError::Dispatcher(e.to_string()))
    }

    /// Dispatch an inbound message for processing
    /// (Placeholder - full implementation will integrate with handlers)
    pub async fn dispatch_inbound(&self, _message: EncryptedMessage) -> Result<()> {
        // TODO: Integrate with message handlers
        Ok(())
    }
}
