use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info};

use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};

use crate::messages::{RequestProfileMessage, REQUEST_PROFILE_MESSAGE_TYPE};
use crate::services::UserProfileService;

pub struct RequestProfileHandler {
    service: Arc<UserProfileService>,
}

impl RequestProfileHandler {
    pub fn new(service: Arc<UserProfileService>) -> Self {
        Self { service }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for RequestProfileHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![REQUEST_PROFILE_MESSAGE_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        let request_msg: RequestProfileMessage =
            serde_json::from_value(inbound.message.body.clone()).map_err(|e| {
                MessageHandlerError::InvalidMessage(format!(
                    "Failed to parse RequestProfileMessage: {}",
                    e
                ))
            })?;

        info!(
            query = ?request_msg.query,
            from = ?inbound.context.from,
            "Received profile request"
        );

        // Load own profile and respond
        let own_record = self
            .service
            .get_own_profile()
            .await
            .map_err(MessageHandlerError::ProcessingFailed)?;

        let Some(record) = own_record else {
            debug!("No own profile set, not responding to request");
            return Ok(None);
        };

        let query_refs: Option<Vec<String>> = request_msg.query.clone();
        let query_slice = query_refs.as_deref();
        let reply = UserProfileService::build_profile_message(&record, query_slice);

        let didcomm_msg = crate::handlers::profile_handler::profile_message_to_didcomm(&reply)
            .map_err(|e| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Failed to build DIDComm message: {}",
                    e
                ))
            })?;

        debug!("Sending own profile in response to request");
        Ok(Some(OutboundMessage {
            message: didcomm_msg,
            to: inbound.context.from.clone().unwrap_or_default(),
            from: inbound.context.to.clone().unwrap_or_default(),
            connection_id: inbound.context.connection_id.clone(),
        }))
    }
}
