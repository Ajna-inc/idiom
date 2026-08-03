use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::discover::DiscoverMessage;
use crate::messages::workflows_response::{WorkflowSummary, WorkflowsResponseMessage};
use crate::services::WorkflowService;
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct DiscoverHandler {
    service: Arc<WorkflowService>,
}

impl DiscoverHandler {
    pub fn new(service: Arc<WorkflowService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for DiscoverHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![DiscoverMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let discover_msg: DiscoverMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let all_templates = self
            .service
            .list_templates()
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // Group by template_id
        let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
        let mut titles: HashMap<String, String> = HashMap::new();
        let mut hashes: HashMap<String, String> = HashMap::new();

        for record in &all_templates {
            // Apply filters
            if let Some(ref filters) = discover_msg.filters {
                if let Some(ref filter_id) = filters.template_id {
                    if &record.template_id != filter_id {
                        continue;
                    }
                }
                if let Some(ref filter_text) = filters.text {
                    if !record
                        .title
                        .to_lowercase()
                        .contains(&filter_text.to_lowercase())
                    {
                        continue;
                    }
                }
            }

            grouped
                .entry(record.template_id.clone())
                .or_default()
                .push(record.version.clone());
            titles.insert(record.template_id.clone(), record.title.clone());
            hashes.insert(record.template_id.clone(), record.hash.clone());
        }

        let mut workflows: Vec<WorkflowSummary> = grouped
            .into_iter()
            .map(|(template_id, versions)| WorkflowSummary {
                title: titles.get(&template_id).cloned(),
                hash: if discover_msg.include_hash {
                    hashes.get(&template_id).cloned()
                } else {
                    None
                },
                template_id,
                versions,
            })
            .collect();

        // Apply paging
        if let Some(ref paging) = discover_msg.paging {
            if let Some(offset) = paging.offset {
                workflows = workflows.into_iter().skip(offset).collect();
            }
            if let Some(limit) = paging.limit {
                workflows.truncate(limit);
            }
        }

        let response = WorkflowsResponseMessage {
            workflows,
            paging: discover_msg.paging,
        };

        let response_body = serde_json::to_value(&response)
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let response_msg = Message::new(
            uuid::Uuid::new_v4().to_string(),
            WorkflowsResponseMessage::TYPE.to_string(),
            response_body,
        );

        if let (Some(from), Some(to)) = (&inbound.context.to, &inbound.context.from) {
            Ok(Some(OutboundMessage {
                message: response_msg,
                to: to.clone(),
                from: from.clone(),
                connection_id: inbound.context.connection_id,
            }))
        } else {
            Ok(None)
        }
    }
}
