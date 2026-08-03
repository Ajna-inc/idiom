use std::sync::Arc;

use async_trait::async_trait;

use crate::messages::fetch_template::FetchTemplateMessage;
use crate::messages::problem_report::ProblemReportMessage;
use crate::messages::template_response::TemplateResponseMessage;
use crate::services::WorkflowService;
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage,
};

pub struct FetchTemplateHandler {
    service: Arc<WorkflowService>,
}

impl FetchTemplateHandler {
    pub fn new(service: Arc<WorkflowService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl MessageHandler for FetchTemplateHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![FetchTemplateMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> std::result::Result<Option<OutboundMessage>, MessageHandlerError> {
        let fetch_msg: FetchTemplateMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;

        let template_record = self
            .service
            .get_template(
                &fetch_msg.template_id,
                fetch_msg.template_version.as_deref(),
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        let (from, to) = match (&inbound.context.to, &inbound.context.from) {
            (Some(f), Some(t)) => (f.clone(), t.clone()),
            _ => return Ok(None),
        };

        match template_record {
            Some(record) => {
                let response = TemplateResponseMessage {
                    template: record.template,
                };

                let response_body = serde_json::to_value(&response)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

                let response_msg = Message::new(
                    uuid::Uuid::new_v4().to_string(),
                    TemplateResponseMessage::TYPE.to_string(),
                    response_body,
                );

                Ok(Some(OutboundMessage {
                    message: response_msg,
                    to,
                    from,
                    connection_id: inbound.context.connection_id,
                }))
            }
            None => {
                // Return problem report
                let problem = ProblemReportMessage {
                    code: "invalid_template".to_string(),
                    comment: Some(format!("Template '{}' not found", fetch_msg.template_id)),
                    args: None,
                };

                let problem_body = serde_json::to_value(&problem)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

                let problem_msg = Message::new(
                    uuid::Uuid::new_v4().to_string(),
                    ProblemReportMessage::TYPE.to_string(),
                    problem_body,
                );

                Ok(Some(OutboundMessage {
                    message: problem_msg,
                    to,
                    from,
                    connection_id: inbound.context.connection_id,
                }))
            }
        }
    }
}
