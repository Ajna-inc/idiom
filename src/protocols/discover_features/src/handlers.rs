//! Query handlers for Discover Features v1 and v2. Each holds a handle to the
//! agent's shared `HandlerRegistry` so it can enumerate the currently-registered
//! protocols at query time and reply with the matching disclosures.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use didcomm::core::{Message, Thread};
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage, Result,
};
use didcomm::messaging::HandlerRegistry;
use tokio::sync::RwLock;

use crate::messages::*;

/// Unique, sorted protocol IDs currently supported by the agent, derived from
/// the registry's registered message-type URIs.
async fn supported_protocols(registry: &Arc<RwLock<HandlerRegistry>>) -> Vec<String> {
    registry
        .read()
        .await
        .registered_types()
        .iter()
        .filter_map(|t| protocol_id(t))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Build a disclose/disclosures reply threaded back to the query (so the
/// requester correlates it), addressed to the authenticated sender. Returns
/// `None` when there is no resolved sender/recipient to reply to.
fn reply(
    msg_type: &str,
    body: serde_json::Value,
    inbound: &InboundMessage,
) -> Result<Option<OutboundMessage>> {
    let mut message = Message::new(uuid::Uuid::new_v4().to_string(), msg_type.to_string(), body);
    // ~thread.thid = the query's thread (or its @id) per RFC 0031/0557.
    let thid = inbound
        .context
        .thread_id
        .clone()
        .unwrap_or_else(|| inbound.message.id.clone());
    message.thread = Some(Thread {
        thid: Some(thid),
        ..Default::default()
    });

    match (&inbound.context.to, &inbound.context.from) {
        (Some(from), Some(to)) => Ok(Some(OutboundMessage {
            message,
            to: to.clone(),
            from: from.clone(),
            connection_id: inbound.context.connection_id.clone(),
        })),
        // No cryptographically-resolved sender → nothing to reply to.
        _ => Ok(None),
    }
}

/// Discover Features **v1** (RFC 0031): handles `query`, replies `disclose`.
pub struct DiscoverFeaturesV1Handler {
    registry: Arc<RwLock<HandlerRegistry>>,
}

impl DiscoverFeaturesV1Handler {
    pub fn new(registry: Arc<RwLock<HandlerRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl MessageHandler for DiscoverFeaturesV1Handler {
    fn supported_types(&self) -> Vec<String> {
        vec![QUERY_V1_TYPE.to_string()]
    }

    async fn handle(&self, inbound: InboundMessage) -> Result<Option<OutboundMessage>> {
        let query: QueryMessage =
            serde_json::from_value(inbound.message.body.clone()).map_err(|e| {
                MessageHandlerError::InvalidMessage(format!("discover-features/1.0 query: {e}"))
            })?;

        let protocols = supported_protocols(&self.registry)
            .await
            .into_iter()
            .filter(|pid| matches_query(&query.query, pid))
            .map(|pid| ProtocolDescriptor { pid, roles: None })
            .collect();

        tracing::debug!(query = %query.query, "discover-features/1.0 query");
        let body = serde_json::to_value(DiscloseMessage { protocols })
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;
        reply(DISCLOSE_V1_TYPE, body, &inbound)
    }
}

/// Discover Features **v2** (RFC 0557): handles `queries`, replies `disclosures`.
pub struct DiscoverFeaturesV2Handler {
    registry: Arc<RwLock<HandlerRegistry>>,
}

impl DiscoverFeaturesV2Handler {
    pub fn new(registry: Arc<RwLock<HandlerRegistry>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl MessageHandler for DiscoverFeaturesV2Handler {
    fn supported_types(&self) -> Vec<String> {
        vec![QUERIES_V2_TYPE.to_string()]
    }

    async fn handle(&self, inbound: InboundMessage) -> Result<Option<OutboundMessage>> {
        let queries: QueriesMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| {
                MessageHandlerError::InvalidMessage(format!("discover-features/2.0 queries: {e}"))
            })?;

        let protocols = supported_protocols(&self.registry).await;
        let mut disclosures = Vec::new();
        let mut seen = BTreeSet::new();
        for q in &queries.queries {
            // Only protocol discovery is supported; goal-code queries are ignored.
            if q.feature_type != "protocol" {
                continue;
            }
            for pid in protocols.iter().filter(|pid| matches_query(&q.match_, pid)) {
                if seen.insert(pid.clone()) {
                    disclosures.push(FeatureDisclosure {
                        feature_type: "protocol".to_string(),
                        id: pid.clone(),
                        roles: None,
                    });
                }
            }
        }

        tracing::debug!(
            queries = queries.queries.len(),
            "discover-features/2.0 queries"
        );
        let body = serde_json::to_value(DisclosuresMessage { disclosures })
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;
        reply(DISCLOSURES_V2_TYPE, body, &inbound)
    }
}
