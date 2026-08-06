//! Query handlers for Discover Features v1 and v2.
//!
//! Each handler is **hybrid**: it auto-derives the supported protocols from the
//! agent's shared [`HandlerRegistry`] (zero-config — every registered inbound
//! handler's protocol is discoverable) and merges the declarative
//! [`FeatureRegistry`] on top. The declarative registry adds what the handler
//! registry can't express: per-protocol **roles**, **goal-codes**, and
//! **send-only** protocols that have no inbound handler. A declared protocol
//! wins over an auto-derived one so its roles are surfaced.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use didcomm::core::{Message, Thread};
use didcomm::messaging::handlers::{
    InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage, Result,
};
use didcomm::messaging::{Feature, FeatureRegistry, HandlerRegistry};
use tokio::sync::RwLock;

use crate::messages::*;

/// A protocol to disclose: its id plus the roles (if any) the agent declared.
struct ProtocolFeature {
    pid: String,
    roles: Option<Vec<String>>,
}

/// The set of protocols the agent supports for a given `match` pattern, merging
/// the auto-derived handler-registry protocols with the declared feature
/// registry (declared entries win so their roles are surfaced). Sorted by pid.
async fn matching_protocols(
    handlers: &Arc<RwLock<HandlerRegistry>>,
    features: &Arc<RwLock<FeatureRegistry>>,
    pattern: &str,
) -> Vec<ProtocolFeature> {
    // Auto-derived from registered handlers (roles unknown).
    let mut merged: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    for pid in handlers
        .read()
        .await
        .registered_types()
        .iter()
        .filter_map(|t| protocol_id(t))
    {
        if matches_query(pattern, &pid) {
            merged.entry(pid).or_insert(None);
        }
    }
    // Declared protocol features override (adds roles / send-only entries).
    for f in features.read().await.query("protocol", pattern) {
        let roles = if f.roles.is_empty() {
            None
        } else {
            Some(f.roles.clone())
        };
        merged.insert(f.id, roles);
    }
    merged
        .into_iter()
        .map(|(pid, roles)| ProtocolFeature { pid, roles })
        .collect()
}

/// Declared goal-code features matching `pattern` (v2 only).
async fn matching_goal_codes(
    features: &Arc<RwLock<FeatureRegistry>>,
    pattern: &str,
) -> Vec<Feature> {
    features.read().await.query("goal-code", pattern)
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
    features: Arc<RwLock<FeatureRegistry>>,
}

impl DiscoverFeaturesV1Handler {
    pub fn new(
        registry: Arc<RwLock<HandlerRegistry>>,
        features: Arc<RwLock<FeatureRegistry>>,
    ) -> Self {
        Self { registry, features }
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

        let protocols = matching_protocols(&self.registry, &self.features, &query.query)
            .await
            .into_iter()
            .map(|p| ProtocolDescriptor {
                pid: p.pid,
                roles: p.roles,
            })
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
    features: Arc<RwLock<FeatureRegistry>>,
}

impl DiscoverFeaturesV2Handler {
    pub fn new(
        registry: Arc<RwLock<HandlerRegistry>>,
        features: Arc<RwLock<FeatureRegistry>>,
    ) -> Self {
        Self { registry, features }
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

        let mut disclosures = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for q in &queries.queries {
            match q.feature_type.as_str() {
                "protocol" => {
                    for p in matching_protocols(&self.registry, &self.features, &q.match_).await {
                        if seen.insert(("protocol".to_string(), p.pid.clone())) {
                            disclosures.push(FeatureDisclosure {
                                feature_type: "protocol".to_string(),
                                id: p.pid,
                                roles: p.roles,
                            });
                        }
                    }
                }
                // Goal-codes are only disclosed when a module has declared them.
                "goal-code" => {
                    for f in matching_goal_codes(&self.features, &q.match_).await {
                        if seen.insert(("goal-code".to_string(), f.id.clone())) {
                            disclosures.push(FeatureDisclosure {
                                feature_type: "goal-code".to_string(),
                                id: f.id,
                                roles: None,
                            });
                        }
                    }
                }
                // Unknown feature types are ignored per RFC 0557.
                _ => {}
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
