//! End-to-end: a Discover Features query enumerates the registry's protocols and
//! replies with the matching disclose/disclosures, threaded to the query.

use std::sync::Arc;

use async_trait::async_trait;
use didcomm::core::Message;
use didcomm::messaging::handlers::{
    InboundMessage, MessageContext, MessageHandler, OutboundMessage, Result as HResult,
};
use didcomm::messaging::{Feature, FeatureRegistry, HandlerRegistry};
use protocol_discover_features::*;
use tokio::sync::RwLock;

/// A no-op handler that only advertises message types, so the registry has
/// protocols to enumerate.
struct Advertise(Vec<String>);

#[async_trait]
impl MessageHandler for Advertise {
    fn supported_types(&self) -> Vec<String> {
        self.0.clone()
    }
    async fn handle(&self, _: InboundMessage) -> HResult<Option<OutboundMessage>> {
        Ok(None)
    }
}

/// Handler registry seeded with a few protocols, plus an empty feature registry.
async fn registries() -> (Arc<RwLock<HandlerRegistry>>, Arc<RwLock<FeatureRegistry>>) {
    let registry = Arc::new(RwLock::new(HandlerRegistry::new()));
    let features = Arc::new(RwLock::new(FeatureRegistry::new()));
    {
        let mut w = registry.write().await;
        w.register(Arc::new(Advertise(vec![
            "https://didcomm.org/basicmessage/1.0/message".into(),
            "https://didcomm.org/coordinate-mediation/1.0/mediate-request".into(),
            "https://didcomm.org/coordinate-mediation/1.0/mediate-grant".into(),
        ])));
        w.register(Arc::new(DiscoverFeaturesV1Handler::new(
            registry.clone(),
            features.clone(),
        )));
        w.register(Arc::new(DiscoverFeaturesV2Handler::new(
            registry.clone(),
            features.clone(),
        )));
    }
    (registry, features)
}

fn inbound(msg_type: &str, body: serde_json::Value) -> InboundMessage {
    InboundMessage {
        message: Message::new("query-id-1".into(), msg_type.into(), body),
        context: MessageContext {
            from: Some("did:peer:bob".into()),
            to: Some("did:peer:alice".into()),
            thread_id: None,
            parent_thread_id: None,
            connection_id: Some("conn-1".into()),
            encrypted: true,
            authenticated: true,
            sender_endpoint: None,
            raw_plaintext: None,
        },
    }
}

#[tokio::test]
async fn v1_query_discloses_and_threads_back() {
    let (registry, features) = registries().await;
    let handler = DiscoverFeaturesV1Handler::new(registry.clone(), features.clone());

    let out = handler
        .handle(inbound(
            QUERY_V1_TYPE,
            serde_json::json!({ "query": "https://didcomm.org/*" }),
        ))
        .await
        .unwrap()
        .expect("should reply");

    assert_eq!(out.message.msg_type, DISCLOSE_V1_TYPE);
    assert_eq!(out.to, "did:peer:bob"); // reply to the sender
    assert_eq!(out.from, "did:peer:alice");
    assert_eq!(
        out.message.thread.as_ref().and_then(|t| t.thid.as_deref()),
        Some("query-id-1") // threaded back to the query
    );

    let disclose: DiscloseMessage = serde_json::from_value(out.message.body).unwrap();
    let pids: Vec<&str> = disclose.protocols.iter().map(|p| p.pid.as_str()).collect();
    assert!(pids.contains(&"https://didcomm.org/basicmessage/1.0"));
    assert!(pids.contains(&"https://didcomm.org/coordinate-mediation/1.0"));
    assert!(pids.contains(&"https://didcomm.org/discover-features/1.0"));
    // coordinate-mediation has two message types but is disclosed once.
    assert_eq!(
        pids.iter()
            .filter(|p| **p == "https://didcomm.org/coordinate-mediation/1.0")
            .count(),
        1
    );
}

#[tokio::test]
async fn v1_wildcard_narrows_results() {
    let (registry, features) = registries().await;
    let handler = DiscoverFeaturesV1Handler::new(registry.clone(), features.clone());
    let out = handler
        .handle(inbound(
            QUERY_V1_TYPE,
            serde_json::json!({ "query": "https://didcomm.org/basicmessage/*" }),
        ))
        .await
        .unwrap()
        .unwrap();
    let disclose: DiscloseMessage = serde_json::from_value(out.message.body).unwrap();
    let pids: Vec<&str> = disclose.protocols.iter().map(|p| p.pid.as_str()).collect();
    assert_eq!(pids, vec!["https://didcomm.org/basicmessage/1.0"]);
}

#[tokio::test]
async fn v2_queries_disclose_protocols() {
    let (registry, features) = registries().await;
    let handler = DiscoverFeaturesV2Handler::new(registry.clone(), features.clone());
    let out = handler
        .handle(inbound(
            QUERIES_V2_TYPE,
            serde_json::json!({
                "queries": [{ "feature-type": "protocol", "match": "https://didcomm.org/coordinate-mediation/*" }]
            }),
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(out.message.msg_type, DISCLOSURES_V2_TYPE);
    let d: DisclosuresMessage = serde_json::from_value(out.message.body).unwrap();
    let ids: Vec<&str> = d.disclosures.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(ids, vec!["https://didcomm.org/coordinate-mediation/1.0"]);
    assert!(d.disclosures.iter().all(|x| x.feature_type == "protocol"));
}

#[tokio::test]
async fn v2_goal_code_query_empty_without_declarations() {
    // No module declared goal-codes, so a goal-code query discloses nothing.
    let (registry, features) = registries().await;
    let handler = DiscoverFeaturesV2Handler::new(registry.clone(), features.clone());
    let out = handler
        .handle(inbound(
            QUERIES_V2_TYPE,
            serde_json::json!({
                "queries": [{ "feature-type": "goal-code", "match": "aries.*" }]
            }),
        ))
        .await
        .unwrap()
        .unwrap();
    let d: DisclosuresMessage = serde_json::from_value(out.message.body).unwrap();
    assert!(d.disclosures.is_empty());
}

/// Declared roles, goal-codes, and send-only protocols are surfaced on top of
/// the auto-derived handler-registry protocols (the hybrid registry).
#[tokio::test]
async fn v2_declared_roles_goal_codes_and_send_only() {
    let (registry, features) = registries().await;
    {
        let mut w = features.write().await;
        // Roles for a protocol that also has an inbound handler.
        w.register(Feature::protocol(
            "https://didcomm.org/coordinate-mediation/1.0",
            ["mediator"],
        ));
        // A send-only protocol (no inbound handler at all).
        w.register(Feature::protocol(
            "https://didcomm.org/report-problem/2.0",
            ["notifier"],
        ));
        w.register(Feature::goal_code("aries.vc.issue"));
    }
    let handler = DiscoverFeaturesV2Handler::new(registry.clone(), features.clone());
    let out = handler
        .handle(inbound(
            QUERIES_V2_TYPE,
            serde_json::json!({
                "queries": [
                    { "feature-type": "protocol", "match": "https://didcomm.org/*" },
                    { "feature-type": "goal-code", "match": "aries.*" }
                ]
            }),
        ))
        .await
        .unwrap()
        .unwrap();
    let d: DisclosuresMessage = serde_json::from_value(out.message.body).unwrap();

    // Declared roles override the auto-derived (role-less) coordinate-mediation.
    let cm = d
        .disclosures
        .iter()
        .find(|x| x.id == "https://didcomm.org/coordinate-mediation/1.0")
        .expect("coordinate-mediation disclosed");
    assert_eq!(cm.roles.as_deref(), Some(&["mediator".to_string()][..]));

    // Send-only protocol appears even though no handler advertises it.
    assert!(d
        .disclosures
        .iter()
        .any(|x| x.id == "https://didcomm.org/report-problem/2.0"));

    // Auto-derived protocol with no declared roles still discloses (roles=None).
    let bm = d
        .disclosures
        .iter()
        .find(|x| x.id == "https://didcomm.org/basicmessage/1.0")
        .expect("basicmessage disclosed");
    assert!(bm.roles.is_none());

    // Declared goal-code is disclosed.
    assert!(d
        .disclosures
        .iter()
        .any(|x| x.feature_type == "goal-code" && x.id == "aries.vc.issue"));
}
