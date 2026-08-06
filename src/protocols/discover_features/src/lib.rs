//! DIDComm **Discover Features** protocol — RFC 0031 (v1 `query`/`disclose`) and
//! RFC 0557 (v2 `queries`/`disclosures`).
//!
//! A responder agent answers "which protocols do you support?" queries by
//! enumerating the message-type URIs registered in the shared
//! [`didcomm::messaging::HandlerRegistry`], deriving unique protocol IDs, and
//! replying with a threaded disclose/disclosures message. This lets peers (e.g.
//! Credo, ACA-Py) negotiate which protocols to use.
//!
//! Register both handlers with the agent's registry to answer either version:
//! ```rust,ignore
//! registry.register(Arc::new(DiscoverFeaturesV1Handler::new(registry_arc.clone())));
//! registry.register(Arc::new(DiscoverFeaturesV2Handler::new(registry_arc.clone())));
//! ```

pub mod handlers;
pub mod messages;

pub use handlers::{DiscoverFeaturesV1Handler, DiscoverFeaturesV2Handler};
pub use messages::{
    matches_query, protocol_id, DiscloseMessage, DisclosuresMessage, FeatureDisclosure,
    FeatureQuery, ProtocolDescriptor, QueriesMessage, QueryMessage, DISCLOSE_V1_TYPE,
    DISCLOSURES_V2_TYPE, QUERIES_V2_TYPE, QUERY_V1_TYPE,
};
