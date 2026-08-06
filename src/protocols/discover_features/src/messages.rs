//! Discover Features message bodies (v1 + v2) and the protocol-matching helpers.

use serde::{Deserialize, Serialize};

/// v1 (RFC 0031) query message type URI.
pub const QUERY_V1_TYPE: &str = "https://didcomm.org/discover-features/1.0/query";
/// v1 (RFC 0031) disclose message type URI.
pub const DISCLOSE_V1_TYPE: &str = "https://didcomm.org/discover-features/1.0/disclose";
/// v2 (RFC 0557) queries message type URI.
pub const QUERIES_V2_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";
/// v2 (RFC 0557) disclosures message type URI.
pub const DISCLOSURES_V2_TYPE: &str = "https://didcomm.org/discover-features/2.0/disclosures";

// ─────────────────────────── v1 (RFC 0031) ───────────────────────────

/// Body of a v1 `query`. `query` is a protocol URI that may end in `*` as a
/// suffix wildcard (e.g. `https://didcomm.org/*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMessage {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A single protocol entry in a v1 `disclose`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDescriptor {
    pub pid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Body of a v1 `disclose`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscloseMessage {
    pub protocols: Vec<ProtocolDescriptor>,
}

// ─────────────────────────── v2 (RFC 0557) ───────────────────────────

/// A single query in a v2 `queries` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureQuery {
    /// e.g. `"protocol"` or `"goal-code"`. Only `"protocol"` is answered.
    #[serde(rename = "feature-type")]
    pub feature_type: String,
    /// URI with optional `*` suffix wildcard.
    #[serde(rename = "match")]
    pub match_: String,
}

/// Body of a v2 `queries`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueriesMessage {
    pub queries: Vec<FeatureQuery>,
}

/// A single disclosed feature in a v2 `disclosures` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDisclosure {
    #[serde(rename = "feature-type")]
    pub feature_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Body of a v2 `disclosures`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosuresMessage {
    pub disclosures: Vec<FeatureDisclosure>,
}

// ─────────────────────────── helpers ───────────────────────────

/// Derive a protocol ID from a message-type URI by dropping the message name:
/// `https://didcomm.org/basicmessage/1.0/message` → `https://didcomm.org/basicmessage/1.0`.
pub fn protocol_id(msg_type: &str) -> Option<String> {
    msg_type
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(pid, _msg)| pid.to_string())
}

/// Match a protocol ID against a query string with an optional trailing `*`
/// wildcard (prefix match); otherwise an exact match.
pub fn matches_query(query: &str, pid: &str) -> bool {
    match query.strip_suffix('*') {
        Some(prefix) => pid.starts_with(prefix),
        None => pid == query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_id_strips_message_name() {
        assert_eq!(
            protocol_id("https://didcomm.org/basicmessage/1.0/message").as_deref(),
            Some("https://didcomm.org/basicmessage/1.0")
        );
        assert_eq!(
            protocol_id("https://didcomm.org/discover-features/2.0/queries").as_deref(),
            Some("https://didcomm.org/discover-features/2.0")
        );
    }

    #[test]
    fn query_matching() {
        let pid = "https://didcomm.org/basicmessage/1.0";
        assert!(matches_query("https://didcomm.org/*", pid));
        assert!(matches_query("https://didcomm.org/basicmessage/*", pid));
        assert!(matches_query("https://didcomm.org/basicmessage/1.0", pid));
        assert!(!matches_query("https://didcomm.org/connections/*", pid));
        assert!(!matches_query("https://didcomm.org/basicmessage/2.0", pid));
    }
}
