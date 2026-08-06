//! Declarative registry of discoverable **features** (RFC 0557 §"feature-type").
//!
//! Modules register the protocols (and goal-codes) they support — with the
//! roles they can play — so the Discover Features protocol can advertise them
//! precisely, including *send-only* protocols that have no inbound handler and
//! per-protocol roles. This complements the automatic protocol enumeration
//! derived from the [`super::HandlerRegistry`]: a discovery responder typically
//! seeds from the handler registry (zero-config) and merges these declared
//! features on top (adding roles / goal-codes / send-only entries).

use std::collections::BTreeMap;

/// A discoverable feature: a protocol or goal-code the agent supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feature {
    /// Feature type — `"protocol"` or `"goal-code"` (extensible per RFC 0557).
    pub feature_type: String,
    /// Protocol URI (e.g. `https://didcomm.org/issue-credential/3.0`) or
    /// goal-code identifier.
    pub id: String,
    /// Roles the agent can play in this protocol (e.g. `["issuer", "holder"]`).
    /// Empty when unspecified.
    pub roles: Vec<String>,
}

impl Feature {
    /// A `protocol` feature with the given roles.
    pub fn protocol<I, S>(id: impl Into<String>, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            feature_type: "protocol".to_string(),
            id: id.into(),
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }

    /// A `goal-code` feature.
    pub fn goal_code(id: impl Into<String>) -> Self {
        Self {
            feature_type: "goal-code".to_string(),
            id: id.into(),
            roles: Vec::new(),
        }
    }
}

/// Registry of declared features, populated by modules and queried by the
/// Discover Features handlers. Re-declaring a feature unions its roles rather
/// than duplicating it, so seeding + augmentation compose cleanly.
#[derive(Debug, Default)]
pub struct FeatureRegistry {
    features: BTreeMap<(String, String), Feature>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a feature, merging roles into any existing entry with the same
    /// `(feature_type, id)`.
    pub fn register(&mut self, feature: Feature) {
        let key = (feature.feature_type.clone(), feature.id.clone());
        self.features
            .entry(key)
            .and_modify(|existing| {
                for role in &feature.roles {
                    if !existing.roles.contains(role) {
                        existing.roles.push(role.clone());
                    }
                }
            })
            .or_insert(feature);
    }

    /// Register many features.
    pub fn register_all(&mut self, features: impl IntoIterator<Item = Feature>) {
        for f in features {
            self.register(f);
        }
    }

    /// Whether a `(feature_type, id)` is already declared.
    pub fn contains(&self, feature_type: &str, id: &str) -> bool {
        self.features
            .contains_key(&(feature_type.to_string(), id.to_string()))
    }

    /// All registered features (sorted by `(feature_type, id)`).
    pub fn all(&self) -> Vec<Feature> {
        self.features.values().cloned().collect()
    }

    /// Features matching a `feature_type` and a `match` pattern (`"*"` matches
    /// all; a trailing `*` is a prefix match; otherwise exact).
    pub fn query(&self, feature_type: &str, match_pattern: &str) -> Vec<Feature> {
        self.features
            .values()
            .filter(|f| f.feature_type == feature_type)
            .filter(|f| matches(match_pattern, &f.id))
            .cloned()
            .collect()
    }
}

/// Wildcard match used by [`FeatureRegistry::query`] and the discover-features
/// handlers: `"*"` = all, trailing `*` = prefix, else exact.
pub fn matches(pattern: &str, id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => id == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_merges_roles() {
        let mut r = FeatureRegistry::new();
        r.register(Feature::protocol("https://didcomm.org/x/1.0", ["issuer"]));
        r.register(Feature::protocol("https://didcomm.org/x/1.0", ["holder"]));
        let all = r.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].roles, vec!["issuer", "holder"]);
    }

    #[test]
    fn query_by_type_and_wildcard() {
        let mut r = FeatureRegistry::new();
        r.register(Feature::protocol("https://didcomm.org/a/1.0", ["r"]));
        r.register(Feature::protocol("https://didcomm.org/b/1.0", ["r"]));
        r.register(Feature::goal_code("aries.vc.issue"));
        assert_eq!(r.query("protocol", "*").len(), 2);
        assert_eq!(r.query("protocol", "https://didcomm.org/a/*").len(), 1);
        assert_eq!(r.query("goal-code", "*").len(), 1);
        assert_eq!(
            r.query("protocol", "https://didcomm.org/a/1.0")[0].roles,
            vec!["r"]
        );
    }
}
