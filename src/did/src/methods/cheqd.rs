//! did:cheqd Method Implementation
//!
//! Resolves did:cheqd DIDs via the public cheqd Universal Resolver gateway
//! at `https://resolver.cheqd.net/1.0/identifiers/{did}`. The gateway speaks
//! the standard W3C DID Resolution flow, so we just GET it and surface the
//! `didDocument` field.
//!
//! # Format
//! did:cheqd:{namespace}:{unique-id}
//! - namespace: `mainnet` or `testnet`
//! - unique-id: 32-character base58btc string or UUID
//!
//! # Examples
//! - `did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1J`
//! - `did:cheqd:testnet:55dbc8bf-fba3-4117-855c-1e0dc1d3bb47`

use async_trait::async_trait;

use crate::core::{DidDocument, DidResolver, ResolutionError, ResolutionResult, DID};

const DEFAULT_GATEWAY: &str = "https://resolver.cheqd.net/1.0/identifiers";

/// did:cheqd Resolver — fetches DID documents via the cheqd Universal Resolver.
pub struct CheqdDidResolver {
    client: reqwest::Client,
    gateway: String,
}

impl Default for CheqdDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CheqdDidResolver {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            gateway: DEFAULT_GATEWAY.to_string(),
        }
    }

    /// Override the resolver gateway (e.g. point at a self-hosted instance
    /// or a mock server for tests).
    pub fn with_gateway(mut self, gateway: impl Into<String>) -> Self {
        self.gateway = gateway.into();
        self
    }

    /// Validate the basic shape of a did:cheqd identifier before issuing
    /// a network call.
    fn validate(did: &DID) -> Result<(), ResolutionError> {
        if did.method() != "cheqd" {
            return Err(ResolutionError::InvalidDid(format!(
                "expected cheqd method, got {}",
                did.method()
            )));
        }
        let id = did.method_specific_id();
        let parts: Vec<&str> = id.split(':').collect();
        if parts.len() != 2 {
            return Err(ResolutionError::InvalidDid(
                "did:cheqd must be namespace:unique-id".into(),
            ));
        }
        let namespace = parts[0];
        if namespace != "mainnet" && namespace != "testnet" {
            return Err(ResolutionError::InvalidDid(format!(
                "did:cheqd namespace must be mainnet or testnet, got {}",
                namespace
            )));
        }
        if parts[1].is_empty() {
            return Err(ResolutionError::InvalidDid(
                "did:cheqd unique-id is empty".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl DidResolver for CheqdDidResolver {
    fn method_name(&self) -> &str {
        "cheqd"
    }

    fn allows_caching(&self) -> bool {
        // cheqd documents are immutable for a given DID until update —
        // safe to cache between resolutions.
        true
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        Self::validate(did)?;
        let url = format!("{}/{}", self.gateway.trim_end_matches('/'), did);

        let response = self.client.get(&url).send().await.map_err(|e| {
            ResolutionError::ResolutionFailed(format!("cheqd gateway request failed: {}", e))
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ResolutionError::NotFound(did.to_string()));
        }
        if !status.is_success() {
            return Err(ResolutionError::ResolutionFailed(format!(
                "cheqd gateway returned {}",
                status
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            ResolutionError::ResolutionFailed(format!("cheqd gateway returned invalid JSON: {}", e))
        })?;

        // Universal Resolver wrapper:
        //   { didDocument: {...}, didResolutionMetadata, didDocumentMetadata }
        let doc_value = body.get("didDocument").cloned().ok_or_else(|| {
            ResolutionError::ResolutionFailed("cheqd response missing didDocument".into())
        })?;

        serde_json::from_value(doc_value).map_err(|e| {
            ResolutionError::ResolutionFailed(format!("cheqd DID document decode: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_correct_did() {
        let did = DID::parse("did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1J").unwrap();
        assert!(CheqdDidResolver::validate(&did).is_ok());
    }

    #[test]
    fn validates_testnet_did() {
        let did = DID::parse("did:cheqd:testnet:55dbc8bf-fba3-4117-855c-1e0dc1d3bb47").unwrap();
        assert!(CheqdDidResolver::validate(&did).is_ok());
    }

    #[test]
    fn rejects_invalid_namespace() {
        let did = DID::parse("did:cheqd:dev:zF7rhDBfUt9d1gJPjx7s1J").unwrap();
        assert!(CheqdDidResolver::validate(&did).is_err());
    }

    #[test]
    fn rejects_missing_namespace() {
        let did = DID::parse("did:cheqd:zF7rhDBfUt9d1gJPjx7s1J").unwrap();
        assert!(CheqdDidResolver::validate(&did).is_err());
    }

    #[test]
    fn method_name_is_cheqd() {
        let r = CheqdDidResolver::new();
        assert_eq!(r.method_name(), "cheqd");
    }

    #[test]
    fn caching_is_allowed() {
        let r = CheqdDidResolver::new();
        assert!(r.allows_caching());
    }
}
