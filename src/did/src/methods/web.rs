//! did:web Method Implementation
//!
//! Implements did:web resolution by fetching DID Documents via HTTPS.
//!
//! # Format
//! did:web:<domain-name>[:port][:<path>]
//!
//! # Examples
//! - did:web:example.com -> https://example.com/.well-known/did.json
//! - did:web:example.com:user:alice -> https://example.com/user/alice/did.json

use async_trait::async_trait;

use crate::core::{DidDocument, DidResolver, ResolutionError, ResolutionResult, DID};

/// did:web Resolver - Resolves did:web DIDs by fetching from HTTPS
pub struct WebDidResolver {
    client: reqwest::Client,
}

impl Default for WebDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl WebDidResolver {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Convert did:web DID to HTTPS URL
    fn did_to_url(did: &DID) -> Result<String, ResolutionError> {
        let method_specific_id = did.method_specific_id();

        // Split by colons to get domain and path components
        let parts: Vec<&str> = method_specific_id.split(':').collect();

        if parts.is_empty() {
            return Err(ResolutionError::InvalidDid(
                "Empty method-specific-id".to_string(),
            ));
        }

        let domain = parts[0];

        // Build the URL
        let url = if parts.len() == 1 {
            // did:web:example.com -> https://example.com/.well-known/did.json
            format!("https://{}/.well-known/did.json", domain)
        } else {
            // did:web:example.com:user:alice -> https://example.com/user/alice/did.json
            let path = parts[1..].join("/");
            format!("https://{}/{}/did.json", domain, path)
        };

        Ok(url)
    }
}

#[async_trait]
impl DidResolver for WebDidResolver {
    fn method_name(&self) -> &str {
        "web"
    }

    fn allows_caching(&self) -> bool {
        true // did:web is remote-fetched, caching is beneficial
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        // Convert DID to URL
        let url = Self::did_to_url(did)?;

        // Fetch the DID Document
        let response = self.client.get(&url).send().await.map_err(|e| {
            ResolutionError::ResolutionFailed(format!("HTTP request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(ResolutionError::NotFound(format!(
                "HTTP {} for {}",
                response.status(),
                url
            )));
        }

        // Parse the DID Document
        let doc: DidDocument = response.json().await.map_err(|e| {
            ResolutionError::ResolutionFailed(format!("Failed to parse DID Document: {}", e))
        })?;

        // Verify the DID in the document matches
        if doc.id != did.as_str() {
            return Err(ResolutionError::ResolutionFailed(format!(
                "DID mismatch: expected {}, got {}",
                did.as_str(),
                doc.id
            )));
        }

        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_web_resolver_method_name() {
        let resolver = WebDidResolver::new();
        assert_eq!(resolver.method_name(), "web");
    }

    #[tokio::test]
    async fn test_web_resolver_allows_caching() {
        let resolver = WebDidResolver::new();
        assert!(resolver.allows_caching()); // did:web should be cached
    }

    #[test]
    fn test_did_to_url_simple() {
        let did = DID::parse("did:web:example.com").unwrap();
        let url = WebDidResolver::did_to_url(&did).unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn test_did_to_url_with_path() {
        let did = DID::parse("did:web:example.com:user:alice").unwrap();
        let url = WebDidResolver::did_to_url(&did).unwrap();
        assert_eq!(url, "https://example.com/user/alice/did.json");
    }

    // Note: Live resolution tests would require actual HTTPS endpoints
    // and are better suited for integration tests
}
