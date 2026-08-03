//! did:jwk Method Implementation
//!
//! Implements did:jwk resolution.
//!
//! # Format
//! did:jwk:<base64url-encoded-jwk>
//!
//! # Note
//! did:jwk is a deterministic method - the DID Document can be derived
//! directly from the JWK embedded in the DID itself.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::core::{DidDocument, DidResolver, ResolutionError, ResolutionResult, DID};

/// did:jwk Resolver - Resolves did:jwk DIDs to DID Documents
pub struct JwkDidResolver;

impl Default for JwkDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl JwkDidResolver {
    pub fn new() -> Self {
        Self
    }

    /// Decode and resolve a did:jwk DID
    fn resolve_jwk(did: &DID) -> Result<DidDocument, ResolutionError> {
        // Extract the JWK part from the DID
        let jwk_part = did.method_specific_id();

        // Decode base64url
        let decoded = URL_SAFE_NO_PAD
            .decode(jwk_part)
            .map_err(|e| ResolutionError::InvalidDid(format!("Failed to decode JWK: {}", e)))?;

        // Parse JWK JSON
        let _jwk: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| ResolutionError::InvalidDid(format!("Failed to parse JWK: {}", e)))?;

        // Create a minimal DID Document
        // In a full implementation, we would create proper verification methods from the JWK
        let doc = DidDocument {
            id: did.as_str().to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            context: Some(serde_json::json!("https://www.w3.org/ns/did/v1")),
            also_known_as: vec![],
            controller: None,
        };

        Ok(doc)
    }
}

#[async_trait]
impl DidResolver for JwkDidResolver {
    fn method_name(&self) -> &str {
        "jwk"
    }

    fn allows_caching(&self) -> bool {
        false // did:jwk is deterministic, no caching needed
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        Self::resolve_jwk(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwk_resolver_method_name() {
        let resolver = JwkDidResolver::new();
        assert_eq!(resolver.method_name(), "jwk");
    }

    #[tokio::test]
    async fn test_jwk_resolver_no_caching() {
        let resolver = JwkDidResolver::new();
        assert!(!resolver.allows_caching());
    }

    // Note: Full did:jwk resolution tests require valid did:jwk DIDs
    // which need proper JWK encoding
}
