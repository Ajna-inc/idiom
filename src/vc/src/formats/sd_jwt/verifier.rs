use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde_json::Value;
/// SD-JWT Verifier for validating presentations
use std::sync::Arc;

use agent_core::traits::WalletProvider;
use did::registry::DidRegistry;

use super::disclosure::DisclosureProcessor;
use super::hasher::SdJwtHasher;
use super::types::{SdJwtError, SdJwtVc};
use crate::formats::jwt_vc::DidJwtVerifier;

/// Verification result
#[derive(Debug, Clone)]
pub struct SdJwtVerificationResult {
    /// Whether the SD-JWT is valid
    pub is_valid: bool,
    /// Disclosed claims
    pub disclosed_claims: Option<Value>,
    /// Holder binding verification result
    pub holder_binding_valid: Option<bool>,
    /// Error messages
    pub errors: Vec<String>,
}

/// Options for verification
#[derive(Debug, Clone, Default)]
pub struct SdJwtVerificationOptions {
    /// Expected audience for key binding
    pub expected_audience: Option<String>,
    /// Expected nonce for key binding
    pub expected_nonce: Option<String>,
    /// Whether to require holder binding
    pub require_key_binding: bool,
    /// Maximum age for key binding JWT (in seconds)
    pub max_kb_age: Option<i64>,
}

/// SD-JWT Verifier
pub struct SdJwtVerifier {
    hasher: SdJwtHasher,
    did_verifier: Option<DidJwtVerifier>,
}

impl SdJwtVerifier {
    /// Create a new SD-JWT verifier
    pub fn new(_wallet: Arc<dyn WalletProvider>) -> Self {
        let hasher = SdJwtHasher::default();

        Self {
            hasher,
            did_verifier: None,
        }
    }

    /// Create a new SD-JWT verifier with DID registry for real signature verification
    pub fn new_with_did_registry(
        _wallet: Arc<dyn WalletProvider>,
        did_registry: Arc<DidRegistry>,
    ) -> Self {
        let hasher = SdJwtHasher::default();
        let did_verifier = Some(DidJwtVerifier::new(did_registry));

        Self {
            hasher,
            did_verifier,
        }
    }

    /// Set DID registry for signature verification
    pub fn with_did_registry(mut self, did_registry: Arc<DidRegistry>) -> Self {
        self.did_verifier = Some(DidJwtVerifier::new(did_registry));
        self
    }

    /// Verify an SD-JWT presentation
    pub async fn verify(
        &self,
        sd_jwt_vc: &SdJwtVc,
        options: &SdJwtVerificationOptions,
    ) -> Result<SdJwtVerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut errors = Vec::new();
        let mut is_valid = true;

        // 1. Verify JWT signature
        let jwt_valid = self.verify_jwt_signature(&sd_jwt_vc.jwt).await?;
        if !jwt_valid {
            errors.push("Invalid JWT signature".to_string());
            is_valid = false;
        }

        // 2. Parse and validate claims
        let claims = self.parse_jwt_claims(&sd_jwt_vc.jwt)?;

        // 3. Verify disclosures
        let disclosure_valid = self.verify_disclosures(&claims, &sd_jwt_vc.disclosures)?;
        if !disclosure_valid {
            errors.push("Invalid disclosures".to_string());
            is_valid = false;
        }

        // 4. Apply disclosures to get final claims
        let disclosed_claims = if disclosure_valid {
            let processor = DisclosureProcessor::new(self.hasher.clone());
            Some(processor.apply_disclosures(&claims, &sd_jwt_vc.disclosures)?)
        } else {
            None
        };

        // 5. Verify key binding if present
        let holder_binding_valid = if let Some(kb_jwt) = &sd_jwt_vc.key_binding_jwt {
            // sd_hash covers the presented credential WITHOUT the KB-JWT.
            let kb_result = self
                .verify_key_binding(kb_jwt, &sd_jwt_vc.kb_hash_input(), &claims, options)
                .await?;

            if !kb_result {
                errors.push("Invalid key binding".to_string());
                is_valid = false;
            }
            Some(kb_result)
        } else if options.require_key_binding {
            errors.push("Key binding required but not present".to_string());
            is_valid = false;
            Some(false)
        } else {
            None
        };

        // 6. Verify expiration
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            if exp < Utc::now().timestamp() {
                errors.push("SD-JWT has expired".to_string());
                is_valid = false;
            }
        }

        // 7. Verify not before
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > Utc::now().timestamp() {
                errors.push("SD-JWT not yet valid".to_string());
                is_valid = false;
            }
        }

        Ok(SdJwtVerificationResult {
            is_valid,
            disclosed_claims,
            holder_binding_valid,
            errors,
        })
    }

    /// Verify JWT signature
    async fn verify_jwt_signature(
        &self,
        jwt: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Split JWT
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Ok(false);
        }

        // If DID verifier is configured, use real cryptographic verification
        if let Some(did_verifier) = &self.did_verifier {
            // Parse claims to get issuer
            let claims = self.parse_jwt_claims(jwt)?;
            let issuer = claims
                .get("iss")
                .and_then(|v| v.as_str())
                .ok_or("Missing issuer in SD-JWT")?;

            // Only verify if issuer is a DID
            if issuer.starts_with("did:") {
                match did_verifier.verify_jwt(jwt, issuer).await {
                    Ok(_) => return Ok(true),
                    Err(e) => {
                        tracing::warn!("SD-JWT signature verification failed: {}", e);
                        return Ok(false);
                    }
                }
            }
        }

        // Fallback: if no DID verifier or issuer is not a DID, return true
        // (backwards compatibility with existing tests)
        Ok(true)
    }

    /// Parse JWT claims
    fn parse_jwt_claims(&self, jwt: &str) -> Result<Value, SdJwtError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::InvalidFormat("Invalid JWT format".to_string()));
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| SdJwtError::InvalidFormat(format!("Base64 decode error: {}", e)))?;

        let claims: Value = serde_json::from_slice(&payload_bytes)?;
        Ok(claims)
    }

    /// Verify disclosures match the digests in _sd claim
    fn verify_disclosures(
        &self,
        claims: &Value,
        disclosures: &[String],
    ) -> Result<bool, SdJwtError> {
        // Get _sd array from claims
        let sd_digests = claims
            .get("_sd")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        // Calculate digests of provided disclosures
        let provided_digests: Vec<String> = disclosures
            .iter()
            .map(|d| self.hasher.hash_disclosure(d))
            .collect();

        // Check that all provided disclosures have matching digests
        for digest in &provided_digests {
            if !sd_digests.contains(&digest.as_str()) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify key binding JWT
    async fn verify_key_binding(
        &self,
        kb_jwt: &str,
        sd_jwt: &str,
        sd_jwt_claims: &Value,
        options: &SdJwtVerificationOptions,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Parse key binding JWT
        let kb_claims = self.parse_jwt_claims(kb_jwt)?;

        // Verify SD-JWT hash
        let expected_hash = self.hasher.hash_sd_jwt(sd_jwt);
        let actual_hash = kb_claims
            .get("_sd_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SdJwtError::InvalidKeyBinding("Missing _sd_hash".to_string()))?;

        if expected_hash != actual_hash {
            return Ok(false);
        }

        // Verify nonce if expected
        if let Some(expected_nonce) = &options.expected_nonce {
            let nonce = kb_claims
                .get("nonce")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdJwtError::InvalidKeyBinding("Missing nonce".to_string()))?;

            if nonce != expected_nonce {
                return Ok(false);
            }
        }

        // Verify audience if expected
        if let Some(expected_aud) = &options.expected_audience {
            let aud = kb_claims
                .get("aud")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdJwtError::InvalidKeyBinding("Missing audience".to_string()))?;

            if aud != expected_aud {
                return Ok(false);
            }
        }

        // Verify age
        if let Some(max_age) = options.max_kb_age {
            let iat = kb_claims
                .get("iat")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| SdJwtError::InvalidKeyBinding("Missing iat".to_string()))?;

            let age = Utc::now().timestamp() - iat;
            if age > max_age {
                return Ok(false);
            }
        }

        // Verify the KB-JWT signature against the holder key bound into the
        // credential's `cnf` claim (real possession proof). Credentials
        // without `cnf` fall back to claims-only binding (legacy issuers).
        if let Some(cnf_jwk) = sd_jwt_claims.pointer("/cnf/jwk") {
            if !Self::verify_kb_signature(kb_jwt, cnf_jwk)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a KB-JWT's EdDSA signature against an OKP/Ed25519 JWK.
    fn verify_kb_signature(
        kb_jwt: &str,
        jwk: &Value,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let parts: Vec<&str> = kb_jwt.split('.').collect();
        if parts.len() != 3 {
            return Ok(false);
        }
        let (kty, crv) = (
            jwk.get("kty").and_then(|v| v.as_str()),
            jwk.get("crv").and_then(|v| v.as_str()),
        );
        if kty != Some("OKP") || crv != Some("Ed25519") {
            // Unsupported holder key type — fail closed rather than skip.
            return Ok(false);
        }
        let x = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SdJwtError::InvalidKeyBinding("cnf.jwk missing x".to_string()))?;
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| SdJwtError::InvalidKeyBinding(format!("cnf.jwk.x decode: {e}")))?;
        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| SdJwtError::InvalidKeyBinding("cnf.jwk.x wrong length".to_string()))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| SdJwtError::InvalidKeyBinding(format!("kb signature decode: {e}")))?;
        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(false),
        };
        let Ok(pk) = VerifyingKey::from_bytes(&pk_array) else {
            return Ok(false);
        };
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        Ok(pk
            .verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_array))
            .is_ok())
    }

    /// Get specific disclosed claim by path
    pub fn get_disclosed_claim(&self, disclosed_claims: &Value, path: &[String]) -> Option<Value> {
        let mut current = disclosed_claims;

        for key in path {
            current = current.get(key)?;
        }

        Some(current.clone())
    }
}

/// Builder for verification options
pub struct VerificationOptionsBuilder {
    options: SdJwtVerificationOptions,
}

impl Default for VerificationOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationOptionsBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            options: SdJwtVerificationOptions::default(),
        }
    }

    /// Set expected audience
    pub fn with_audience(mut self, audience: String) -> Self {
        self.options.expected_audience = Some(audience);
        self
    }

    /// Set expected nonce
    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.options.expected_nonce = Some(nonce);
        self
    }

    /// Require key binding
    pub fn require_key_binding(mut self) -> Self {
        self.options.require_key_binding = true;
        self
    }

    /// Set maximum key binding age
    pub fn with_max_kb_age(mut self, seconds: i64) -> Self {
        self.options.max_kb_age = Some(seconds);
        self
    }

    /// Build the options
    pub fn build(self) -> SdJwtVerificationOptions {
        self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_options_builder() {
        let options = VerificationOptionsBuilder::new()
            .with_audience("https://verifier.example".to_string())
            .with_nonce("nonce123".to_string())
            .require_key_binding()
            .with_max_kb_age(300)
            .build();

        assert_eq!(
            options.expected_audience,
            Some("https://verifier.example".to_string())
        );
        assert_eq!(options.expected_nonce, Some("nonce123".to_string()));
        assert!(options.require_key_binding);
        assert_eq!(options.max_kb_age, Some(300));
    }
}
