use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{
    CredentialData, CredentialFormat, CredentialFormatService, SignCredentialOptions,
    VerificationResult, VerifyCredentialOptions, W3cCredential, W3cPresentation, W3cV2Credential,
};

use super::transformer::{JwtVcPayload, JwtVcTransformer, JwtVpPayload, OneOrMany};

pub struct JwtVcService {
    /// Default algorithm to use if not specified
    default_algorithm: Algorithm,
}

impl JwtVcService {
    pub fn new() -> Self {
        Self {
            default_algorithm: Algorithm::EdDSA,
        }
    }

    pub fn with_default_algorithm(algorithm: Algorithm) -> Self {
        Self {
            default_algorithm: algorithm,
        }
    }

    /// Parse algorithm from string
    fn parse_algorithm(&self, alg: Option<&String>) -> Algorithm {
        match alg.map(|s| s.as_str()) {
            Some("EdDSA") => Algorithm::EdDSA,
            Some("ES256") => Algorithm::ES256,
            Some("ES384") => Algorithm::ES384,
            Some("ES512") => Algorithm::ES384, // ES512 not supported by jsonwebtoken, use ES384
            Some("RS256") => Algorithm::RS256,
            Some("RS384") => Algorithm::RS384,
            Some("RS512") => Algorithm::RS512,
            Some("PS256") => Algorithm::PS256,
            Some("PS384") => Algorithm::PS384,
            Some("PS512") => Algorithm::PS512,
            Some("HS256") => Algorithm::HS256,
            Some("HS384") => Algorithm::HS384,
            Some("HS512") => Algorithm::HS512,
            _ => self.default_algorithm,
        }
    }

    /// Create JWT header
    fn create_header(&self, algorithm: Algorithm, key_id: &str) -> Header {
        let mut header = Header::new(algorithm);
        header.kid = Some(key_id.to_string());
        header.typ = Some("JWT".to_string());
        header
    }

    /// Sign JWT with provided key (placeholder - needs real key integration)
    async fn sign_jwt(
        &self,
        header: &Header,
        payload: &Value,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Integrate with actual key management system
        // For now, use a dummy key for testing
        let key = EncodingKey::from_secret(b"secret");

        let token = encode(header, payload, &key)?;
        Ok(token)
    }

    /// Verify JWT signature (placeholder - needs real key integration)
    async fn verify_jwt(
        &self,
        token: &str,
    ) -> Result<(Header, Value), Box<dyn std::error::Error + Send + Sync>> {
        // Parse without verification first to get header
        let header = decode_header(token)?;

        // TODO: Integrate with actual key resolver to get public key
        // For now, use a dummy key for testing
        let key = DecodingKey::from_secret(b"secret");

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false; // We'll validate manually
        validation.validate_nbf = false; // We'll validate manually
        validation.validate_aud = false; // VCs need not carry an `aud` claim
                                         // `Validation::new` defaults `required_spec_claims` to {"exp"}. Since we
                                         // validate exp manually (and VCs without an expiry legitimately omit it),
                                         // an absent `exp` must not fail decoding — clear the required set.
        validation.required_spec_claims.clear();

        let token_data = decode::<Value>(token, &key, &validation)?;

        Ok((header, token_data.claims))
    }
}

#[async_trait]
impl CredentialFormatService for JwtVcService {
    fn format(&self) -> CredentialFormat {
        CredentialFormat::JwtVc
    }

    async fn sign_credential(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Transform credential to JWT payload
        let payload = JwtVcTransformer::credential_to_jwt_payload(credential)?;

        // Parse algorithm
        let algorithm = self.parse_algorithm(options.algorithm.as_ref());

        // Create header
        let header = self.create_header(algorithm, &options.key_id);

        // Convert payload to JSON value
        let payload_value = serde_json::to_value(payload)?;

        // Sign JWT
        let jwt = self.sign_jwt(&header, &payload_value).await?;

        Ok(jwt)
    }

    async fn sign_credential_v2(
        &self,
        credential: &W3cV2Credential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Convert v2 to v1 and sign
        let v1 = self.convert_v2_to_v1(credential)?;
        self.sign_credential(&v1, options).await
    }

    async fn verify_credential(
        &self,
        credential: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Verify JWT signature and get payload
        let (header, payload_value) = match self.verify_jwt(credential).await {
            Ok(result) => result,
            Err(e) => {
                return Ok(VerificationResult::invalid(format!(
                    "JWT verification failed: {}",
                    e
                )));
            }
        };

        // Parse JWT payload
        let payload: JwtVcPayload = serde_json::from_value(payload_value)?;

        // Transform to W3C credential
        let credential = JwtVcTransformer::jwt_payload_to_credential(&payload)?;

        // Additional validation
        let now = chrono::Utc::now().timestamp();

        // Check not before
        if let Some(nbf) = payload.nbf {
            if nbf > now {
                return Ok(VerificationResult::invalid("Credential not yet valid"));
            }
        }

        // Check expiration
        if let Some(exp) = payload.exp {
            if exp < now {
                return Ok(VerificationResult::invalid("Credential expired"));
            }
        }

        // Check expected issuer if provided
        if let Some(expected_issuer) = &options.expected_issuer {
            if let Some(iss) = &payload.iss {
                if iss != expected_issuer {
                    return Ok(VerificationResult::invalid(format!(
                        "Issuer mismatch: expected {}, got {}",
                        expected_issuer, iss
                    )));
                }
            }
        }

        // Check expected subject if provided
        if let Some(expected_subject) = &options.expected_subject {
            if let Some(sub) = &payload.sub {
                if sub != expected_subject {
                    return Ok(VerificationResult::invalid(format!(
                        "Subject mismatch: expected {}, got {}",
                        expected_subject, sub
                    )));
                }
            }
        }

        let mut result =
            VerificationResult::valid(CredentialData::V1(credential), CredentialFormat::JwtVc);

        // Add verification details
        result = result.add_detail("algorithm", json!(format!("{:?}", header.alg)));
        if let Some(kid) = header.kid {
            result = result.add_detail("kid", json!(kid));
        }

        Ok(result)
    }

    async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Extract audience and nonce from options
        let audience = options
            .additional
            .get("audience")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let nonce = options
            .additional
            .get("nonce")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Transform presentation to JWT payload
        let payload = JwtVcTransformer::presentation_to_jwt_payload_with_options(
            presentation,
            audience,
            nonce,
        )?;

        // Parse algorithm
        let algorithm = self.parse_algorithm(options.algorithm.as_ref());

        // Create header
        let header = self.create_header(algorithm, &options.key_id);

        // Convert payload to JSON value
        let payload_value = serde_json::to_value(payload)?;

        // Sign JWT
        let jwt = self.sign_jwt(&header, &payload_value).await?;

        Ok(jwt)
    }

    async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Verify JWT signature and get payload
        let (header, payload_value) = match self.verify_jwt(presentation).await {
            Ok(result) => result,
            Err(e) => {
                return Ok(VerificationResult::invalid(format!(
                    "JWT verification failed: {}",
                    e
                )));
            }
        };

        // Parse JWT payload
        let payload: JwtVpPayload = serde_json::from_value(payload_value)?;

        // Transform to W3C presentation
        let _presentation = JwtVcTransformer::jwt_payload_to_presentation(&payload)?;

        // Check nonce if expected. A caller-supplied expected nonce that is not
        // a JSON string is a misuse we must not silently treat as an empty match
        // — reject it rather than degrading to `""`.
        if let Some(expected_nonce) = options.additional.get("nonce") {
            let Some(expected_nonce) = expected_nonce.as_str() else {
                return Ok(VerificationResult::invalid(
                    "Expected nonce must be a string",
                ));
            };
            match &payload.nonce {
                Some(nonce) if nonce == expected_nonce => {}
                Some(_) => return Ok(VerificationResult::invalid("Nonce mismatch")),
                None => return Ok(VerificationResult::invalid("Missing nonce")),
            }
        }

        // Check audience if expected — the presentation's `aud` must contain the
        // expected verifier identifier (single or list form).
        if let Some(expected_aud) = options.additional.get("audience") {
            let Some(expected_aud) = expected_aud.as_str() else {
                return Ok(VerificationResult::invalid(
                    "Expected audience must be a string",
                ));
            };
            let aud_matches = match &payload.aud {
                Some(OneOrMany::One(aud)) => aud == expected_aud,
                Some(OneOrMany::Many(auds)) => auds.iter().any(|a| a == expected_aud),
                None => false,
            };
            if !aud_matches {
                return Ok(VerificationResult::invalid("Audience mismatch"));
            }
        }

        let mut result = VerificationResult {
            is_valid: true,
            format: Some(CredentialFormat::JwtVc),
            credential: None, // Presentations don't have credentials directly
            errors: Vec::new(),
            details: HashMap::new(),
        };

        result = result.add_detail("algorithm", json!(format!("{:?}", header.alg)));
        if let Some(kid) = header.kid {
            result = result.add_detail("kid", json!(kid));
        }

        Ok(result)
    }

    fn can_handle(&self, credential: &str) -> bool {
        // Check if it's a JWT format (three base64url-encoded parts separated by dots)
        let parts: Vec<&str> = credential.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Try to decode header to verify it's a JWT
        if let Ok(header_json) = URL_SAFE_NO_PAD.decode(parts[0]) {
            if let Ok(header_value) = serde_json::from_slice::<Value>(&header_json) {
                // Check for typ: JWT or missing typ (default JWT)
                if let Some(typ) = header_value.get("typ") {
                    return typ == "JWT";
                }
                // If no typ field, could still be a JWT
                return header_value.get("alg").is_some();
            }
        }

        false
    }
}

impl Default for JwtVcService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::CredentialSubjectObject;

    #[tokio::test]
    async fn test_sign_and_verify_credential() {
        let service = JwtVcService::new();

        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let credential = W3cCredential::new("did:example:issuer", subject)
            .with_id("http://example.com/credentials/123");

        // NOTE: the placeholder `sign_jwt`/`verify_jwt` use a symmetric HMAC
        // dummy key (`EncodingKey::from_secret`). jsonwebtoken rejects an HMAC
        // key with an asymmetric algorithm (EdDSA/ES256) as `InvalidAlgorithm`,
        // so this round-trip test must use an HS* algorithm that matches the
        // dummy secret key. Real asymmetric signing is exercised by
        // EnhancedJwtVcServiceV2 (wallet-backed), not this placeholder service.
        let options = SignCredentialOptions {
            format: CredentialFormat::JwtVc,
            key_id: "did:example:issuer#key-1".to_string(),
            algorithm: Some("HS256".to_string()),
            proof_purpose: None,
            additional: HashMap::new(),
        };

        // Sign credential
        let jwt = service
            .sign_credential(&credential, &options)
            .await
            .unwrap();
        assert!(jwt.contains('.'));

        // Verify credential
        let verify_options = VerifyCredentialOptions::default();
        let result = service
            .verify_credential(&jwt, &verify_options)
            .await
            .unwrap();

        assert!(result.is_valid);
        assert_eq!(result.format, Some(CredentialFormat::JwtVc));
    }

    #[test]
    fn test_can_handle_jwt() {
        let service = JwtVcService::new();

        // Valid JWT format
        let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature";
        assert!(service.can_handle(jwt));

        // Invalid - not three parts
        assert!(!service.can_handle("not.jwt"));
        assert!(!service.can_handle("not-a-jwt"));

        // Invalid - not base64url
        assert!(!service.can_handle("not.a.jwt"));
    }
}
