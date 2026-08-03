use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{
    CredentialData, CredentialFormat, CredentialFormatService, SignCredentialOptions,
    SignatureAlgorithm, VerificationResult, VerifyCredentialOptions, W3cCredential,
    W3cPresentation, W3cV2Credential,
};
use agent_core::traits::WalletProvider;

use super::transformer::{JwtVcPayload, JwtVcTransformer, JwtVpPayload, OneOrMany};
use super::wallet_signer::WalletBackedJwtVcService;

/// Enhanced JWT-VC service that can work with or without a wallet
pub struct EnhancedJwtVcService {
    /// Wallet-backed service (if wallet is available)
    wallet_service: Option<WalletBackedJwtVcService>,
}

impl EnhancedJwtVcService {
    /// Create a new service without a wallet (uses dummy keys for testing)
    pub fn new() -> Self {
        Self {
            wallet_service: None,
        }
    }

    /// Create a new service with a wallet for real cryptographic operations
    pub fn with_wallet(wallet: Arc<dyn WalletProvider>) -> Self {
        let wallet_service = WalletBackedJwtVcService::new(wallet.clone());
        Self {
            wallet_service: Some(wallet_service),
        }
    }

    /// Parse algorithm from string
    fn parse_algorithm(&self, alg: Option<&String>) -> SignatureAlgorithm {
        match alg.map(|s| s.as_str()) {
            Some("EdDSA") => SignatureAlgorithm::EdDSA,
            Some("ES256") => SignatureAlgorithm::ES256,
            Some("ES384") => SignatureAlgorithm::ES384,
            Some("ES512") => SignatureAlgorithm::ES512,
            Some("RS256") => SignatureAlgorithm::RS256,
            Some("RS384") => SignatureAlgorithm::RS384,
            Some("RS512") => SignatureAlgorithm::RS512,
            Some("PS256") => SignatureAlgorithm::PS256,
            Some("PS384") => SignatureAlgorithm::PS384,
            Some("PS512") => SignatureAlgorithm::PS512,
            _ => SignatureAlgorithm::EdDSA, // Default
        }
    }

    /// Sign JWT using wallet if available, otherwise use fallback
    async fn sign_jwt_internal(
        &self,
        header: &Value,
        payload: &Value,
        key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(wallet_service) = &self.wallet_service {
            // Use wallet for real signing
            wallet_service
                .sign_jwt(header, payload, key_id, algorithm)
                .await
        } else {
            // Fallback service (deterministic dummy key, for tests / no-wallet).
            //
            // The previous implementation used `EncodingKey::from_secret` — an
            // HMAC key — with an *asymmetric* algorithm (EdDSA/ES256/…). All
            // `SignatureAlgorithm` variants are asymmetric, so jsonwebtoken
            // always rejected that combination with `InvalidAlgorithm`, making
            // the fallback path unusable. We instead sign with a real,
            // deterministic Ed25519 key so the fallback genuinely round-trips.
            //
            // Only EdDSA is supported by the keyless fallback (the default and
            // what the no-wallet path uses); other algorithms require real key
            // material and must go through the wallet-backed service.
            if algorithm != SignatureAlgorithm::EdDSA {
                return Err(format!(
                    "Keyless fallback only supports EdDSA; {:?} requires a wallet-backed key",
                    algorithm
                )
                .into());
            }

            use ed25519_dalek::pkcs8::EncodePrivateKey;
            let signing_key = Self::fallback_ed25519_key();
            let pkcs8 = signing_key
                .to_pkcs8_der()
                .map_err(|e| format!("Failed to encode fallback Ed25519 key: {e}"))?;
            let key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8.as_bytes());

            let mut jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
            jwt_header.kid = Some(key_id.to_string());
            jwt_header.typ = Some("JWT".to_string());

            let token = jsonwebtoken::encode(&jwt_header, payload, &key)?;
            Ok(token)
        }
    }

    /// Deterministic Ed25519 key used by the keyless fallback so that
    /// `sign_jwt_internal` and `verify_jwt_internal` share the same key pair.
    /// This is NOT for production signing — real signing goes through the wallet.
    fn fallback_ed25519_key() -> ed25519_dalek::SigningKey {
        // Fixed seed → deterministic keypair shared between sign and verify.
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Verify JWT using wallet if available, otherwise use fallback
    async fn verify_jwt_internal(
        &self,
        jwt: &str,
    ) -> Result<(Value, Value), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(wallet_service) = &self.wallet_service {
            // Use wallet for verification
            wallet_service.verify_jwt(jwt).await
        } else {
            // Keyless fallback verification using the same deterministic Ed25519
            // key pair as `sign_jwt_internal`. Uses the raw 32-byte public key.
            let header = jsonwebtoken::decode_header(jwt)?;
            let verifying_key = Self::fallback_ed25519_key().verifying_key();
            let key = jsonwebtoken::DecodingKey::from_ed_der(verifying_key.as_bytes());

            let mut validation = jsonwebtoken::Validation::new(header.alg);
            validation.validate_exp = false;
            validation.validate_nbf = false;
            validation.validate_aud = false;
            // `Validation::new` defaults `required_spec_claims` to {"exp"}; VCs
            // without an expiry legitimately omit `exp`, so clear the set.
            validation.required_spec_claims.clear();

            let token_data = jsonwebtoken::decode::<Value>(jwt, &key, &validation)?;

            let header_value = serde_json::to_value(&header)?;
            Ok((header_value, token_data.claims))
        }
    }
}

#[async_trait]
impl CredentialFormatService for EnhancedJwtVcService {
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

        // Convert payload to JSON value
        let payload_value = serde_json::to_value(payload)?;

        // Create header
        let header = json!({
            "alg": match algorithm {
                SignatureAlgorithm::EdDSA => "EdDSA",
                SignatureAlgorithm::ES256 => "ES256",
                SignatureAlgorithm::ES384 => "ES384",
                SignatureAlgorithm::ES512 => "ES512",
                SignatureAlgorithm::RS256 => "RS256",
                SignatureAlgorithm::RS384 => "RS384",
                SignatureAlgorithm::RS512 => "RS512",
                SignatureAlgorithm::PS256 => "PS256",
                SignatureAlgorithm::PS384 => "PS384",
                SignatureAlgorithm::PS512 => "PS512",
            },
            "typ": "JWT",
            "kid": options.key_id
        });

        // Sign JWT
        self.sign_jwt_internal(&header, &payload_value, &options.key_id, algorithm)
            .await
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
        let (header, payload_value) = match self.verify_jwt_internal(credential).await {
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
        if let Some(alg) = header.get("alg") {
            result = result.add_detail("algorithm", alg.clone());
        }
        if let Some(kid) = header.get("kid") {
            result = result.add_detail("kid", kid.clone());
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

        // Convert payload to JSON value
        let payload_value = serde_json::to_value(payload)?;

        // Create header
        let header = json!({
            "alg": match algorithm {
                SignatureAlgorithm::EdDSA => "EdDSA",
                SignatureAlgorithm::ES256 => "ES256",
                _ => "EdDSA", // Default
            },
            "typ": "JWT",
            "kid": options.key_id
        });

        // Sign JWT
        self.sign_jwt_internal(&header, &payload_value, &options.key_id, algorithm)
            .await
    }

    async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Verify JWT signature and get payload
        let (header, payload_value) = match self.verify_jwt_internal(presentation).await {
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

        // Check nonce if expected. A non-string expected nonce is caller misuse
        // and must not silently degrade to an empty match — reject it.
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
            credential: None,
            errors: Vec::new(),
            details: HashMap::new(),
        };

        if let Some(alg) = header.get("alg") {
            result = result.add_detail("algorithm", alg.clone());
        }
        if let Some(kid) = header.get("kid") {
            result = result.add_detail("kid", kid.clone());
        }

        Ok(result)
    }

    fn can_handle(&self, credential: &str) -> bool {
        // Check if it's a JWT format
        let parts: Vec<&str> = credential.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Try to decode header
        if let Ok(header_json) = URL_SAFE_NO_PAD.decode(parts[0]) {
            if let Ok(header_value) = serde_json::from_slice::<Value>(&header_json) {
                if let Some(typ) = header_value.get("typ") {
                    return typ == "JWT";
                }
                return header_value.get("alg").is_some();
            }
        }

        false
    }
}

impl Default for EnhancedJwtVcService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::CredentialSubjectObject;

    #[tokio::test]
    async fn test_enhanced_service_without_wallet() {
        let service = EnhancedJwtVcService::new();

        let subject = CredentialSubjectObject {
            id: Some("did:example:subject".to_string()),
            claims: HashMap::new(),
        };

        let credential = W3cCredential::new("did:example:issuer", subject)
            .with_id("http://example.com/credentials/123");

        let options = SignCredentialOptions {
            format: CredentialFormat::JwtVc,
            key_id: "did:example:issuer#key-1".to_string(),
            algorithm: Some("EdDSA".to_string()),
            proof_purpose: None,
            additional: HashMap::new(),
        };

        // Should work with fallback service
        let jwt = service
            .sign_credential(&credential, &options)
            .await
            .unwrap();
        assert!(jwt.contains('.'));

        // Verify
        let result = service
            .verify_credential(&jwt, &VerifyCredentialOptions::default())
            .await
            .unwrap();
        assert!(result.is_valid);
    }
}
