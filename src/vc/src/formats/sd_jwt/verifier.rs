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
    /// Refuse any Disclosure (possession-only profiles).
    pub forbid_disclosures: bool,
    /// Instant for `exp`/`nbf`/KB-JWT `iat` checks; `None` = wall clock.
    pub now: Option<i64>,
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
        let now = options.now.unwrap_or_else(|| Utc::now().timestamp());

        // 1. Verify JWT signature
        let jwt_valid = self.verify_jwt_signature(&sd_jwt_vc.jwt).await?;
        if !jwt_valid {
            errors.push("Invalid JWT signature".to_string());
            is_valid = false;
        }

        // 2. Parse and validate claims
        let claims = self.parse_jwt_claims(&sd_jwt_vc.jwt)?;

        // 2b. Refuse disclosures when the profile forbids them
        if options.forbid_disclosures && !sd_jwt_vc.disclosures.is_empty() {
            errors.push("Disclosures are not permitted by the verification profile".to_string());
            is_valid = false;
        }

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
            if exp < now {
                errors.push("SD-JWT has expired".to_string());
                is_valid = false;
            }
        }

        // 7. Verify not before
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > now {
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

        // Unsupported issuers and missing trust configuration are not a
        // successful verification result. Callers must construct the service
        // with a resolver that can authenticate the issuer's assertion key.
        Ok(false)
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
        let now = options.now.unwrap_or_else(|| Utc::now().timestamp());

        // RFC 9901 §4.3: typ MUST be kb+jwt; alg is bound to the cnf key type below
        let header = self.parse_jwt_header(kb_jwt)?;
        if header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
            return Ok(false);
        }
        let Some(alg) = header.get("alg").and_then(Value::as_str) else {
            return Ok(false);
        };

        let kb_claims = self.parse_jwt_claims(kb_jwt)?;

        // RFC 9901 §4.3 sd_hash over the presentation without the KB-JWT
        let Some(actual_hash) = kb_claims.get("sd_hash").and_then(Value::as_str) else {
            return Ok(false);
        };
        if self.hasher.hash_sd_jwt(sd_jwt) != actual_hash {
            return Ok(false);
        }

        if let Some(expected_nonce) = &options.expected_nonce {
            if kb_claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce.as_str()) {
                return Ok(false);
            }
        }
        if let Some(expected_aud) = &options.expected_audience {
            if kb_claims.get("aud").and_then(Value::as_str) != Some(expected_aud.as_str()) {
                return Ok(false);
            }
        }
        if let Some(max_age) = options.max_kb_age {
            let Some(iat) = kb_claims.get("iat").and_then(Value::as_i64) else {
                return Ok(false);
            };
            if now - iat > max_age {
                return Ok(false);
            }
        }

        // No cnf key means no verifiable key binding; there is no claims-only fallback
        let Some(cnf_jwk) = sd_jwt_claims.pointer("/cnf/jwk") else {
            return Ok(false);
        };
        Self::verify_kb_signature(kb_jwt, cnf_jwk, alg)
    }

    /// Parse the (unverified) header of a compact JWT.
    fn parse_jwt_header(&self, jwt: &str) -> Result<Value, SdJwtError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::InvalidFormat("Invalid JWT format".to_string()));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| SdJwtError::InvalidFormat(format!("Base64 decode error: {}", e)))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Verify the KB-JWT signature against the `cnf` JWK; `alg` must match the key type.
    fn verify_kb_signature(
        kb_jwt: &str,
        jwk: &Value,
        alg: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parts: Vec<&str> = kb_jwt.split('.').collect();
        if parts.len() != 3 {
            return Ok(false);
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let Ok(signature) = URL_SAFE_NO_PAD.decode(parts[2]) else {
            return Ok(false);
        };
        let field = |name: &str| -> Option<Vec<u8>> {
            jwk.get(name)
                .and_then(Value::as_str)
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
        };
        let kty = jwk.get("kty").and_then(Value::as_str);
        let crv = jwk.get("crv").and_then(Value::as_str);

        match (alg, kty, crv) {
            ("EdDSA", Some("OKP"), Some("Ed25519")) => {
                use ed25519_dalek::{Signature, VerifyingKey};
                let Some(x) = field("x") else {
                    return Ok(false);
                };
                let Ok(x) = <[u8; 32]>::try_from(x) else {
                    return Ok(false);
                };
                let Ok(key) = VerifyingKey::from_bytes(&x) else {
                    return Ok(false);
                };
                let Ok(sig) = Signature::from_slice(&signature) else {
                    return Ok(false);
                };
                Ok(key.verify_strict(signing_input.as_bytes(), &sig).is_ok())
            }
            ("ES256", Some("EC"), Some("P-256")) => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                use p256::elliptic_curve::generic_array::GenericArray;
                use p256::EncodedPoint;
                let (Some(x), Some(y)) = (field("x"), field("y")) else {
                    return Ok(false);
                };
                if x.len() != 32 || y.len() != 32 {
                    return Ok(false);
                }
                let point = EncodedPoint::from_affine_coordinates(
                    GenericArray::from_slice(&x),
                    GenericArray::from_slice(&y),
                    false,
                );
                let Ok(key) = VerifyingKey::from_encoded_point(&point) else {
                    return Ok(false);
                };
                let Ok(sig) = Signature::from_slice(&signature) else {
                    return Ok(false);
                };
                Ok(key.verify(signing_input.as_bytes(), &sig).is_ok())
            }
            _ => Ok(false),
        }
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

    pub fn forbid_disclosures(mut self) -> Self {
        self.options.forbid_disclosures = true;
        self
    }

    pub fn at_time(mut self, now_unix: i64) -> Self {
        self.options.now = Some(now_unix);
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

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;

    const SD_JWT_INPUT: &str = "issuer.jwt.sig~";

    fn verifier() -> SdJwtVerifier {
        SdJwtVerifier {
            hasher: SdJwtHasher::default(),
            did_verifier: None,
        }
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn jwt(header: &Value, payload: &Value, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
        let h = b64(&serde_json::to_vec(header).unwrap());
        let p = b64(&serde_json::to_vec(payload).unwrap());
        let input = format!("{h}.{p}");
        let sig = sign(input.as_bytes());
        format!("{input}.{}", b64(&sig))
    }

    fn ed25519() -> (ed25519_dalek::SigningKey, Value) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": b64(sk.verifying_key().as_bytes())});
        (sk, jwk)
    }

    fn p256() -> (p256::ecdsa::SigningKey, Value) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = json!({
            "kty": "EC", "crv": "P-256",
            "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap()),
        });
        (sk, jwk)
    }

    fn sign_ed(sk: &ed25519_dalek::SigningKey) -> impl FnOnce(&[u8]) -> Vec<u8> + '_ {
        move |m| {
            use ed25519_dalek::Signer;
            sk.sign(m).to_bytes().to_vec()
        }
    }

    fn sign_es(sk: &p256::ecdsa::SigningKey) -> impl FnOnce(&[u8]) -> Vec<u8> + '_ {
        move |m| {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = sk.sign(m);
            sig.to_bytes().to_vec()
        }
    }

    fn kb_header(alg: &str) -> Value {
        json!({"typ": "kb+jwt", "alg": alg})
    }

    fn kb_payload(iat: i64) -> Value {
        json!({
            "nonce": "n", "aud": "https://rp.example", "iat": iat,
            "sd_hash": SdJwtHasher::default().hash_sd_jwt(SD_JWT_INPUT),
        })
    }

    fn cnf(jwk: &Value) -> Value {
        json!({"cnf": {"jwk": jwk}})
    }

    fn options(now: i64) -> SdJwtVerificationOptions {
        VerificationOptionsBuilder::new()
            .with_audience("https://rp.example".to_string())
            .with_nonce("n".to_string())
            .require_key_binding()
            .at_time(now)
            .build()
    }

    async fn kb(
        kb_jwt: &str,
        issuer_claims: &Value,
        opts: &SdJwtVerificationOptions,
    ) -> Result<bool, String> {
        verifier()
            .verify_key_binding(kb_jwt, SD_JWT_INPUT, issuer_claims, opts)
            .await
            .map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn es256_key_binding_verifies_under_a_p256_cnf_key() {
        let (sk, jwk) = p256();
        let token = jwt(&kb_header("ES256"), &kb_payload(1_000), sign_es(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(true));
        let mut broken = token.clone();
        broken.replace_range(
            broken.len() - 1..,
            if broken.ends_with('A') { "B" } else { "A" },
        );
        assert_eq!(kb(&broken, &cnf(&jwk), &options(1_000)).await, Ok(false));
    }

    #[tokio::test]
    async fn eddsa_key_binding_still_verifies() {
        let (sk, jwk) = ed25519();
        let token = jwt(&kb_header("EdDSA"), &kb_payload(1_000), sign_ed(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(true));
    }

    #[tokio::test]
    async fn the_kb_jwt_alg_must_match_the_cnf_key_type() {
        let (sk, jwk) = ed25519();
        let token = jwt(&kb_header("ES256"), &kb_payload(1_000), sign_ed(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(false));
        let (sk, jwk) = p256();
        let token = jwt(&kb_header("EdDSA"), &kb_payload(1_000), sign_es(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(false));
    }

    #[tokio::test]
    async fn a_kb_jwt_without_typ_kb_jwt_is_refused() {
        let (sk, jwk) = ed25519();
        for header in [
            json!({"alg": "EdDSA"}),
            json!({"typ": "JWT", "alg": "EdDSA"}),
        ] {
            let token = jwt(&header, &kb_payload(1_000), sign_ed(&sk));
            assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(false));
        }
    }

    #[tokio::test]
    async fn the_hash_claim_is_sd_hash_per_rfc_9901() {
        let (sk, jwk) = ed25519();
        let token = jwt(&kb_header("EdDSA"), &kb_payload(1_000), sign_ed(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(true));
        let mut legacy = kb_payload(1_000);
        let hash = legacy.as_object_mut().unwrap().remove("sd_hash").unwrap();
        legacy["_sd_hash"] = hash;
        let token = jwt(&kb_header("EdDSA"), &legacy, sign_ed(&sk));
        assert_eq!(kb(&token, &cnf(&jwk), &options(1_000)).await, Ok(false));
    }

    #[tokio::test]
    async fn a_kb_jwt_is_never_accepted_without_a_cnf_key() {
        let (sk, _) = ed25519();
        let token = jwt(&kb_header("EdDSA"), &kb_payload(1_000), sign_ed(&sk));
        for issuer in [
            json!({}),
            json!({"cnf": {}}),
            json!({"cnf": {"kid": "did:key:z6Mk"}}),
        ] {
            assert_eq!(kb(&token, &issuer, &options(1_000)).await, Ok(false));
        }
    }

    #[tokio::test]
    async fn kb_jwt_age_is_measured_at_the_supplied_instant() {
        let (sk, jwk) = ed25519();
        let token = jwt(&kb_header("EdDSA"), &kb_payload(1_000), sign_ed(&sk));
        let aged = |max: i64| {
            VerificationOptionsBuilder::new()
                .with_audience("https://rp.example".to_string())
                .with_nonce("n".to_string())
                .require_key_binding()
                .with_max_kb_age(max)
                .at_time(1_400)
                .build()
        };
        assert_eq!(kb(&token, &cnf(&jwk), &aged(300)).await, Ok(false));
        assert_eq!(kb(&token, &cnf(&jwk), &aged(500)).await, Ok(true));
    }

    #[tokio::test]
    async fn disclosures_are_refused_when_the_profile_forbids_them() {
        let sd_jwt_vc = SdJwtVc {
            jwt: jwt(&json!({"alg": "EdDSA"}), &json!({"iss": "x"}), |_| {
                vec![0; 64]
            }),
            disclosures: vec![b64(b"[\"salt\",\"name\",\"value\"]")],
            key_binding_jwt: None,
        };
        let opts = VerificationOptionsBuilder::new()
            .forbid_disclosures()
            .at_time(1)
            .build();
        let result = verifier().verify(&sd_jwt_vc, &opts).await.unwrap();
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Disclosures are not permitted")));
    }

    #[test]
    fn from_compact_refuses_malformed_envelopes() {
        assert!(SdJwtVc::from_compact("a.b.c~~").is_err());
        assert!(SdJwtVc::from_compact("nodots~").is_err());
        assert!(SdJwtVc::from_compact("a.b.c").is_err());
        assert!(SdJwtVc::from_compact("a.b.c~").is_ok());
        assert!(SdJwtVc::from_compact("a.b.c~d1~").is_ok());
        let with_kb = SdJwtVc::from_compact("a.b.c~d1~k.b.j").unwrap();
        assert_eq!(with_kb.disclosures, vec!["d1".to_string()]);
        assert_eq!(with_kb.key_binding_jwt.as_deref(), Some("k.b.j"));
    }
}
