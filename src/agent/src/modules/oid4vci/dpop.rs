//! dPoP (Demonstrating Proof of Possession) support for OID4VCI.
//!
//! Per RFC 9449, a wallet can prove possession of a private key on each
//! HTTP request by sending a `DPoP: <jwt>` header. The JWT carries the
//! public key (as a JWK in its header) and signs over the HTTP method,
//! request URL, and a fresh nonce.
//!
//! This module provides type-safe builders / parsers for the JWT payload.
//! Actual signing is handed off to a `DPoPSigner` trait so callers can
//! plug their own JWT signing path (Askar, hardware-backed, etc.).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 9449 dPoP JWT body. The `htm` / `htu` claims pin the token to the
/// exact HTTP method + URL it was crafted for, `jti` makes it single-use,
/// `nonce` accepts an optional server-issued anti-replay value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPopClaims {
    /// JWT ID — uuid v4 string, single-use.
    pub jti: String,
    /// HTTP method, uppercase (`POST`, `GET`).
    pub htm: String,
    /// Target URI without query / fragment.
    pub htu: String,
    /// Issued-at (seconds since unix epoch).
    pub iat: u64,
    /// Optional server-issued anti-replay nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional `ath` — base64url-encoded SHA-256 hash of the access token.
    /// Used on the credential request to bind the dPoP to the bearer token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

impl DPopClaims {
    pub fn new(method: &str, uri: &str) -> Self {
        Self {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: strip_query_and_fragment(uri),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nonce: None,
            ath: None,
        }
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Bind the proof to an access token by including its SHA-256 digest.
    pub fn with_access_token_hash(mut self, access_token: &str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(access_token.as_bytes());
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest);
        self.ath = Some(encoded);
        self
    }
}

/// JWT header for a dPoP proof — `typ: dpop+jwt` and the public JWK embedded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPopHeader {
    pub alg: String,
    pub typ: String,
    pub jwk: serde_json::Value,
}

impl DPopHeader {
    pub fn new(alg: impl Into<String>, jwk: serde_json::Value) -> Self {
        Self {
            alg: alg.into(),
            typ: "dpop+jwt".to_string(),
            jwk,
        }
    }
}

/// Pluggable JWS signer — given a base64url(header) + "." + base64url(payload)
/// signing input, returns the base64url-encoded signature. Wallet implementations
/// plug this so the private key never leaves their wallet.
#[async_trait]
pub trait DPopSigner: Send + Sync {
    fn algorithm(&self) -> &str;
    fn public_jwk(&self) -> serde_json::Value;
    async fn sign(&self, signing_input: &[u8]) -> Result<String, String>;
}

/// Build a fully-serialised dPoP JWT ready to drop into the `DPoP` header.
pub async fn build_dpop_proof(
    signer: &dyn DPopSigner,
    claims: &DPopClaims,
) -> Result<String, String> {
    let header = DPopHeader::new(signer.algorithm(), signer.public_jwk());
    let header_json =
        serde_json::to_vec(&header).map_err(|e| format!("serialise header: {}", e))?;
    let payload_json =
        serde_json::to_vec(claims).map_err(|e| format!("serialise claims: {}", e))?;
    let header_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_json,
    );
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_json,
    );
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = signer.sign(signing_input.as_bytes()).await?;
    Ok(format!("{}.{}", signing_input, signature))
}

/// Parse a dPoP JWT into header + claims (signature unverified).
/// Use this on the issuer side to inspect the request before calling
/// `verify_dpop_signature` on the embedded JWK.
pub fn parse_dpop_proof(proof: &str) -> Result<(DPopHeader, DPopClaims), String> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err("dPoP JWT must have exactly 3 segments".into());
    }
    let header_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
            .map_err(|e| format!("decode header: {}", e))?;
    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .map_err(|e| format!("decode payload: {}", e))?;
    let header: DPopHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("parse header: {}", e))?;
    if header.typ != "dpop+jwt" {
        return Err(format!("dPoP typ mismatch: got `{}`", header.typ));
    }
    let claims: DPopClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("parse claims: {}", e))?;
    Ok((header, claims))
}

fn strip_query_and_fragment(uri: &str) -> String {
    let mut end = uri.len();
    if let Some(q) = uri.find('?') {
        end = end.min(q);
    }
    if let Some(f) = uri.find('#') {
        end = end.min(f);
    }
    uri[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSigner;

    #[async_trait]
    impl DPopSigner for FakeSigner {
        fn algorithm(&self) -> &str {
            "EdDSA"
        }
        fn public_jwk(&self) -> serde_json::Value {
            serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"})
        }
        async fn sign(&self, _signing_input: &[u8]) -> Result<String, String> {
            Ok("FAKE_SIGNATURE".to_string())
        }
    }

    #[tokio::test]
    async fn build_and_parse_roundtrip() {
        let signer = FakeSigner;
        let claims = DPopClaims::new("POST", "https://issuer.example.com/credential")
            .with_nonce("server-nonce")
            .with_access_token_hash("test-token");
        let jwt = build_dpop_proof(&signer, &claims).await.unwrap();
        assert_eq!(jwt.matches('.').count(), 2);
        let (header, parsed_claims) = parse_dpop_proof(&jwt).unwrap();
        assert_eq!(header.typ, "dpop+jwt");
        assert_eq!(parsed_claims.htm, "POST");
        assert_eq!(parsed_claims.htu, "https://issuer.example.com/credential");
        assert_eq!(parsed_claims.nonce.as_deref(), Some("server-nonce"));
        assert!(parsed_claims.ath.is_some());
    }

    #[test]
    fn strip_query_and_fragment_works() {
        assert_eq!(
            strip_query_and_fragment("https://example.com/foo?x=1#bar"),
            "https://example.com/foo"
        );
        assert_eq!(
            strip_query_and_fragment("https://example.com/foo"),
            "https://example.com/foo"
        );
    }

    #[test]
    fn parse_rejects_non_dpop_jwt() {
        let header_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"jwk\":{}}",
        );
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"jti":"x","htm":"POST","htu":"https://e","iat":0}"#,
        );
        let bad = format!("{}.{}.fake", header_b64, payload_b64);
        let err = parse_dpop_proof(&bad).unwrap_err();
        assert!(err.contains("typ mismatch"));
    }
}
