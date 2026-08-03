//! Key attestation support for OID4VCI proofs.
//!
//! Per OpenID4VCI draft 15+, a wallet can prove that the binding key lives
//! in a tamper-resistant element by attaching a `key_attestation` to the
//! credential request's proof. The attestation is itself a JWT signed by
//! the attestor (typically the wallet vendor or a TPM/SE), and its body
//! lists the public keys backed by the secure element.
//!
//! This module models the attestation JWT shape and parses it for the
//! issuer. Actual JWS verification is left to the caller because attestor
//! key discovery is deployment-specific.

use serde::{Deserialize, Serialize};

/// Body of a wallet `key_attestation` JWT (selected fields). Many more
/// fields exist — we expose the ones an issuer typically inspects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestationClaims {
    /// Attestor identifier.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Issued-at, seconds since unix epoch.
    pub iat: u64,
    /// Expiration, seconds since unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Attested JWKs — public keys claimed to be hardware-backed.
    #[serde(default)]
    pub attested_keys: Vec<serde_json::Value>,
    /// `nonce` — optional anti-replay value bound to the credential request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Assurance level (`AAL1`/`AAL2`/`AAL3`). Free-form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<KeyStorage>,
    /// User-verification level used at attestation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<UserAuthentication>,
}

/// Suggested values: `software` / `hardware` / `tee` / `secure_element` / `strongbox`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    Software,
    Hardware,
    Tee,
    SecureElement,
    Strongbox,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAuthentication {
    SystemBiometry,
    SystemPin,
    InternalBiometry,
    InternalPin,
    SecureElement,
    #[serde(other)]
    Other,
}

/// Parse a key attestation JWT (signature unverified).
///
/// Returns the header (typ/alg) and the claims. The caller verifies the
/// signature against the attestor's discovered public key.
pub fn parse_key_attestation(
    jwt: &str,
) -> Result<(serde_json::Value, KeyAttestationClaims), String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("key attestation JWT must have exactly 3 segments".into());
    }
    let header_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
            .map_err(|e| format!("decode header: {}", e))?;
    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .map_err(|e| format!("decode payload: {}", e))?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("parse header: {}", e))?;
    let claims: KeyAttestationClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("parse claims: {}", e))?;
    Ok((header, claims))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(claims_json: &str) -> String {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"EdDSA","typ":"key-attestation+jwt"}"#,
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            claims_json.as_bytes(),
        );
        format!("{}.{}.sig", header, payload)
    }

    #[test]
    fn parse_minimal_attestation() {
        let jwt = make_jwt(
            r#"{
            "iss": "https://wallet.example.com/attestor",
            "iat": 1700000000,
            "attested_keys": [{"kty":"OKP","crv":"Ed25519","x":"AA"}],
            "key_storage": "secure_element",
            "user_authentication": "internal_biometry"
        }"#,
        );
        let (header, claims) = parse_key_attestation(&jwt).unwrap();
        assert_eq!(header.get("typ").unwrap(), "key-attestation+jwt");
        assert_eq!(claims.issuer, "https://wallet.example.com/attestor");
        assert_eq!(claims.attested_keys.len(), 1);
        assert!(matches!(
            claims.key_storage,
            Some(KeyStorage::SecureElement)
        ));
    }

    #[test]
    fn rejects_non_jwt() {
        let result = parse_key_attestation("not-a-jwt");
        assert!(result.is_err());
    }
}
