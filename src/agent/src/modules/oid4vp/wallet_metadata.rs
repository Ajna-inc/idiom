//! Wallet metadata for OpenID4VP.
//!
//! Per OpenID4VP draft 24+, a verifier may need to discover the wallet's
//! capabilities — supported credential formats, supported client_id schemes,
//! signing algorithms, etc. This module exposes that metadata so the wallet
//! can:
//!
//! - serve it from a static `.well-known/openid-wallet` URL, or
//! - send it inline via the `wallet_metadata` query parameter when
//!   redirecting back to a verifier, or
//! - return it via FFI to the host app for embedding into a QR/deep-link.
//!
//! Follows the OpenID4VP "wallet metadata" data model.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level wallet metadata document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletMetadata {
    /// Map of credential format identifier → format-specific algorithm constraints.
    /// e.g. `"vc+sd-jwt"`, `"mso_mdoc"`, `"dc+sd-jwt"`, `"ac_vp"`.
    pub vp_formats_supported: HashMap<String, VpFormat>,

    /// `client_id` schemes the wallet will accept from a verifier
    /// (`x509_san_dns`, `redirect_uri`, `did`, `pre-registered`, `https`).
    pub client_id_schemes_supported: Vec<String>,

    /// Response modes the wallet supports as a wallet → verifier transport
    /// (`direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt`).
    pub response_modes_supported: Vec<String>,

    /// JWS signing algs the wallet accepts when verifying a JAR
    /// (Request-Object) coming from a verifier.
    pub request_object_signing_alg_values_supported: Vec<String>,

    /// Subject syntax types the wallet accepts in `client_id`
    /// (`did:web`, `did:key`, `urn:ietf:params:oauth:jwk-thumbprint`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subject_syntax_types_supported: Vec<String>,

    /// Authorization endpoint the wallet exposes (typically a deep link
    /// scheme like `openid4vp://`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,

    /// Human-readable wallet name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_name: Option<String>,

    /// Wallet logo (https URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

/// Per-format capability declaration. For JWT-based formats this is just a
/// list of signing algs; for ldp this is a list of proof types; for mdoc
/// this is a list of issuer-data alg names.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VpFormat {
    /// e.g. `["EdDSA","ES256","ES384"]`
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alg: Vec<String>,

    /// e.g. `["EdDSA","ES256"]` — algorithms used by the holder's binding key.
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        default,
        rename = "alg_values_supported"
    )]
    pub alg_values_supported: Vec<String>,

    /// JSON-LD proof types (only for ldp formats).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof_type: Vec<String>,
}

impl WalletMetadata {
    /// Default wallet metadata for the formats currently supported by this
    /// crate: SD-JWT-VC, mDoc, and AnonCreds-over-OID4VP.
    pub fn default_for_supported_formats() -> Self {
        let mut formats = HashMap::new();

        formats.insert(
            "vc+sd-jwt".to_string(),
            VpFormat {
                alg_values_supported: vec!["EdDSA".into(), "ES256".into(), "ES384".into()],
                ..Default::default()
            },
        );
        formats.insert(
            "dc+sd-jwt".to_string(),
            VpFormat {
                alg_values_supported: vec!["EdDSA".into(), "ES256".into(), "ES384".into()],
                ..Default::default()
            },
        );
        formats.insert(
            "mso_mdoc".to_string(),
            VpFormat {
                alg_values_supported: vec!["ES256".into(), "EdDSA".into()],
                ..Default::default()
            },
        );
        formats.insert(
            "ac_vp".to_string(),
            VpFormat {
                alg: vec!["CL".into()], // AnonCreds CL signatures
                ..Default::default()
            },
        );

        Self {
            vp_formats_supported: formats,
            client_id_schemes_supported: vec![
                "x509_san_dns".into(),
                "redirect_uri".into(),
                "did".into(),
                "pre-registered".into(),
                "https".into(),
            ],
            response_modes_supported: vec!["direct_post".into(), "direct_post.jwt".into()],
            request_object_signing_alg_values_supported: vec![
                "EdDSA".into(),
                "ES256".into(),
                "ES384".into(),
            ],
            subject_syntax_types_supported: vec![
                "did:key".into(),
                "did:jwk".into(),
                "did:web".into(),
                "urn:ietf:params:oauth:jwk-thumbprint".into(),
            ],
            authorization_endpoint: Some("openid4vp://".into()),
            wallet_name: Some("Ajna Wallet".into()),
            logo_uri: None,
        }
    }

    /// Override the wallet name (e.g., for white-label apps).
    pub fn with_wallet_name(mut self, name: impl Into<String>) -> Self {
        self.wallet_name = Some(name.into());
        self
    }

    /// Set the logo URI (must be https).
    pub fn with_logo_uri(mut self, uri: impl Into<String>) -> Self {
        self.logo_uri = Some(uri.into());
        self
    }

    /// Set a custom deep-link authorization endpoint.
    pub fn with_authorization_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.authorization_endpoint = Some(endpoint.into());
        self
    }

    /// Serialize to a JSON string suitable for hosting at a well-known URL or
    /// returning over FFI.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a metadata document received from a verifier asking the wallet
    /// to confirm capabilities. Currently we don't change behaviour based on
    /// the parsed value — but we expose the parser so callers can round-trip.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_required_formats() {
        let m = WalletMetadata::default_for_supported_formats();
        assert!(m.vp_formats_supported.contains_key("vc+sd-jwt"));
        assert!(m.vp_formats_supported.contains_key("mso_mdoc"));
        assert!(m.vp_formats_supported.contains_key("ac_vp"));
    }

    #[test]
    fn roundtrip_json() {
        let m = WalletMetadata::default_for_supported_formats().with_wallet_name("Test Wallet");
        let j = m.to_json().unwrap();
        let parsed = WalletMetadata::from_json(&j).unwrap();
        assert_eq!(parsed.wallet_name.as_deref(), Some("Test Wallet"));
        assert_eq!(
            parsed.vp_formats_supported.len(),
            m.vp_formats_supported.len()
        );
    }

    #[test]
    fn anoncreds_format_uses_cl() {
        let m = WalletMetadata::default_for_supported_formats();
        let ac = m.vp_formats_supported.get("ac_vp").unwrap();
        assert_eq!(ac.alg, vec!["CL".to_string()]);
    }
}
