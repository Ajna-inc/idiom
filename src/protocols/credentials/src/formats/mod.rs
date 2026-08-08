//! DIDComm credential-format abstraction.
//!
//! The DIDComm issue-credential protocol negotiates a *format* per attachment
//! (`aries/ld-proof-vc-detail@v1.0`, `aries/jwt-vc-detail@v1.0`,
//! `vc+sd-jwt-detail@v1.0`, …). This module maps those wire ids onto the
//! [`vc::core::CredentialFormat`] enum and the concrete
//! [`vc::core::CredentialFormatService`] instances that sign / verify the
//! credential, so the protocol crate stays decoupled from any specific format
//! implementation and from the `agent` crate — the services are injected.
//!
//! AnonCreds is deliberately *not* modelled here: it uses CL signatures (not the
//! `CredentialFormatService` sign/verify contract) and keeps its own
//! [`crate::services::CredentialExchangeService`] path, feature-gated behind
//! `anoncreds`.

use crate::messages::formats;
use vc::core::CredentialFormat;

/// The W3C / JOSE credential formats the DIDComm protocol can issue via an
/// injected [`vc::core::CredentialFormatService`].
///
/// This is a thin, DIDComm-facing view over [`vc::core::CredentialFormat`] that
/// carries the two wire ids each format needs (the negotiation *detail* id and
/// the issued *credential* id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DidCommCredentialFormat {
    /// JSON-LD Data Integrity (LD-proof) VC — RFC 0593.
    JsonLd,
    /// JWT-VC (W3C VC-JOSE).
    JwtVc,
    /// SD-JWT VC (IETF selective disclosure).
    SdJwt,
}

impl DidCommCredentialFormat {
    /// The underlying [`vc::core::CredentialFormat`] used to look up the signing
    /// / verifying [`vc::core::CredentialFormatService`].
    pub fn vc_format(self) -> CredentialFormat {
        match self {
            DidCommCredentialFormat::JsonLd => CredentialFormat::JsonLd,
            DidCommCredentialFormat::JwtVc => CredentialFormat::JwtVc,
            DidCommCredentialFormat::SdJwt => CredentialFormat::SdJwt,
        }
    }

    /// Attachment format id for propose / offer / request messages (the
    /// `{credential, options}` detail).
    pub fn detail_format_id(self) -> &'static str {
        match self {
            DidCommCredentialFormat::JsonLd => formats::JSONLD_LD_PROOF_VC_DETAIL,
            DidCommCredentialFormat::JwtVc => formats::JWT_VC_DETAIL,
            DidCommCredentialFormat::SdJwt => formats::SD_JWT_VC_DETAIL,
        }
    }

    /// Attachment format id for the issue-credential message (the signed
    /// credential string).
    pub fn credential_format_id(self) -> &'static str {
        match self {
            DidCommCredentialFormat::JsonLd => formats::JSONLD_LD_PROOF_VC,
            DidCommCredentialFormat::JwtVc => formats::JWT_VC,
            DidCommCredentialFormat::SdJwt => formats::SD_JWT_VC,
        }
    }

    /// Default signature algorithm token for this format (mirrors the
    /// `agent` crate's `CredentialsModule::issue_credential`).
    pub fn default_algorithm(self) -> Option<&'static str> {
        match self {
            DidCommCredentialFormat::JsonLd => Some("Ed25519Signature2020"),
            DidCommCredentialFormat::JwtVc => Some("EdDSA"),
            DidCommCredentialFormat::SdJwt => None,
        }
    }

    /// Classify a DIDComm attachment format id. Recognises both the `-detail`
    /// (offer/request) and the issued-credential ids of each family. Returns
    /// `None` for AnonCreds / unknown ids.
    pub fn from_format_id(format_id: &str) -> Option<Self> {
        if format_id.contains("ld-proof-vc") {
            Some(DidCommCredentialFormat::JsonLd)
        } else if format_id.contains("jwt-vc") {
            Some(DidCommCredentialFormat::JwtVc)
        } else if format_id.contains("sd-jwt") {
            Some(DidCommCredentialFormat::SdJwt)
        } else {
            None
        }
    }
}

/// The `{credential, options}` payload carried in an `*-ld-proof-vc-detail` /
/// `*-detail` attachment (RFC 0593 credential *detail*).
///
/// * `credential` — the unsigned credential the issuer will sign. For JSON-LD
///   and JWT-VC this is a W3C VC JSON object; for SD-JWT VC it is the claim set.
/// * `options` — format-specific proof options (`proofType`,
///   `verificationMethod`, `credentialStatus`, …). Optional / free-form.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialDetail {
    pub credential: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

impl CredentialDetail {
    /// Build a detail from an unsigned credential value and optional proof
    /// options.
    pub fn new(credential: serde_json::Value, options: Option<serde_json::Value>) -> Self {
        Self {
            credential,
            options,
        }
    }

    /// Parse a detail from a JSON string. Tolerates a bare credential object
    /// (no `credential`/`options` envelope) by wrapping it.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_str(s)?;
        if value.get("credential").is_some() {
            serde_json::from_value(value)
        } else {
            Ok(CredentialDetail::new(value, None))
        }
    }

    /// Read `options.verificationMethod`, if present.
    pub fn verification_method(&self) -> Option<String> {
        self.options
            .as_ref()
            .and_then(|o| o.get("verificationMethod"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Read `options.proofType`, if present.
    pub fn proof_type(&self) -> Option<String> {
        self.options
            .as_ref()
            .and_then(|o| o.get("proofType"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_id_roundtrip() {
        for f in [
            DidCommCredentialFormat::JsonLd,
            DidCommCredentialFormat::JwtVc,
            DidCommCredentialFormat::SdJwt,
        ] {
            assert_eq!(
                DidCommCredentialFormat::from_format_id(f.detail_format_id()),
                Some(f)
            );
            assert_eq!(
                DidCommCredentialFormat::from_format_id(f.credential_format_id()),
                Some(f)
            );
        }
        assert_eq!(
            DidCommCredentialFormat::from_format_id(formats::ANONCREDS_CREDENTIAL_OFFER),
            None
        );
    }

    #[test]
    fn detail_wraps_bare_credential() {
        let d = CredentialDetail::from_json(r#"{"type":["VerifiableCredential"]}"#).unwrap();
        assert!(d.options.is_none());
        assert!(d.credential.get("type").is_some());

        let d2 =
            CredentialDetail::from_json(r#"{"credential":{"a":1},"options":{"proofType":"x"}}"#)
                .unwrap();
        assert_eq!(d2.proof_type().as_deref(), Some("x"));
    }
}
