//! OID4VCI protocol types.
//!
//! Based on OpenID for Verifiable Credential Issuance 1.0 with
//! AnonCreds Credential Format Profile extension.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Credential Offer
// =============================================================================

/// Credential Offer — received from QR code or deep link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    #[serde(default)]
    pub grants: CredentialOfferGrants,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialOfferGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    pub authorization_code: Option<AuthorizationCodeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub tx_code: Option<TxCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCode {
    pub input_mode: Option<String>,
    pub length: Option<u32>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

// =============================================================================
// Issuer Metadata
// =============================================================================

/// Issuer Metadata — from GET /.well-known/openid-credential-issuer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    #[serde(default)]
    pub nonce_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub authorization_server: Option<String>,
    #[serde(default)]
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
    #[serde(default)]
    pub display: Option<Vec<DisplayInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub credential_signing_alg_values_supported: Vec<String>,
    /// AnonCreds-specific metadata
    #[serde(default)]
    pub anoncreds: Option<AnonCredsMetadata>,
    #[serde(default)]
    pub display: Option<Vec<DisplayInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonCredsMetadata {
    pub schema: Option<AnonCredsSchemaInfo>,
    pub credential_definition: Option<AnonCredsCredDefInfo>,
    pub revocation: Option<AnonCredsRevocationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonCredsSchemaInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub attr_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonCredsCredDefInfo {
    pub id: String,
    pub schema_id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonCredsRevocationInfo {
    pub supported: bool,
    pub registry_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayInfo {
    pub name: String,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub logo: Option<LogoInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoInfo {
    pub uri: Option<String>,
    pub alt_text: Option<String>,
}

// =============================================================================
// Token Exchange
// =============================================================================

/// Token Response — from POST /token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub c_nonce: Option<String>,
    #[serde(default)]
    pub c_nonce_expires_in: Option<u64>,
}

/// Authorization Server Metadata — from GET /.well-known/oauth-authorization-server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
}

// =============================================================================
// Credential Request / Response
// =============================================================================

/// Credential Request — POST /credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

/// Credential Proof — proves holder binding.
/// For JWT: proof of key possession.
/// For AnonCreds: blinded link secret commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "proof_type")]
pub enum CredentialProof {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    #[serde(rename = "anoncreds")]
    AnonCreds {
        #[serde(skip_serializing_if = "Option::is_none")]
        prover_did: Option<String>,
        cred_def_id: String,
        blinded_ms: serde_json::Value,
        blinded_ms_correctness_proof: serde_json::Value,
        nonce: String,
    },
}

/// Credential Response — from POST /credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub format: String,
    pub credential: serde_json::Value,
    #[serde(default)]
    pub c_nonce: Option<String>,
    #[serde(default)]
    pub c_nonce_expires_in: Option<u64>,
}

// =============================================================================
// Resolved state
// =============================================================================

/// Resolved Credential Offer — after fetching metadata
#[derive(Debug, Clone)]
pub struct ResolvedCredentialOffer {
    pub offer: CredentialOffer,
    pub metadata: IssuerMetadata,
    pub token_endpoint: String,
    pub configurations: Vec<(String, CredentialConfiguration)>,
}

/// Issued Credential — result of successful issuance
#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub format: String,
    pub credential: serde_json::Value,
    pub credential_id: Option<String>,
}
