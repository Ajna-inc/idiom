//! OID4VP types for authorization requests and responses

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authorization request from verifier (can be URI, JWT, or JSON object)
// The `Object` variant is naturally larger than the string variants; this type
// is constructed rarely (once per request), so the size gap is not worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum AuthorizationRequest {
    /// URI with embedded parameters: openid4vp://?client_id=...
    Uri(String),
    /// URI with request_uri parameter that must be fetched
    RequestUri { request_uri: String },
    /// Signed JWT (JAR - JWT-secured Authorization Request)
    Jwt(String),
    /// Direct JSON object
    Object(AuthorizationRequestPayload),
}

/// Parsed authorization request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequestPayload {
    /// Verifier's client identifier
    pub client_id: String,
    /// Where to send the response
    pub response_uri: String,
    /// Response mode (direct_post, direct_post.jwt, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    /// Nonce for replay protection
    pub nonce: String,
    /// State parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Presentation definition (DIF PEX)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<serde_json::Value>,
    /// DCQL query (DC API)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<super::dcql::DcqlQuery>,
    /// Client metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
}

/// Client metadata (verifier information)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_purpose: Option<String>,
}

/// Resolved authorization request (after parsing and validation)
#[derive(Debug, Clone)]
pub struct ResolvedAuthorizationRequest {
    /// Original payload
    pub payload: AuthorizationRequestPayload,
    /// Verifier information
    pub verifier: VerifierInfo,
    /// Matched credentials (if query present)
    pub matched_credentials: Option<Vec<MatchedCredential>>,
    /// Origin (for session transcript)
    pub origin: Option<String>,
}

/// Information about the verifier
#[derive(Debug, Clone)]
pub struct VerifierInfo {
    /// Client ID prefix type (x509_san_dns, redirect_uri, etc.)
    pub client_id_scheme: ClientIdScheme,
    /// Effective client ID after validation
    pub effective_client_id: String,
    /// Display name
    pub name: Option<String>,
}

/// Client ID scheme
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdScheme {
    /// X.509 SAN DNS
    X509SanDns,
    /// Redirect URI
    RedirectUri,
    /// Decentralized Identifier (DID)
    Did,
    /// Pre-registered client
    PreRegistered,
}

/// Matched credential from wallet
#[derive(Debug, Clone)]
pub struct MatchedCredential {
    /// Credential ID
    pub id: String,
    /// Document type
    pub doc_type: String,
    /// Available namespaces and claims
    pub available_claims: HashMap<String, Vec<String>>,
    /// Whether this credential matches the query
    pub matches: bool,
}

/// Authorization response to send back to verifier
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationResponse {
    /// VP token (base64url-encoded DeviceResponse)
    pub vp_token: String,
    /// Presentation submission (mapping of credentials to input descriptors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<PresentationSubmission>,
    /// State from authorization request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Presentation submission (DIF PEX)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMap {
    pub id: String,
    pub format: String,
    pub path: String,
}

/// Response from direct_post endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct DirectPostResponse {
    /// Optional redirect URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}
