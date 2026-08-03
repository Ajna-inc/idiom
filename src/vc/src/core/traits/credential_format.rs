use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::models::{W3cCredential, W3cPresentation, W3cV2Credential};

/// Supported credential formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialFormat {
    /// JWT Verifiable Credential
    JwtVc,
    /// JSON-LD with Data Integrity Proof
    JsonLd,
    /// Selective Disclosure JWT
    SdJwt,
    /// Mobile Document (ISO 18013-5)
    Mdoc,
    /// AnonCreds (Hyperledger AnonCreds)
    AnonCreds,
}

/// Options for signing a credential
#[derive(Debug, Clone)]
pub struct SignCredentialOptions {
    /// Format to sign the credential in
    pub format: CredentialFormat,
    /// Key ID or DID URL for signing
    pub key_id: String,
    /// Algorithm to use (format-specific)
    pub algorithm: Option<String>,
    /// Proof purpose (for JSON-LD)
    pub proof_purpose: Option<String>,
    /// Additional format-specific options
    pub additional: HashMap<String, serde_json::Value>,
}

/// Options for verifying a credential
#[derive(Debug, Clone, Default)]
pub struct VerifyCredentialOptions {
    /// Expected issuer (optional)
    pub expected_issuer: Option<String>,
    /// Expected subject (optional)
    pub expected_subject: Option<String>,
    /// Check revocation status
    pub check_status: bool,
    /// Additional format-specific options
    pub additional: HashMap<String, serde_json::Value>,
}

/// Result of credential verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the credential is valid
    pub is_valid: bool,
    /// The credential format detected
    pub format: Option<CredentialFormat>,
    /// The parsed credential (if valid)
    pub credential: Option<CredentialData>,
    /// Any errors or warnings
    pub errors: Vec<String>,
    /// Additional verification details
    pub details: HashMap<String, serde_json::Value>,
}

/// Unified credential data from any format
#[derive(Debug, Clone)]
pub enum CredentialData {
    V1(W3cCredential),
    V2(W3cV2Credential),
}

impl VerificationResult {
    /// Create a valid verification result
    pub fn valid(credential: CredentialData, format: CredentialFormat) -> Self {
        Self {
            is_valid: true,
            format: Some(format),
            credential: Some(credential),
            errors: Vec::new(),
            details: HashMap::new(),
        }
    }

    /// Create an invalid verification result
    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            is_valid: false,
            format: None,
            credential: None,
            errors: vec![error.into()],
            details: HashMap::new(),
        }
    }

    /// Add an error message
    pub fn add_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self.is_valid = false;
        self
    }

    /// Add a detail
    pub fn add_detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }
}

/// Trait for credential format services (JWT-VC, JSON-LD, SD-JWT, mDoc)
#[async_trait]
pub trait CredentialFormatService: Send + Sync {
    /// Get the format this service handles
    fn format(&self) -> CredentialFormat;

    /// Sign a credential in this format
    async fn sign_credential(
        &self,
        credential: &W3cCredential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Sign a v2 credential in this format
    async fn sign_credential_v2(
        &self,
        credential: &W3cV2Credential,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Default implementation converts to v1 - formats can override
        let v1 = self.convert_v2_to_v1(credential)?;
        self.sign_credential(&v1, options).await
    }

    /// Verify a credential in this format
    async fn verify_credential(
        &self,
        credential: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>>;

    /// Sign a presentation in this format
    async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Verify a presentation in this format
    async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>>;

    /// Check if this service can handle the given credential string
    fn can_handle(&self, credential: &str) -> bool;

    /// Helper to convert v2 to v1 credential (for formats that don't support v2)
    fn convert_v2_to_v1(
        &self,
        v2: &W3cV2Credential,
    ) -> Result<W3cCredential, Box<dyn std::error::Error + Send + Sync>> {
        Ok(W3cCredential {
            context: v2.context.clone(),
            id: v2.id.clone(),
            type_: v2.type_.clone(),
            issuer: v2.issuer.clone(),
            issuance_date: v2.valid_from,
            expiration_date: v2.valid_until,
            credential_subject: v2.credential_subject.clone(),
            credential_status: v2.credential_status.clone(),
            credential_schema: v2.credential_schema.clone(),
            refresh_service: None,
            proof: v2.proof.clone(),
        })
    }
}

/// Options for creating presentations
#[derive(Debug, Clone)]
pub struct CreatePresentationOptions {
    /// Holder DID or identifier
    pub holder: Option<String>,
    /// Challenge for the proof
    pub challenge: Option<String>,
    /// Domain for the proof
    pub domain: Option<String>,
    /// Presentation submission (for DIF Presentation Exchange)
    pub presentation_submission: Option<crate::core::models::PresentationSubmission>,
}

/// Service for creating and verifying presentations
#[async_trait]
pub trait PresentationService: Send + Sync {
    /// Create a presentation from credentials
    async fn create_presentation(
        &self,
        credentials: Vec<String>,
        options: &CreatePresentationOptions,
    ) -> Result<W3cPresentation, Box<dyn std::error::Error + Send + Sync>>;

    /// Sign a presentation
    async fn sign_presentation(
        &self,
        presentation: &W3cPresentation,
        options: &SignCredentialOptions,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Verify a presentation
    async fn verify_presentation(
        &self,
        presentation: &str,
        options: &VerifyCredentialOptions,
    ) -> Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>>;
}
