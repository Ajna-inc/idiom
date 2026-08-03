//! Verification callbacks for customizing verification behavior

use crate::cose::CoseKey;
use crate::error::{MdocError, Result};
use crate::types::{DeviceResponse, Document};
use async_trait::async_trait;
use std::collections::HashMap;

/// Convert ciborium::Value to serde_json::Value for output
fn cbor_to_json_value(cbor: &ciborium::Value) -> serde_json::Value {
    match cbor {
        ciborium::Value::Integer(i) => {
            let i128_val = i128::from(*i);
            if let Ok(i64_val) = TryInto::<i64>::try_into(i128_val) {
                serde_json::Value::Number(i64_val.into())
            } else {
                serde_json::Value::Null
            }
        }
        ciborium::Value::Bytes(b) => {
            // Encode bytes as base64 string
            serde_json::Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b,
            ))
        }
        ciborium::Value::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(*f) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::Null
            }
        }
        ciborium::Value::Text(s) => serde_json::Value::String(s.clone()),
        ciborium::Value::Bool(b) => serde_json::Value::Bool(*b),
        ciborium::Value::Null => serde_json::Value::Null,
        ciborium::Value::Tag(_tag, value) => {
            // For tagged values, just convert the inner value
            // TODO: Handle specific tags like 1004 (DateOnly) specially
            cbor_to_json_value(value)
        }
        ciborium::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_to_json_value).collect())
        }
        ciborium::Value::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k {
                    obj.insert(key.clone(), cbor_to_json_value(v));
                }
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

/// Verification callback trait for customizing verification behavior
///
/// Implementations can customize:
/// - Certificate trust validation
/// - Age verification policies
/// - Custom business logic
/// - Audit logging
///
/// # Example
///
/// ```rust,ignore
/// struct MyVerifier {
///     trusted_roots: Vec<Vec<u8>>,
/// }
///
/// #[async_trait]
/// impl VerificationCallback for MyVerifier {
///     async fn verify_issuer_certificate(&self, chain: &[Vec<u8>]) -> Result<bool> {
///         // Custom certificate validation logic
///         Ok(true)
///     }
///
///     async fn on_verification_complete(&self, result: &VerificationResult) {
///         // Log verification result
///         println!("Verification completed: {:?}", result);
///     }
/// }
/// ```
#[async_trait]
pub trait VerificationCallback: Send + Sync {
    /// Verify the issuer's certificate chain
    ///
    /// Return true if the chain is trusted, false otherwise
    async fn verify_issuer_certificate(&self, certificate_chain: &[Vec<u8>]) -> Result<bool> {
        // Default: accept all certificates (override for production)
        let _ = certificate_chain;
        Ok(true)
    }

    /// Verify the device key is authorized
    ///
    /// Check if the device key is in an allowlist, not revoked, etc.
    async fn verify_device_key(&self, device_key: &CoseKey) -> Result<bool> {
        // Default: accept all device keys (override for production)
        let _ = device_key;
        Ok(true)
    }

    /// Check age verification requirements (for mDL)
    ///
    /// Return the minimum age requirement (e.g., 18, 21) or None
    async fn get_age_requirement(&self) -> Option<u32> {
        None
    }

    /// Verify a specific element value meets business logic requirements
    ///
    /// Called for each disclosed element
    async fn verify_element(
        &self,
        namespace: &str,
        element_id: &str,
        element_value: &serde_json::Value,
    ) -> Result<bool> {
        // Default: accept all elements
        let _ = (namespace, element_id, element_value);
        Ok(true)
    }

    /// Called when verification completes successfully
    ///
    /// Use for audit logging, metrics, etc.
    async fn on_verification_complete(&self, result: &VerificationResult) {
        let _ = result;
    }

    /// Called when verification fails
    ///
    /// Use for error logging, metrics, etc.
    async fn on_verification_failed(&self, error: &VerificationError) {
        let _ = error;
    }
}

/// Result of a verification operation
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The document type that was verified
    pub doc_type: String,

    /// Namespaces that were disclosed
    pub disclosed_namespaces: Vec<String>,

    /// Total number of elements disclosed
    pub disclosed_element_count: usize,

    /// Whether issuer authentication passed
    pub issuer_auth_valid: bool,

    /// Whether device authentication passed
    pub device_auth_valid: bool,

    /// Age over verification result (if applicable)
    pub age_over_verified: Option<bool>,

    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl VerificationResult {
    /// Create a new verification result
    pub fn new(doc_type: String) -> Self {
        Self {
            doc_type,
            disclosed_namespaces: Vec::new(),
            disclosed_element_count: 0,
            issuer_auth_valid: false,
            device_auth_valid: false,
            age_over_verified: None,
            metadata: HashMap::new(),
        }
    }

    /// Check if all verifications passed
    pub fn is_valid(&self) -> bool {
        self.issuer_auth_valid && self.device_auth_valid
    }

    /// Add custom metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Verification error details
#[derive(Debug, Clone)]
pub struct VerificationError {
    /// The underlying error
    pub error: String,

    /// The document type being verified
    pub doc_type: Option<String>,

    /// The verification stage where the error occurred
    pub stage: VerificationStage,

    /// Additional context
    pub context: HashMap<String, String>,
}

impl VerificationError {
    /// Create a new verification error
    pub fn new(error: impl Into<String>, stage: VerificationStage) -> Self {
        Self {
            error: error.into(),
            doc_type: None,
            stage,
            context: HashMap::new(),
        }
    }

    /// Add context information
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Set the document type
    pub fn with_doc_type(mut self, doc_type: String) -> Self {
        self.doc_type = Some(doc_type);
        self
    }
}

impl From<MdocError> for VerificationError {
    fn from(error: MdocError) -> Self {
        Self {
            error: error.to_string(),
            doc_type: None,
            stage: VerificationStage::Unknown,
            context: HashMap::new(),
        }
    }
}

/// Verification stage identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStage {
    /// Parsing device response
    Parsing,

    /// Verifying issuer authentication
    IssuerAuth,

    /// Verifying device authentication
    DeviceAuth,

    /// Verifying certificate chain
    CertificateChain,

    /// Verifying element digests
    ElementDigests,

    /// Verifying business logic
    BusinessLogic,

    /// Unknown stage
    Unknown,
}

impl std::fmt::Display for VerificationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parsing => write!(f, "Parsing"),
            Self::IssuerAuth => write!(f, "Issuer Authentication"),
            Self::DeviceAuth => write!(f, "Device Authentication"),
            Self::CertificateChain => write!(f, "Certificate Chain"),
            Self::ElementDigests => write!(f, "Element Digests"),
            Self::BusinessLogic => write!(f, "Business Logic"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Verified device response wrapper
///
/// Contains the device response along with verification metadata
#[derive(Debug, Clone)]
pub struct VerifiedDeviceResponse {
    /// The original device response
    pub response: DeviceResponse,

    /// Verification result
    pub verification: VerificationResult,

    /// Extracted claims by namespace
    pub claims: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl VerifiedDeviceResponse {
    /// Create a new verified device response
    pub fn new(response: DeviceResponse, verification: VerificationResult) -> Self {
        Self {
            response,
            verification,
            claims: HashMap::new(),
        }
    }

    /// Extract all claims from the verified response
    pub fn extract_claims(mut self) -> Result<Self> {
        // Clone documents to avoid borrow checker issues
        let documents = self.response.documents.clone();

        // Extract claims from each document
        for doc in documents.iter().flatten() {
            self.extract_claims_from_document(doc)?;
        }
        Ok(self)
    }

    /// Extract claims from a single document
    fn extract_claims_from_document(&mut self, document: &Document) -> Result<()> {
        for (namespace, items) in &document.issuer_signed.name_spaces {
            let namespace_claims = self.claims.entry(namespace.clone()).or_default();

            for item in items {
                namespace_claims.insert(
                    item.element_identifier.clone(),
                    cbor_to_json_value(&item.element_value),
                );
            }
        }
        Ok(())
    }

    /// Get a specific claim value
    pub fn get_claim(&self, namespace: &str, element_id: &str) -> Option<&serde_json::Value> {
        self.claims.get(namespace)?.get(element_id)
    }

    /// Get a claim as a string
    pub fn get_claim_string(&self, namespace: &str, element_id: &str) -> Option<String> {
        match self.get_claim(namespace, element_id)? {
            serde_json::Value::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// Get a claim as an integer
    pub fn get_claim_integer(&self, namespace: &str, element_id: &str) -> Option<i64> {
        self.get_claim(namespace, element_id)?.as_i64()
    }

    /// Get a claim as a boolean
    pub fn get_claim_bool(&self, namespace: &str, element_id: &str) -> Option<bool> {
        self.get_claim(namespace, element_id)?.as_bool()
    }

    /// Get all claims for a namespace
    pub fn get_namespace_claims(
        &self,
        namespace: &str,
    ) -> Option<&HashMap<String, serde_json::Value>> {
        self.claims.get(namespace)
    }

    /// Check if verification was successful
    pub fn is_valid(&self) -> bool {
        self.verification.is_valid()
    }
}

/// Default verification callback (accepts everything)
pub struct DefaultVerificationCallback;

#[async_trait]
impl VerificationCallback for DefaultVerificationCallback {
    // Uses all default implementations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_validity() {
        let mut result = VerificationResult::new("org.iso.18013.5.1.mDL".to_string());
        assert!(!result.is_valid());

        result.issuer_auth_valid = true;
        assert!(!result.is_valid());

        result.device_auth_valid = true;
        assert!(result.is_valid());
    }

    #[test]
    fn test_verification_error_builder() {
        let error = VerificationError::new("Test error", VerificationStage::IssuerAuth)
            .with_doc_type("org.iso.18013.5.1.mDL".to_string())
            .with_context("detail".to_string(), "More info".to_string());

        assert_eq!(error.error, "Test error");
        assert_eq!(error.doc_type, Some("org.iso.18013.5.1.mDL".to_string()));
        assert_eq!(error.stage, VerificationStage::IssuerAuth);
    }

    #[test]
    fn test_verification_stage_display() {
        assert_eq!(
            format!("{}", VerificationStage::IssuerAuth),
            "Issuer Authentication"
        );
        assert_eq!(
            format!("{}", VerificationStage::DeviceAuth),
            "Device Authentication"
        );
    }

    #[tokio::test]
    async fn test_default_callback() {
        let callback = DefaultVerificationCallback;

        assert!(callback.verify_issuer_certificate(&[]).await.unwrap());
        assert!(callback.verify_device_key(&CoseKey::new(2)).await.unwrap());
        assert!(callback.get_age_requirement().await.is_none());
    }
}
