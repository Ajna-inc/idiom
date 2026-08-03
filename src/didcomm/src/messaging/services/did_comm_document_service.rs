//! DIDComm Document Service
//!
//! Provides DID document resolution and key/endpoint extraction for DIDComm operations.

use did::core::{DidDocument, DID};
use did::registry::DidRegistry;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidCommDocumentError {
    #[error("Failed to parse DID: {0}")]
    ParseError(String),

    #[error("Failed to resolve DID: {0}")]
    ResolutionError(String),

    #[error("DID document missing required field: {0}")]
    MissingField(String),

    #[error("Invalid endpoint format: {0}")]
    InvalidEndpoint(String),
}

pub type Result<T> = std::result::Result<T, DidCommDocumentError>;

/// Service for resolving DID documents and extracting DIDComm-related information
///
/// This service provides methods to:
/// - Resolve DID documents
/// - Extract authentication keys (Ed25519) for signing
/// - Extract key agreement keys (X25519) for encryption
/// - Extract service endpoints for message delivery
pub struct DidCommDocumentService {
    did_registry: Arc<DidRegistry>,
}

impl DidCommDocumentService {
    /// Create a new DidCommDocumentService
    pub fn new(did_registry: Arc<DidRegistry>) -> Self {
        Self { did_registry }
    }

    /// Resolve a DID to its DID document
    ///
    /// # Arguments
    /// * `did` - The DID string to resolve
    ///
    /// # Returns
    /// The resolved DID document
    pub async fn resolve_did_document(&self, did: &str) -> Result<DidDocument> {
        let did_parsed =
            DID::parse(did).map_err(|e| DidCommDocumentError::ParseError(format!("{}", e)))?;

        self.did_registry
            .resolve(&did_parsed)
            .await
            .map_err(|e| DidCommDocumentError::ResolutionError(format!("{}", e)))
    }

    /// Extract the service endpoint from a DID
    ///
    /// Resolves the DID document and extracts the first service endpoint.
    /// Used to determine where to send DIDComm messages.
    ///
    /// # Arguments
    /// * `did` - The DID string to extract endpoint from
    ///
    /// # Returns
    /// The service endpoint URL as a string
    pub async fn extract_service_endpoint(&self, did: &str) -> Result<String> {
        let did_doc = self.resolve_did_document(did).await?;

        let service = did_doc.service.first().ok_or_else(|| {
            DidCommDocumentError::MissingField("No services in DID document".to_string())
        })?;

        // Service endpoint can be either a string or an object
        // For DIDComm, we expect a string URL
        let endpoint = service.service_endpoint.as_str().ok_or_else(|| {
            DidCommDocumentError::InvalidEndpoint("Service endpoint is not a string".to_string())
        })?;

        Ok(endpoint.to_string())
    }

    /// Extract base58-encoded Ed25519 authentication key from a DID
    ///
    /// This extracts the Ed25519 SIGNING key (the first verification method).
    /// Used for:
    /// - Finding keys in the wallet (wallet stores Ed25519 keys)
    /// - Setting `kid` in JWE headers
    /// - DIDComm message signing
    ///
    /// # Arguments
    /// * `did` - The DID string to extract key from
    ///
    /// # Returns
    /// The Ed25519 public key in base58 encoding
    ///
    /// (see `vm_verkey_base58` free fn below for how keys are normalized)
    pub async fn extract_authentication_key(&self, did: &str) -> Result<String> {
        let did_doc = self.resolve_did_document(did).await?;

        // Get the first verification method (Ed25519 signing key)
        // For did:key, this is the Ed25519 key that's stored in the wallet
        let verification_method = did_doc.verification_method.first().ok_or_else(|| {
            DidCommDocumentError::MissingField(
                "No verification methods in DID document".to_string(),
            )
        })?;

        // Extract the Ed25519 public key in base58 format
        let public_key_base58 = vm_verkey_base58(verification_method).ok_or_else(|| {
            DidCommDocumentError::MissingField(
                "Verification method missing public key (base58 or multibase)".to_string(),
            )
        })?;

        Ok(public_key_base58)
    }

    /// Extract base58-encoded X25519 keyAgreement key from a DID
    ///
    /// For encryption, we need the X25519 keyAgreement key, NOT the Ed25519 signing key.
    /// This function:
    /// 1. Looks at the keyAgreement array in the DID document
    /// 2. Finds the referenced verification method
    /// 3. Extracts the X25519 public key
    ///
    /// **This is the correct key for ENCRYPTION!**
    ///
    /// # Arguments
    /// * `did` - The DID string to extract key from
    ///
    /// # Returns
    /// The X25519 public key in base58 encoding
    pub async fn extract_key_agreement_key(&self, did: &str) -> Result<String> {
        let did_doc = self.resolve_did_document(did).await?;

        // Get the keyAgreement reference (for encryption/ECDH, not signing!)
        // For did:key, this points to the X25519 verification method
        let key_agreement_ref = did_doc.key_agreement.first().ok_or_else(|| {
            DidCommDocumentError::MissingField(
                "No key agreement methods in DID document".to_string(),
            )
        })?;

        // Extract the key ID from the reference
        // VerificationRelationship can be a Reference (string ID) or Embedded (full VM)
        let key_id = match key_agreement_ref {
            did::core::document::VerificationRelationship::Reference(id) => id.clone(),
            did::core::document::VerificationRelationship::Embedded(vm) => vm.id.clone(),
        };

        // Find the corresponding verification method by ID
        let verification_method = did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id == key_id)
            .ok_or_else(|| {
                DidCommDocumentError::MissingField(format!(
                    "Key agreement method not found: {}",
                    key_id
                ))
            })?;

        // Extract the X25519 public key in base58 format
        let public_key_base58 = vm_verkey_base58(verification_method).ok_or_else(|| {
            DidCommDocumentError::MissingField(
                "Verification method missing public key (base58 or multibase)".to_string(),
            )
        })?;

        Ok(public_key_base58)
    }
}

/// Extract the raw base58 verkey from a verification method, accepting either
/// `publicKeyBase58` or a `publicKeyMultibase` (`z…` multibase, as used by
/// `Multikey` verification methods and did:peer:2 documents).
///
/// Aries DIDComm v1 packing and mediator keylists key off the raw base58
/// verkey, so a peer whose DID resolves to `publicKeyMultibase` (e.g. credo's
/// did:peer:2) must be normalized down to base58 — otherwise v1 packing to it
/// fails with "missing public_key_base58" and the connection stalls.
fn vm_verkey_base58(vm: &did::core::document::VerificationMethod) -> Option<String> {
    if let Some(b58) = vm.public_key_base58.as_ref() {
        return Some(b58.clone());
    }
    // `publicKeyMultibase` (Multikey) → raw base58 verkey via the canonical
    // converter.
    let mb = vm.public_key_multibase.as_ref()?;
    did::methods::key::multibase_to_base58_verkey(mb)
}

#[cfg(test)]
mod tests {

    // Tests would require a mock DidRegistry
    // TODO: Add tests with mock DID resolution
}
