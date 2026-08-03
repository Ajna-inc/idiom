//! mDoc service for issuance and verification

use chrono::{Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;

use crate::core::VerificationResult;
use agent_core::traits::WalletProvider;

use super::disclosure::{DisclosureProcessor, DocRequest};
use super::encoder::MdocEncoder;
use super::issuer_auth::IssuerAuth;
use super::types::*;

/// Error types for mDoc service
#[derive(Debug, thiserror::Error)]
pub enum MdocServiceError {
    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Issuer auth error: {0}")]
    IssuerAuth(String),

    #[error("Device auth error: {0}")]
    DeviceAuth(String),

    #[error("Disclosure error: {0}")]
    Disclosure(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// mDoc service for credential operations
pub struct MdocService {
    issuer_auth: IssuerAuth,
}

impl MdocService {
    /// Create new mDoc service
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let issuer_auth = IssuerAuth::new(wallet.clone());

        Self { issuer_auth }
    }

    /// Issue an mDoc credential
    pub async fn issue_mdoc(
        &self,
        doc_type: String,
        data_elements: HashMap<String, HashMap<String, serde_json::Value>>,
        issuer_key_id: &str,
        device_public_key: Vec<u8>,
        validity_days: i64,
    ) -> Result<MDoc, MdocServiceError> {
        // Create mDoc structure
        let mut mdoc = MDoc::new(doc_type.clone());

        // Create Mobile Security Object
        let device_key_info = DeviceKeyInfo {
            device_key: device_public_key,
            key_authorizations: None,
            key_info: None,
        };

        let valid_from = Utc::now();
        let valid_until = valid_from + Duration::days(validity_days);

        let mut mso =
            MobileSecurityObject::new(doc_type.clone(), device_key_info, valid_from, valid_until);

        // Process each namespace
        for (namespace, elements) in data_elements {
            for (digest_id, (element_id, element_value)) in elements.into_iter().enumerate() {
                let digest_id = digest_id as u32;

                // Generate random salt
                let random = Self::generate_random_salt();

                // Create issuer signed item
                let item = IssuerSignedItem {
                    digest_id,
                    random: random.clone(),
                    element_identifier: element_id.clone(),
                    element_value: element_value.clone(),
                };

                // Calculate digest
                let item_bytes = self.encode_issuer_signed_item(&item)?;
                let digest = IssuerAuth::hash_data_element(&item_bytes);

                // Add to MSO value digests
                mso.add_digest(namespace.clone(), digest_id, digest);

                // Add to mDoc
                mdoc.add_issuer_signed_element(namespace.clone(), item);
            }
        }

        // Sign MSO with issuer key (create issuer auth)
        let issuer_auth_bytes = self
            .issuer_auth
            .sign_mso(&mso, issuer_key_id)
            .await
            .map_err(|e| MdocServiceError::IssuerAuth(e.to_string()))?;

        mdoc.issuer_signed.issuer_auth = issuer_auth_bytes;

        Ok(mdoc)
    }

    /// Verify an mDoc credential
    pub async fn verify_mdoc(&self, mdoc: &MDoc) -> Result<VerificationResult, MdocServiceError> {
        // Check status
        if !mdoc.is_valid() {
            return Ok(VerificationResult::invalid("mDoc status indicates invalid"));
        }

        // Verify issuer authentication (extract and verify MSO)
        let mso = self
            .issuer_auth
            .verify_issuer_auth(&mdoc.issuer_signed.issuer_auth, &mdoc.doc_type)
            .await
            .map_err(|e| MdocServiceError::IssuerAuth(e.to_string()))?;

        // Verify MSO is currently valid
        if !mso.is_currently_valid() {
            return Ok(VerificationResult::invalid("MSO expired or not yet valid"));
        }

        // Verify digests for all issuer-signed items
        for (namespace, items) in &mdoc.issuer_signed.name_spaces {
            for item in items {
                // Get expected digest from MSO
                let expected_digest = mso
                    .value_digests
                    .get(namespace)
                    .and_then(|ns_digests| ns_digests.get(&item.digest_id))
                    .ok_or_else(|| {
                        MdocServiceError::Validation(format!(
                            "Missing digest for {}:{}",
                            namespace, item.digest_id
                        ))
                    })?;

                // Calculate actual digest
                let item_bytes = self.encode_issuer_signed_item(item)?;
                let actual_digest = IssuerAuth::hash_data_element(&item_bytes);

                // Compare
                if expected_digest != &actual_digest {
                    return Ok(VerificationResult::invalid(format!(
                        "Digest mismatch for {}:{}",
                        namespace, item.element_identifier
                    )));
                }
            }
        }

        // All checks passed
        Ok(VerificationResult {
            is_valid: true,
            format: None,
            credential: None,
            errors: Vec::new(),
            details: HashMap::new(),
        })
    }

    /// Create a device response with selective disclosure
    pub fn create_device_response(
        &self,
        mdoc: &MDoc,
        request: &DocRequest,
    ) -> Result<MDoc, MdocServiceError> {
        DisclosureProcessor::filter_mdoc(mdoc, request)
            .map_err(|e| MdocServiceError::Disclosure(e.to_string()))
    }

    /// Validate a disclosure request against an mDoc
    pub fn validate_disclosure_request(
        &self,
        mdoc: &MDoc,
        request: &DocRequest,
    ) -> Result<(), MdocServiceError> {
        DisclosureProcessor::validate_request(mdoc, request)
            .map_err(|e| MdocServiceError::Disclosure(e.to_string()))
    }

    /// Encode an issuer-signed item to CBOR bytes (for hashing)
    fn encode_issuer_signed_item(
        &self,
        item: &IssuerSignedItem,
    ) -> Result<Vec<u8>, MdocServiceError> {
        // Encode to CBOR using serde_cbor
        serde_cbor::to_vec(&item).map_err(|e| MdocServiceError::Encoding(e.to_string()))
    }

    /// Generate random salt for data elements
    fn generate_random_salt() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; 16];
        rng.fill(&mut salt[..]);
        salt
    }

    /// Convert mDoc to CBOR bytes
    pub fn encode_mdoc(&self, mdoc: &MDoc) -> Result<Vec<u8>, MdocServiceError> {
        MdocEncoder::encode_mdoc(mdoc).map_err(|e| MdocServiceError::Encoding(e.to_string()))
    }

    /// Decode CBOR bytes to mDoc
    pub fn decode_mdoc(&self, bytes: &[u8]) -> Result<MDoc, MdocServiceError> {
        MdocEncoder::decode_mdoc(bytes).map_err(|e| MdocServiceError::Encoding(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_salt() {
        let salt1 = MdocService::generate_random_salt();
        let salt2 = MdocService::generate_random_salt();

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[tokio::test]
    async fn test_mdoc_creation() {
        // This is a basic structure test
        // Full test would require wallet setup

        let doc_type = DOCTYPE_MDL.to_string();
        let mdoc = MDoc::new(doc_type.clone());

        assert_eq!(mdoc.doc_type, doc_type);
        assert_eq!(mdoc.version, "1.0");
        assert!(mdoc.is_valid());
    }

    #[test]
    fn test_issuer_signed_item_encoding() {
        let item = IssuerSignedItem {
            digest_id: 0,
            random: vec![1, 2, 3, 4],
            element_identifier: "test".to_string(),
            element_value: serde_json::json!("value"),
        };

        let encoded = serde_cbor::to_vec(&item).unwrap();
        assert!(!encoded.is_empty());

        // Can decode back
        let decoded: IssuerSignedItem = serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded.element_identifier, "test");
    }
}
