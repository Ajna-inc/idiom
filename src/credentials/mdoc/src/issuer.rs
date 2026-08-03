//! Issuer API for creating and signing mDoc documents
//!
//! Based on animo-id/mdoc's Document class with builder pattern

use crate::cbor;
use crate::context::{DigestAlgorithm, MdocContext, SignatureAlgorithm};
use crate::cose::Sign1;
use crate::error::{MdocError, Result};
use crate::types::*;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;

/// Convert serde_json::Value to ciborium::Value
fn json_to_cbor_value(json: &serde_json::Value) -> ciborium::Value {
    match json {
        serde_json::Value::Null => ciborium::Value::Null,
        serde_json::Value::Bool(b) => ciborium::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ciborium::Value::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                ciborium::Value::Integer(u.into())
            } else if let Some(f) = n.as_f64() {
                ciborium::Value::Float(f)
            } else {
                ciborium::Value::Null
            }
        }
        serde_json::Value::String(s) => ciborium::Value::Text(s.clone()),
        serde_json::Value::Array(arr) => {
            ciborium::Value::Array(arr.iter().map(json_to_cbor_value).collect())
        }
        serde_json::Value::Object(obj) => ciborium::Value::Map(
            obj.iter()
                .map(|(k, v)| (ciborium::Value::Text(k.clone()), json_to_cbor_value(v)))
                .collect(),
        ),
    }
}

/// Builder for creating and signing mDoc documents
///
/// # Example (matching animo API):
///
/// ```rust,ignore
/// let document = DocumentBuilder::new("org.iso.18013.5.1.mDL")
///     .add_issuer_namespace("org.iso.18013.5.1", elements)
///     .use_digest_algorithm(DigestAlgorithm::Sha256)
///     .add_validity_info(validity_info)
///     .add_device_key_info(device_key_info)
///     .sign(context, issuer_key_id, SignatureAlgorithm::ES256)
///     .await?;
/// ```
pub struct DocumentBuilder {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, serde_json::Value>>,
    digest_algorithm: DigestAlgorithm,
    validity_info: Option<ValidityInfo>,
    device_key_info: Option<DeviceKeyInfo>,
}

impl DocumentBuilder {
    /// Create a new document builder
    pub fn new(doc_type: impl Into<String>) -> Self {
        Self {
            doc_type: doc_type.into(),
            namespaces: HashMap::new(),
            digest_algorithm: DigestAlgorithm::Sha256,
            validity_info: None,
            device_key_info: None,
        }
    }

    /// Add a namespace with data elements
    ///
    /// # Arguments
    /// * `namespace` - ISO namespace (e.g., "org.iso.18013.5.1")
    /// * `elements` - Map of element identifiers to values
    pub fn add_issuer_namespace(
        mut self,
        namespace: impl Into<String>,
        elements: HashMap<String, serde_json::Value>,
    ) -> Self {
        self.namespaces.insert(namespace.into(), elements);
        self
    }

    /// Set the digest algorithm (default: SHA-256)
    pub fn use_digest_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = algorithm;
        self
    }

    /// Add validity information
    pub fn add_validity_info(mut self, validity_info: ValidityInfo) -> Self {
        self.validity_info = Some(validity_info);
        self
    }

    /// Add device key information
    pub fn add_device_key_info(mut self, device_key_info: DeviceKeyInfo) -> Self {
        self.device_key_info = Some(device_key_info);
        self
    }

    /// Convenience method to set validity from a signed date
    pub fn set_validity_from_signed(mut self, signed: DateTime<Utc>, validity_days: i64) -> Self {
        self.validity_info = Some(ValidityInfo {
            signed,
            valid_from: signed,
            valid_until: signed + Duration::days(validity_days),
            expected_update: None,
        });
        self
    }

    /// Sign the document and create the final mDoc
    ///
    /// This performs the following steps:
    /// 1. Create IssuerSignedItems with random salts
    /// 2. Calculate digests for all elements
    /// 3. Build Mobile Security Object (MSO)
    /// 4. Sign MSO with COSE_Sign1 (IssuerAuth)
    /// 5. Create final Document
    pub async fn sign(
        self,
        context: &dyn MdocContext,
        issuer_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Document> {
        // Validate required fields
        let validity_info = self.validity_info.ok_or_else(|| MdocError::MissingField {
            field: "validity_info".to_string(),
        })?;

        let device_key_info = self
            .device_key_info
            .ok_or_else(|| MdocError::MissingField {
                field: "device_key_info".to_string(),
            })?;

        // Build IssuerSigned with all namespaces
        let mut issuer_signed_namespaces: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();
        let mut value_digests: HashMap<String, HashMap<u32, Vec<u8>>> = HashMap::new();

        for (namespace, elements) in &self.namespaces {
            let mut namespace_items = Vec::new();
            let mut namespace_digests = HashMap::new();

            for (digest_id, (element_id, element_value)) in elements.iter().enumerate() {
                let digest_id = digest_id as u32;

                // Generate random salt
                let random = generate_random_salt(context).await?;

                // Create IssuerSignedItem
                let item = IssuerSignedItem {
                    digest_id,
                    random: random.clone(),
                    element_identifier: element_id.clone(),
                    element_value: json_to_cbor_value(element_value),
                };

                // Encode item to CBOR
                let item_bytes = cbor::encode(&item)?;

                // Calculate digest
                let digest = calculate_digest(self.digest_algorithm, &item_bytes)?;

                namespace_items.push(item);
                namespace_digests.insert(digest_id, digest);
            }

            issuer_signed_namespaces.insert(namespace.clone(), namespace_items);
            value_digests.insert(namespace.clone(), namespace_digests);
        }

        // Build Mobile Security Object
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: self.digest_algorithm.as_str().to_string(),
            value_digests,
            device_key_info,
            doc_type: self.doc_type.clone(),
            validity_info,
        };

        // Encode MSO to CBOR
        let mso_bytes = cbor::encode(&mso)?;

        // Create COSE_Sign1 for IssuerAuth
        let sign1 = Sign1::builder()
            .payload(mso_bytes)
            .algorithm(algorithm)
            .build()?;

        // Sign with issuer key
        let signed_issuer_auth = sign1.sign(context, issuer_key_id).await?;

        // Encode signed IssuerAuth to bytes first
        let issuer_auth_bytes = signed_issuer_auth.encode()?;

        // Convert bytes to CBOR Value (real-world mDocs store as COSE_Sign1 array)
        let issuer_auth_value: ciborium::Value = ciborium::de::from_reader(&issuer_auth_bytes[..])?;

        // Create final document
        let document = Document {
            doc_type: self.doc_type,
            issuer_signed: IssuerSigned {
                name_spaces: issuer_signed_namespaces,
                issuer_auth: issuer_auth_value,
            },
            device_signed: None,
            errors: None,
        };

        Ok(document)
    }
}

/// Generate a random salt for digest calculation
async fn generate_random_salt(context: &dyn MdocContext) -> Result<Vec<u8>> {
    context.random(16).await
}

/// Calculate digest of data using specified algorithm
fn calculate_digest(algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        DigestAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        DigestAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        DigestAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }
}

/// Simple synchronous random generator for tests
pub fn generate_random_salt_sync() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_builder_creation() {
        let builder = DocumentBuilder::new("org.iso.18013.5.1.mDL")
            .use_digest_algorithm(DigestAlgorithm::Sha256);

        assert_eq!(builder.doc_type, "org.iso.18013.5.1.mDL");
        assert_eq!(builder.digest_algorithm, DigestAlgorithm::Sha256);
    }

    #[test]
    fn test_digest_calculation() {
        let data = b"test data";
        let digest = calculate_digest(DigestAlgorithm::Sha256, data).unwrap();

        assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_random_salt_generation() {
        let salt1 = generate_random_salt_sync();
        let salt2 = generate_random_salt_sync();

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be different
    }
}
