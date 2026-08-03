//! Verifier API for validating mDoc documents and device responses

use crate::cbor;
use crate::context::MdocContext;
use crate::cose::Sign1;
use crate::error::{MdocError, Result};
use crate::types::*;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};

/// Verifier for mDoc documents
pub struct Verifier;

impl Verifier {
    /// Verify a device response
    pub async fn verify(
        context: &dyn MdocContext,
        device_response_bytes: &[u8],
        trusted_certificates: &[Vec<u8>],
    ) -> Result<DeviceResponse> {
        // Decode device response
        let device_response: DeviceResponse = cbor::decode(device_response_bytes)?;

        // Verify each document
        for doc in device_response.documents.iter().flatten() {
            Self::verify_document(context, doc, trusted_certificates).await?;
        }

        Ok(device_response)
    }

    /// Verify a single document
    pub async fn verify_document(
        context: &dyn MdocContext,
        document: &Document,
        trusted_certificates: &[Vec<u8>],
    ) -> Result<()> {
        // 1. Verify issuer authentication (COSE_Sign1)
        let mso = Self::verify_issuer_auth(context, document, trusted_certificates).await?;

        // 2. Verify all element digests
        Self::verify_element_digests(document, &mso)?;

        // 3. Verify device authentication if present
        if let Some(ref device_signed) = document.device_signed {
            Self::verify_device_auth(context, device_signed, &mso.device_key_info).await?;
        }

        // 4. Verify validity period
        Self::verify_validity(&mso.validity_info)?;

        Ok(())
    }

    /// Verify issuer authentication and extract MSO
    async fn verify_issuer_auth(
        _context: &dyn MdocContext,
        document: &Document,
        _trusted_certificates: &[Vec<u8>],
    ) -> Result<MobileSecurityObject> {
        // Convert issuer_auth Value to bytes
        let mut issuer_auth_bytes = Vec::new();
        ciborium::ser::into_writer(&document.issuer_signed.issuer_auth, &mut issuer_auth_bytes)?;

        // Decode COSE_Sign1
        let sign1 = Sign1::decode(&issuer_auth_bytes)?;

        // Extract MSO payload
        let mso_bytes = sign1.payload().ok_or_else(|| MdocError::IssuerAuthFailed {
            reason: "Missing MSO payload".to_string(),
        })?;

        let mso: MobileSecurityObject = cbor::decode(mso_bytes)?;

        // TODO: Extract public key from certificate chain in sign1 headers
        // For now, we'll skip certificate validation in this basic implementation
        // A full implementation would:
        // 1. Extract x5chain from unprotected headers
        // 2. Validate certificate chain against trusted_certificates
        // 3. Extract public key from leaf certificate
        // 4. Verify signature

        // Verify doc_type matches
        if mso.doc_type != document.doc_type {
            return Err(MdocError::DocTypeMismatch {
                expected: mso.doc_type.clone(),
                actual: document.doc_type.clone(),
            });
        }

        Ok(mso)
    }

    /// Verify all element digests match the MSO
    fn verify_element_digests(document: &Document, mso: &MobileSecurityObject) -> Result<()> {
        for (namespace, items) in &document.issuer_signed.name_spaces {
            let expected_digests =
                mso.value_digests
                    .get(namespace)
                    .ok_or_else(|| MdocError::NamespaceNotFound {
                        namespace: namespace.clone(),
                    })?;

            for item in items {
                // Encode item to CBOR
                let item_bytes = cbor::encode(item)?;

                // Calculate digest
                let actual_digest = calculate_digest(&mso.digest_algorithm, &item_bytes)?;

                // Get expected digest
                let expected_digest = expected_digests.get(&item.digest_id).ok_or_else(|| {
                    MdocError::DigestVerificationFailed {
                        element: item.element_identifier.clone(),
                    }
                })?;

                // Compare
                if &actual_digest != expected_digest {
                    return Err(MdocError::DigestVerificationFailed {
                        element: item.element_identifier.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Verify device authentication
    async fn verify_device_auth(
        _context: &dyn MdocContext,
        _device_signed: &DeviceSigned,
        _device_key_info: &DeviceKeyInfo,
    ) -> Result<()> {
        // TODO: Implement device authentication verification
        // This requires:
        // 1. Decode device_auth (Sign1 or Mac0)
        // 2. Extract device public key from device_key_info
        // 3. Verify signature/MAC
        // 4. Verify DeviceAuthentication structure

        Ok(())
    }

    /// Verify validity period
    fn verify_validity(validity_info: &ValidityInfo) -> Result<()> {
        let now = chrono::Utc::now();

        if now < validity_info.valid_from {
            return Err(MdocError::InvalidMSO {
                reason: "Document not yet valid".to_string(),
            });
        }

        if now > validity_info.valid_until {
            return Err(MdocError::InvalidMSO {
                reason: "Document expired".to_string(),
            });
        }

        Ok(())
    }
}

/// Calculate digest using specified algorithm
fn calculate_digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-384" => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "SHA-512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(MdocError::Other(format!(
            "Unsupported digest algorithm: {}",
            algorithm
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_calculation() {
        let data = b"test data";
        let digest = calculate_digest("SHA-256", data).unwrap();

        assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes
    }
}
