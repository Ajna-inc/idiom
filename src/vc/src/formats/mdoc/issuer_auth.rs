//! Issuer authentication using COSE_Sign1
//!
//! The issuer signs the Mobile Security Object (MSO) using COSE_Sign1 structure

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::encoder::MdocEncoder;
use super::types::MobileSecurityObject;
use agent_core::traits::{KeyType, WalletProvider};

/// Error types for issuer authentication
#[derive(Debug, thiserror::Error)]
pub enum IssuerAuthError {
    #[error("CBOR encoding error: {0}")]
    CborEncoding(String),

    #[error("COSE error: {0}")]
    Cose(String),

    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Invalid key type: expected {expected}, got {actual}")]
    InvalidKeyType { expected: String, actual: String },

    #[error("Signature error: {0}")]
    Signature(String),
}

/// Issuer authentication handler
pub struct IssuerAuth {
    wallet: Arc<dyn WalletProvider>,
}

impl IssuerAuth {
    /// Create new issuer auth handler
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        Self { wallet }
    }

    /// Sign a Mobile Security Object and create COSE_Sign1
    pub async fn sign_mso(
        &self,
        mso: &MobileSecurityObject,
        key_id: &str,
    ) -> Result<Vec<u8>, IssuerAuthError> {
        // Encode MSO to CBOR
        let mso_bytes = MdocEncoder::encode_mso(mso)
            .map_err(|e| IssuerAuthError::CborEncoding(e.to_string()))?;

        // Get key from wallet
        let key = self
            .wallet
            .get_key(key_id)
            .await
            .map_err(|e| IssuerAuthError::Wallet(e.to_string()))?
            .ok_or_else(|| IssuerAuthError::Wallet(format!("Key not found: {}", key_id)))?;

        // Determine algorithm based on key type
        let alg = match key.key_type {
            KeyType::Ed25519 => coset::iana::Algorithm::EdDSA,
            KeyType::P256 => coset::iana::Algorithm::ES256,
            _ => {
                return Err(IssuerAuthError::InvalidKeyType {
                    expected: "Ed25519 or P256".to_string(),
                    actual: format!("{:?}", key.key_type),
                });
            }
        };

        // Build protected header
        let protected = HeaderBuilder::new().algorithm(alg).build();

        // Build COSE_Sign1 structure
        let sign1_builder = CoseSign1Builder::new()
            .protected(protected)
            .payload(mso_bytes);

        // Create signature
        let to_sign = Self::create_sig_structure(&sign1_builder)?;
        let signature = self
            .wallet
            .sign(key_id, &to_sign)
            .await
            .map_err(|e| IssuerAuthError::Wallet(e.to_string()))?;

        // Complete COSE_Sign1
        let sign1 = sign1_builder.signature(signature.bytes).build();

        // Encode to CBOR
        let cose_bytes = sign1
            .to_vec()
            .map_err(|e| IssuerAuthError::Cose(format!("{:?}", e)))?;

        Ok(cose_bytes)
    }

    /// Verify a COSE_Sign1 issuer authentication
    pub async fn verify_issuer_auth(
        &self,
        cose_bytes: &[u8],
        expected_doc_type: &str,
    ) -> Result<MobileSecurityObject, IssuerAuthError> {
        // Decode COSE_Sign1
        let sign1 = CoseSign1::from_slice(cose_bytes)
            .map_err(|e| IssuerAuthError::Cose(format!("{:?}", e)))?;

        // Extract payload (MSO)
        let mso_bytes = sign1
            .payload
            .as_ref()
            .ok_or_else(|| IssuerAuthError::Cose("Missing payload in COSE_Sign1".to_string()))?;

        // Decode MSO
        let mso = Self::decode_mso(mso_bytes)?;

        // Verify doc type matches
        if mso.doc_type != expected_doc_type {
            return Err(IssuerAuthError::Signature(format!(
                "Doc type mismatch: expected {}, got {}",
                expected_doc_type, mso.doc_type
            )));
        }

        // Verify MSO is currently valid
        if !mso.is_currently_valid() {
            return Err(IssuerAuthError::Signature(
                "MSO expired or not yet valid".to_string(),
            ));
        }

        // TODO: Verify signature against issuer's public key
        // This requires extracting the public key from the MSO or a trusted issuer registry

        Ok(mso)
    }

    /// Create signature structure for COSE_Sign1 (Sig_structure)
    fn create_sig_structure(_builder: &CoseSign1Builder) -> Result<Vec<u8>, IssuerAuthError> {
        // COSE Sig_structure = [
        //   context = "Signature1",
        //   body_protected = protected header,
        //   external_aad = "",
        //   payload = MSO bytes
        // ]

        // For now, we'll use a simplified approach
        // In production, use proper CBOR array encoding
        let mut sig_data = Vec::new();

        // Context
        sig_data.extend_from_slice(b"Signature1");

        // Protected header (would need proper CBOR encoding)
        // Payload (would be included)

        // Simplified: just return the payload for now
        // TODO: Implement proper Sig_structure creation
        Ok(sig_data)
    }

    /// Decode MSO from CBOR bytes (helper)
    fn decode_mso(bytes: &[u8]) -> Result<MobileSecurityObject, IssuerAuthError> {
        // Parse CBOR to MSO structure
        let cbor_value: serde_cbor::Value = serde_cbor::from_slice(bytes)
            .map_err(|e| IssuerAuthError::CborEncoding(e.to_string()))?;

        // Convert to MSO (simplified - would need full parsing)
        let map = match &cbor_value {
            serde_cbor::Value::Map(m) => m,
            _ => {
                return Err(IssuerAuthError::CborEncoding(
                    "Expected map for MSO".to_string(),
                ))
            }
        };

        let doc_type = map
            .get(&serde_cbor::Value::Text("docType".to_string()))
            .and_then(|v| match v {
                serde_cbor::Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| IssuerAuthError::CborEncoding("Missing docType".to_string()))?
            .to_string();

        let valid_from_str = map
            .get(&serde_cbor::Value::Text("validFrom".to_string()))
            .and_then(|v| match v {
                serde_cbor::Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| IssuerAuthError::CborEncoding("Missing validFrom".to_string()))?;

        let valid_until_str = map
            .get(&serde_cbor::Value::Text("validUntil".to_string()))
            .and_then(|v| match v {
                serde_cbor::Value::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| IssuerAuthError::CborEncoding("Missing validUntil".to_string()))?;

        let valid_from = chrono::DateTime::parse_from_rfc3339(valid_from_str)
            .map_err(|e| IssuerAuthError::CborEncoding(format!("Invalid validFrom date: {}", e)))?
            .with_timezone(&chrono::Utc);

        let valid_until = chrono::DateTime::parse_from_rfc3339(valid_until_str)
            .map_err(|e| IssuerAuthError::CborEncoding(format!("Invalid validUntil date: {}", e)))?
            .with_timezone(&chrono::Utc);

        // Create minimal MSO structure
        use super::types::DeviceKeyInfo;
        let device_key_info = DeviceKeyInfo {
            device_key: Vec::new(),
            key_authorizations: None,
            key_info: None,
        };

        Ok(MobileSecurityObject::new(
            doc_type,
            device_key_info,
            valid_from,
            valid_until,
        ))
    }

    /// Hash data element for digest calculation
    pub fn hash_data_element(item_bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(item_bytes);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{DeviceKeyInfo, MobileSecurityObject, DOCTYPE_MDL};
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_hash_data_element() {
        let data = b"test data";
        let hash = IssuerAuth::hash_data_element(data);

        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_mso_validity_check() {
        let device_key_info = DeviceKeyInfo {
            device_key: vec![],
            key_authorizations: None,
            key_info: None,
        };

        let valid_from = Utc::now() - chrono::Duration::hours(1);
        let valid_until = Utc::now() + chrono::Duration::days(30);

        let mso = MobileSecurityObject::new(
            DOCTYPE_MDL.to_string(),
            device_key_info,
            valid_from,
            valid_until,
        );

        assert!(mso.is_currently_valid());
    }
}
