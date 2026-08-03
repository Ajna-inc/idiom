//! COSE_Sign1 wrapper based on animo-id/mdoc pattern
//!
//! This implements the COSE_Sign1 structure per RFC 8152 with proper
//! Sig_structure creation for signing.

use crate::context::{MdocContext, SignatureAlgorithm};
use crate::error::{MdocError, Result};
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1, Header, HeaderBuilder, ProtectedHeader};

/// Wrapper around COSE_Sign1 with builder pattern
///
/// Based on animo/mdoc's Sign1 class:
/// - Provides `to_be_signed()` method that creates proper Sig_structure
/// - Supports signing with pluggable context
#[derive(Debug, Clone)]
pub struct Sign1 {
    inner: CoseSign1,
    algorithm: SignatureAlgorithm,
    external_aad: Vec<u8>,
}

impl Sign1 {
    /// Create a new Sign1 builder
    pub fn builder() -> Sign1Builder {
        Sign1Builder::default()
    }

    /// Get the payload
    pub fn payload(&self) -> Option<&[u8]> {
        self.inner.payload.as_deref()
    }

    /// Get the signature
    pub fn signature(&self) -> &[u8] {
        &self.inner.signature
    }

    /// Get the protected headers as encoded bytes
    pub fn protected_headers_bytes(&self) -> Result<Vec<u8>> {
        // Use coset's built-in serialization
        let cbor_value = self.inner.protected.clone().cbor_bstr().map_err(|e| {
            MdocError::Other(format!("Failed to encode protected headers: {:?}", e))
        })?;

        // cbor_bstr returns a CBOR Value (byte string), we need to extract the bytes
        if let Value::Bytes(bytes) = cbor_value {
            Ok(bytes)
        } else {
            // Encode the value to bytes
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&cbor_value, &mut buf)?;
            Ok(buf)
        }
    }

    /// Create the "to be signed" bytes (Sig_structure)
    ///
    /// Per RFC 8152 Section 4.4:
    /// Sig_structure = [
    ///     context: "Signature1",
    ///     body_protected: protected_headers_bytes,
    ///     external_aad: external_aad,
    ///     payload: payload
    /// ]
    pub fn create_to_be_signed(&self) -> Result<Vec<u8>> {
        let protected_bytes = self.protected_headers_bytes()?;
        let payload = self
            .payload()
            .ok_or_else(|| MdocError::Other("Missing payload".to_string()))?;

        // Create the Sig_structure array
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".to_string()),
            Value::Bytes(protected_bytes),
            Value::Bytes(self.external_aad.clone()),
            Value::Bytes(payload.to_vec()),
        ]);

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&sig_structure, &mut buf)?;
        Ok(buf)
    }

    /// Sign the payload using the provided context
    pub async fn sign(mut self, context: &dyn MdocContext, key_id: &str) -> Result<Self> {
        let to_be_signed = self.create_to_be_signed()?;
        let protected_bytes = self.protected_headers_bytes()?;

        let signature = context
            .cose_sign1_sign(key_id, &to_be_signed, &protected_bytes, self.algorithm)
            .await?;

        self.inner.signature = signature;
        Ok(self)
    }

    /// Encode the COSE_Sign1 to CBOR bytes using coset's encoding
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .clone()
            .to_vec()
            .map_err(|e| MdocError::Other(format!("Failed to encode COSE_Sign1: {:?}", e)))
    }

    /// Decode from CBOR bytes using coset's decoding
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let inner = CoseSign1::from_slice(bytes)
            .map_err(|e| MdocError::Other(format!("Failed to decode COSE_Sign1: {:?}", e)))?;

        // Extract algorithm from protected headers
        let algorithm = extract_algorithm_from_header(&inner.protected.header)?;

        Ok(Self {
            inner,
            algorithm,
            external_aad: Vec::new(),
        })
    }

    /// Verify the signature using the provided context and public key
    pub async fn verify(
        &self,
        context: &dyn MdocContext,
        public_key: &crate::cose::CoseKey,
    ) -> Result<bool> {
        let to_be_signed = self.create_to_be_signed()?;
        let protected_bytes = self.protected_headers_bytes()?;

        context
            .cose_sign1_verify(
                public_key,
                &self.inner.signature,
                &to_be_signed,
                &protected_bytes,
                self.algorithm,
            )
            .await
    }
}

/// Builder for Sign1 structure
#[derive(Default)]
pub struct Sign1Builder {
    payload: Option<Vec<u8>>,
    algorithm: Option<SignatureAlgorithm>,
    external_aad: Option<Vec<u8>>,
}

impl Sign1Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the payload to be signed
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the signature algorithm
    pub fn algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set external additional authenticated data
    pub fn external_aad(mut self, aad: Vec<u8>) -> Self {
        self.external_aad = Some(aad);
        self
    }

    /// Build the Sign1 structure (not yet signed)
    pub fn build(self) -> Result<Sign1> {
        let algorithm = self.algorithm.ok_or_else(|| MdocError::MissingField {
            field: "algorithm".to_string(),
        })?;

        let payload = self.payload.ok_or_else(|| MdocError::MissingField {
            field: "payload".to_string(),
        })?;

        // Build protected headers
        let header = HeaderBuilder::new()
            .algorithm(algorithm.to_cose_algorithm())
            .build();

        let protected = ProtectedHeader {
            original_data: None,
            header,
        };

        let inner = CoseSign1 {
            protected,
            unprotected: Header::default(),
            payload: Some(payload),
            signature: Vec::new(), // Empty until signed
        };

        Ok(Sign1 {
            inner,
            algorithm,
            external_aad: self.external_aad.unwrap_or_default(),
        })
    }
}

/// Extract algorithm from COSE header
fn extract_algorithm_from_header(header: &Header) -> Result<SignatureAlgorithm> {
    if let Some(alg) = &header.alg {
        match alg {
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                Ok(SignatureAlgorithm::EdDSA)
            }
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES256) => {
                Ok(SignatureAlgorithm::ES256)
            }
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384) => {
                Ok(SignatureAlgorithm::ES384)
            }
            _ => Err(MdocError::Other(format!(
                "Unsupported algorithm: {:?}",
                alg
            ))),
        }
    } else {
        Err(MdocError::MissingField {
            field: "algorithm in protected header".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign1_builder() {
        let sign1 = Sign1::builder()
            .payload(b"test payload".to_vec())
            .algorithm(SignatureAlgorithm::EdDSA)
            .build()
            .unwrap();

        assert_eq!(sign1.payload(), Some(b"test payload".as_ref()));
        assert_eq!(sign1.algorithm, SignatureAlgorithm::EdDSA);
    }

    #[test]
    fn test_to_be_signed_structure() {
        let sign1 = Sign1::builder()
            .payload(b"test".to_vec())
            .algorithm(SignatureAlgorithm::EdDSA)
            .external_aad(b"aad".to_vec())
            .build()
            .unwrap();

        let tbs = sign1.create_to_be_signed().unwrap();

        // Should be a CBOR array
        assert!(!tbs.is_empty());

        // Decode and verify structure
        use std::io::Cursor;
        let value: Value = ciborium::de::from_reader(Cursor::new(&tbs)).unwrap();
        if let Value::Array(arr) = value {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], Value::Text("Signature1".to_string()));
        } else {
            panic!("Expected array");
        }
    }
}
