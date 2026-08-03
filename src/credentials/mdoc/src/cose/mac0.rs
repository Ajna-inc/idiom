//! COSE_Mac0 wrapper for message authentication
//!
//! This implements the COSE_Mac0 structure per RFC 8152 for device authentication
//! as an alternative to signatures (useful for constrained devices).

use crate::context::MdocContext;
use crate::error::{MdocError, Result};
use ciborium::value::Value;
use coset::{CborSerializable, CoseMac0, Header, HeaderBuilder, ProtectedHeader};

/// Wrapper around COSE_Mac0 with builder pattern
///
/// Similar to Sign1 but uses MAC instead of signature.
/// Used for device authentication when signatures are not desired.
pub struct Mac0 {
    inner: CoseMac0,
    external_aad: Vec<u8>,
}

impl Mac0 {
    /// Create a new Mac0 builder
    pub fn builder() -> Mac0Builder {
        Mac0Builder::default()
    }

    /// Get the payload
    pub fn payload(&self) -> Option<&[u8]> {
        self.inner.payload.as_deref()
    }

    /// Get the tag (MAC)
    pub fn tag(&self) -> &[u8] {
        &self.inner.tag
    }

    /// Get the protected headers as encoded bytes
    pub fn protected_headers_bytes(&self) -> Result<Vec<u8>> {
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

    /// Create the "to be MACed" bytes (MAC_structure)
    ///
    /// Per RFC 8152 Section 6.3:
    /// MAC_structure = [
    ///     context: "MAC0",
    ///     protected: protected_headers_bytes,
    ///     external_aad: external_aad,
    ///     payload: payload
    /// ]
    pub fn create_to_be_maced(&self) -> Result<Vec<u8>> {
        let protected_bytes = self.protected_headers_bytes()?;
        let payload = self
            .payload()
            .ok_or_else(|| MdocError::Other("Missing payload".to_string()))?;

        // Create the MAC_structure array
        let mac_structure = Value::Array(vec![
            Value::Text("MAC0".to_string()),
            Value::Bytes(protected_bytes),
            Value::Bytes(self.external_aad.clone()),
            Value::Bytes(payload.to_vec()),
        ]);

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&mac_structure, &mut buf)?;
        Ok(buf)
    }

    /// Compute the MAC tag using the provided context
    pub async fn compute_tag(mut self, context: &dyn MdocContext, key: &[u8]) -> Result<Self> {
        let to_be_maced = self.create_to_be_maced()?;
        let protected_bytes = self.protected_headers_bytes()?;

        let tag = context
            .cose_mac0_sign(key, &to_be_maced, &protected_bytes)
            .await?;

        self.inner.tag = tag;
        Ok(self)
    }

    /// Encode the COSE_Mac0 to CBOR bytes using coset's encoding
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .clone()
            .to_vec()
            .map_err(|e| MdocError::Other(format!("Failed to encode COSE_Mac0: {:?}", e)))
    }

    /// Decode from CBOR bytes using coset's decoding
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let inner = CoseMac0::from_slice(bytes)
            .map_err(|e| MdocError::Other(format!("Failed to decode COSE_Mac0: {:?}", e)))?;

        Ok(Self {
            inner,
            external_aad: Vec::new(),
        })
    }

    /// Verify the MAC tag using the provided context
    pub async fn verify(&self, context: &dyn MdocContext, key: &[u8]) -> Result<bool> {
        let to_be_maced = self.create_to_be_maced()?;
        let protected_bytes = self.protected_headers_bytes()?;

        context
            .cose_mac0_verify(key, &self.inner.tag, &to_be_maced, &protected_bytes)
            .await
    }
}

/// Builder for Mac0 structure
#[derive(Default)]
pub struct Mac0Builder {
    payload: Option<Vec<u8>>,
    external_aad: Option<Vec<u8>>,
    algorithm: Option<coset::iana::Algorithm>,
}

impl Mac0Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the payload to be MACed
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the MAC algorithm (e.g., HMAC-SHA256)
    pub fn algorithm(mut self, algorithm: coset::iana::Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set external additional authenticated data
    pub fn external_aad(mut self, aad: Vec<u8>) -> Self {
        self.external_aad = Some(aad);
        self
    }

    /// Build the Mac0 structure (not yet computed)
    pub fn build(self) -> Result<Mac0> {
        let algorithm = self
            .algorithm
            .unwrap_or(coset::iana::Algorithm::HMAC_256_256);

        let payload = self.payload.ok_or_else(|| MdocError::MissingField {
            field: "payload".to_string(),
        })?;

        // Build protected headers
        let header = HeaderBuilder::new().algorithm(algorithm).build();

        let protected = ProtectedHeader {
            original_data: None,
            header,
        };

        let inner = CoseMac0 {
            protected,
            unprotected: Header::default(),
            payload: Some(payload),
            tag: Vec::new(), // Empty until computed
        };

        Ok(Mac0 {
            inner,
            external_aad: self.external_aad.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac0_builder() {
        let mac0 = Mac0::builder()
            .payload(b"test payload".to_vec())
            .algorithm(coset::iana::Algorithm::HMAC_256_256)
            .build()
            .unwrap();

        assert_eq!(mac0.payload(), Some(b"test payload".as_ref()));
    }

    #[test]
    fn test_to_be_maced_structure() {
        let mac0 = Mac0::builder()
            .payload(b"test".to_vec())
            .algorithm(coset::iana::Algorithm::HMAC_256_256)
            .external_aad(b"aad".to_vec())
            .build()
            .unwrap();

        let tbm = mac0.create_to_be_maced().unwrap();

        // Should be a CBOR array
        assert!(!tbm.is_empty());

        // Decode and verify structure
        use std::io::Cursor;
        let value: Value = ciborium::de::from_reader(Cursor::new(&tbm)).unwrap();
        if let Value::Array(arr) = value {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], Value::Text("MAC0".to_string()));
        } else {
            panic!("Expected array");
        }
    }
}
