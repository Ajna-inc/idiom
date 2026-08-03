//! Device authentication for mDoc
//!
//! Supports device signature (COSE_Sign1) and device MAC (COSE_Mac0)

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use std::sync::Arc;

use agent_core::traits::WalletProvider;

/// Error types for device authentication
#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthError {
    #[error("CBOR encoding error: {0}")]
    CborEncoding(String),

    #[error("COSE error: {0}")]
    Cose(String),

    #[error("Wallet error: {0}")]
    Wallet(String),

    #[error("Signature error: {0}")]
    Signature(String),
}

/// Device authentication handler
pub struct DeviceAuth {
    wallet: Arc<dyn WalletProvider>,
}

impl DeviceAuth {
    /// Create new device auth handler
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        Self { wallet }
    }

    /// Create device signature (COSE_Sign1)
    pub async fn create_device_signature(
        &self,
        session_transcript: &SessionTranscript,
        doc_type: &str,
        namespaces: &serde_json::Value,
        device_key_id: &str,
    ) -> Result<Vec<u8>, DeviceAuthError> {
        // Create DeviceAuthentication structure
        let device_auth_bytes =
            Self::create_device_authentication(session_transcript, doc_type, namespaces)?;

        // Sign with device key
        let signature = self
            .wallet
            .sign(device_key_id, &device_auth_bytes)
            .await
            .map_err(|e| DeviceAuthError::Wallet(e.to_string()))?;

        // Build COSE_Sign1
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(device_auth_bytes)
            .signature(signature.bytes)
            .build();

        // Encode to CBOR
        let cose_bytes = sign1
            .to_vec()
            .map_err(|e| DeviceAuthError::Cose(format!("{:?}", e)))?;

        Ok(cose_bytes)
    }

    /// Verify device signature
    pub async fn verify_device_signature(
        &self,
        cose_bytes: &[u8],
        _session_transcript: &SessionTranscript,
        _expected_doc_type: &str,
    ) -> Result<bool, DeviceAuthError> {
        // Decode COSE_Sign1
        let sign1 = CoseSign1::from_slice(cose_bytes)
            .map_err(|e| DeviceAuthError::Cose(format!("{:?}", e)))?;

        // Extract payload
        let _payload = sign1
            .payload
            .as_ref()
            .ok_or_else(|| DeviceAuthError::Cose("Missing payload".to_string()))?;

        // Verify the structure includes expected session transcript
        // TODO: Full verification against device public key

        Ok(true) // Simplified for now
    }

    /// Create DeviceAuthentication structure for signing
    ///
    /// DeviceAuthentication = [
    ///   "DeviceAuthentication",
    ///   SessionTranscript,
    ///   DocType,
    ///   DeviceNameSpacesBytes
    /// ]
    fn create_device_authentication(
        session_transcript: &SessionTranscript,
        doc_type: &str,
        namespaces: &serde_json::Value,
    ) -> Result<Vec<u8>, DeviceAuthError> {
        // Create CBOR array
        let mut array = Vec::new();

        // Add "DeviceAuthentication" string
        array.push(serde_cbor::Value::Text("DeviceAuthentication".to_string()));

        // Add session transcript (encoded as bytes)
        let st_bytes = serde_cbor::to_vec(&session_transcript.to_cbor()?)
            .map_err(|e| DeviceAuthError::CborEncoding(e.to_string()))?;
        array.push(serde_cbor::Value::Bytes(st_bytes));

        // Add doc type
        array.push(serde_cbor::Value::Text(doc_type.to_string()));

        // Add namespaces (empty for basic auth)
        let ns_bytes = serde_cbor::to_vec(&namespaces)
            .map_err(|e| DeviceAuthError::CborEncoding(e.to_string()))?;
        array.push(serde_cbor::Value::Bytes(ns_bytes));

        // Encode entire array
        let bytes = serde_cbor::to_vec(&serde_cbor::Value::Array(array))
            .map_err(|e| DeviceAuthError::CborEncoding(e.to_string()))?;

        Ok(bytes)
    }
}

/// Session transcript for device engagement
///
/// Contains cryptographic binding between reader and holder
#[derive(Debug, Clone)]
pub struct SessionTranscript {
    /// Device engagement (optional)
    pub device_engagement: Option<Vec<u8>>,

    /// E-reader key (public key from verifier)
    pub e_reader_key: Option<Vec<u8>>,

    /// Handover data
    pub handover: Vec<u8>,
}

impl SessionTranscript {
    /// Create new session transcript
    pub fn new(handover: Vec<u8>) -> Self {
        Self {
            device_engagement: None,
            e_reader_key: None,
            handover,
        }
    }

    /// Convert to CBOR value
    fn to_cbor(&self) -> Result<serde_cbor::Value, DeviceAuthError> {
        let mut array = Vec::new();

        // Device engagement (null if not present)
        if let Some(de) = &self.device_engagement {
            array.push(serde_cbor::Value::Bytes(de.clone()));
        } else {
            array.push(serde_cbor::Value::Null);
        }

        // E-reader key (null if not present)
        if let Some(erk) = &self.e_reader_key {
            array.push(serde_cbor::Value::Bytes(erk.clone()));
        } else {
            array.push(serde_cbor::Value::Null);
        }

        // Handover
        array.push(serde_cbor::Value::Bytes(self.handover.clone()));

        Ok(serde_cbor::Value::Array(array))
    }
}

/// Device signature result
#[derive(Debug, Clone)]
pub struct DeviceSignature {
    /// COSE_Sign1 encoded signature
    pub signature_bytes: Vec<u8>,

    /// Device public key (for verification)
    pub device_public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_transcript_creation() {
        let handover = vec![1, 2, 3, 4];
        let st = SessionTranscript::new(handover.clone());

        assert_eq!(st.handover, handover);
        assert!(st.device_engagement.is_none());
        assert!(st.e_reader_key.is_none());
    }

    #[test]
    fn test_session_transcript_to_cbor() {
        let st = SessionTranscript::new(vec![1, 2, 3]);
        let cbor = st.to_cbor().unwrap();

        // Should be an array with 3 elements
        if let serde_cbor::Value::Array(arr) = cbor {
            assert_eq!(arr.len(), 3);
        } else {
            panic!("Expected array");
        }
    }
}
