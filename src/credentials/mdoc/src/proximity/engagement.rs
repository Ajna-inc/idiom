//! DeviceEngagement for proximity presentations (BLE, NFC, WiFi)

use crate::error::{MdocError, Result};
use crate::proximity::{DeviceRetrievalMethods, Security};
use base64::Engine;
use ciborium::Value;
use serde::{Deserialize, Serialize};

/// DeviceEngagement structure for establishing proximity presentations
///
/// Used when holder and verifier are physically proximate (BLE, NFC, WiFi-Aware)
/// Contains cryptographic material and transport information for secure channel establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEngagement {
    /// Protocol version (e.g., "1.0")
    pub version: String,

    /// Security parameters including device public key
    pub security: Security,

    /// Available transport methods (BLE, NFC, WiFi, etc.)
    #[serde(rename = "deviceRetrievalMethods")]
    pub device_retrieval_methods: Vec<DeviceRetrievalMethods>,

    /// Optional server retrieval options
    #[serde(
        rename = "serverRetrievalOptions",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_retrieval_options: Option<Value>,

    /// Optional protocol information
    #[serde(rename = "protocolInfo", skip_serializing_if = "Option::is_none")]
    pub protocol_info: Option<Value>,
}

impl DeviceEngagement {
    /// Create a new DeviceEngagement with default version "1.0"
    pub fn new(security: Security) -> Self {
        Self {
            version: "1.0".to_string(),
            security,
            device_retrieval_methods: Vec::new(),
            server_retrieval_options: None,
            protocol_info: None,
        }
    }

    /// Builder pattern: add a retrieval method
    pub fn add_retrieval_method(mut self, method: DeviceRetrievalMethods) -> Self {
        self.device_retrieval_methods.push(method);
        self
    }

    /// Builder pattern: set server retrieval options
    pub fn with_server_retrieval(mut self, options: Value) -> Self {
        self.server_retrieval_options = Some(options);
        self
    }

    /// Builder pattern: set protocol info
    pub fn with_protocol_info(mut self, info: Value) -> Self {
        self.protocol_info = Some(info);
        self
    }

    /// Encode DeviceEngagement to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Decode DeviceEngagement from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(Into::into)
    }

    /// Convert to QR code payload (Base64-encoded CBOR)
    pub fn to_qr_code_uri(&self) -> Result<String> {
        let cbor_bytes = self.to_cbor()?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes);
        Ok(format!("mdoc:{}", encoded))
    }

    /// Parse from QR code URI
    pub fn from_qr_code_uri(uri: &str) -> Result<Self> {
        let encoded = uri
            .strip_prefix("mdoc:")
            .ok_or_else(|| MdocError::Other("Invalid QR code URI format".to_string()))?;

        let cbor_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;

        Self::from_cbor(&cbor_bytes)
    }

    /// Get the device's ephemeral public key from security parameters
    pub fn get_device_key(&self) -> &crate::cose::CoseKey {
        &self.security.device_key.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseKey;

    #[test]
    fn test_device_engagement_creation() {
        let device_key = CoseKey::new(2); // EC2 key
        let edevice_key = crate::proximity::EDeviceKey::new(device_key);
        let security = Security::new(1, edevice_key); // Cipher suite 1

        let engagement = DeviceEngagement::new(security);

        assert_eq!(engagement.version, "1.0");
        assert_eq!(engagement.device_retrieval_methods.len(), 0);
    }

    #[test]
    fn test_device_engagement_builder() {
        let device_key = CoseKey::new(2);
        let edevice_key = crate::proximity::EDeviceKey::new(device_key);
        let security = Security::new(1, edevice_key);

        let engagement = DeviceEngagement::new(security).with_protocol_info(Value::Null);

        assert!(engagement.protocol_info.is_some());
    }

    #[test]
    fn test_qr_code_uri() {
        let device_key = CoseKey::new(2);
        let edevice_key = crate::proximity::EDeviceKey::new(device_key);
        let security = Security::new(1, edevice_key);
        let engagement = DeviceEngagement::new(security);

        let uri = engagement.to_qr_code_uri().unwrap();
        assert!(uri.starts_with("mdoc:"));

        let decoded = DeviceEngagement::from_qr_code_uri(&uri).unwrap();
        assert_eq!(decoded.version, "1.0");
    }
}
