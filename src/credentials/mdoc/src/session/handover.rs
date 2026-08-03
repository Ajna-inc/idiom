//! Handover types for different presentation scenarios

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Handover represents the context in which the presentation occurs
///
/// Different handover types for different scenarios:
/// - BLE: Bluetooth Low Energy connection info
/// - NFC: Near Field Communication parameters
/// - QR: QR code presentation details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Handover {
    Ble(BleHandover),
    Nfc(NfcHandover),
    Qr(QrHandover),
}

impl Handover {
    /// Create BLE handover
    pub fn ble(
        peripheral_server_uuid: Option<String>,
        central_client_uuid: Option<String>,
    ) -> Self {
        Handover::Ble(BleHandover {
            handover_type: HandoverType::Ble,
            peripheral_server_uuid,
            central_client_uuid,
        })
    }

    /// Create NFC handover
    pub fn nfc(command_data: Option<Vec<u8>>, response_data: Option<Vec<u8>>) -> Self {
        Handover::Nfc(NfcHandover {
            handover_type: HandoverType::Nfc,
            command_data,
            response_data,
        })
    }

    /// Create QR code handover
    pub fn qr() -> Self {
        Handover::Qr(QrHandover {
            handover_type: HandoverType::Qr,
        })
    }

    /// Encode handover to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(self, &mut buffer)?;
        Ok(buffer)
    }

    /// Decode handover from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(Into::into)
    }

    /// Get the handover type
    pub fn handover_type(&self) -> HandoverType {
        match self {
            Handover::Ble(h) => h.handover_type,
            Handover::Nfc(h) => h.handover_type,
            Handover::Qr(h) => h.handover_type,
        }
    }
}

/// Handover type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandoverType {
    /// Bluetooth Low Energy
    #[serde(rename = "ble")]
    Ble,

    /// Near Field Communication
    #[serde(rename = "nfc")]
    Nfc,

    /// QR code
    #[serde(rename = "qr")]
    Qr,
}

/// BLE handover information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleHandover {
    /// Handover type identifier
    #[serde(rename = "type")]
    pub handover_type: HandoverType,

    /// Optional peripheral server mode UUID
    #[serde(
        rename = "peripheralServerUuid",
        skip_serializing_if = "Option::is_none"
    )]
    pub peripheral_server_uuid: Option<String>,

    /// Optional central client mode UUID
    #[serde(rename = "centralClientUuid", skip_serializing_if = "Option::is_none")]
    pub central_client_uuid: Option<String>,
}

impl BleHandover {
    /// Create BLE handover with peripheral server
    pub fn peripheral_server(uuid: impl Into<String>) -> Self {
        Self {
            handover_type: HandoverType::Ble,
            peripheral_server_uuid: Some(uuid.into()),
            central_client_uuid: None,
        }
    }

    /// Create BLE handover with central client
    pub fn central_client(uuid: impl Into<String>) -> Self {
        Self {
            handover_type: HandoverType::Ble,
            peripheral_server_uuid: None,
            central_client_uuid: Some(uuid.into()),
        }
    }

    /// Create BLE handover with both modes
    pub fn dual_mode(peripheral_uuid: impl Into<String>, central_uuid: impl Into<String>) -> Self {
        Self {
            handover_type: HandoverType::Ble,
            peripheral_server_uuid: Some(peripheral_uuid.into()),
            central_client_uuid: Some(central_uuid.into()),
        }
    }
}

/// NFC handover information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcHandover {
    /// Handover type identifier
    #[serde(rename = "type")]
    pub handover_type: HandoverType,

    /// Optional command data
    #[serde(rename = "commandData", skip_serializing_if = "Option::is_none")]
    pub command_data: Option<Vec<u8>>,

    /// Optional response data
    #[serde(rename = "responseData", skip_serializing_if = "Option::is_none")]
    pub response_data: Option<Vec<u8>>,
}

impl NfcHandover {
    /// Create NFC handover
    pub fn new() -> Self {
        Self {
            handover_type: HandoverType::Nfc,
            command_data: None,
            response_data: None,
        }
    }

    /// Set command data
    pub fn with_command_data(mut self, data: Vec<u8>) -> Self {
        self.command_data = Some(data);
        self
    }

    /// Set response data
    pub fn with_response_data(mut self, data: Vec<u8>) -> Self {
        self.response_data = Some(data);
        self
    }
}

impl Default for NfcHandover {
    fn default() -> Self {
        Self::new()
    }
}

/// QR code handover (minimal - just indicates QR presentation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrHandover {
    /// Handover type identifier
    #[serde(rename = "type")]
    pub handover_type: HandoverType,
}

impl QrHandover {
    /// Create QR handover
    pub fn new() -> Self {
        Self {
            handover_type: HandoverType::Qr,
        }
    }
}

impl Default for QrHandover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_handover() {
        let handover = Handover::ble(Some("uuid-123".to_string()), None);
        assert_eq!(handover.handover_type(), HandoverType::Ble);

        let cbor = handover.to_cbor().unwrap();
        let decoded = Handover::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.handover_type(), HandoverType::Ble);
    }

    #[test]
    fn test_nfc_handover() {
        let handover = Handover::nfc(Some(vec![1, 2, 3]), None);
        assert_eq!(handover.handover_type(), HandoverType::Nfc);
    }

    #[test]
    fn test_qr_handover() {
        let handover = Handover::qr();
        assert_eq!(handover.handover_type(), HandoverType::Qr);
    }

    #[test]
    fn test_ble_handover_builder() {
        let handover = BleHandover::peripheral_server("uuid-123");
        assert_eq!(handover.handover_type, HandoverType::Ble);
        assert!(handover.peripheral_server_uuid.is_some());
        assert!(handover.central_client_uuid.is_none());
    }

    #[test]
    fn test_nfc_handover_builder() {
        let handover = NfcHandover::new()
            .with_command_data(vec![1, 2, 3])
            .with_response_data(vec![4, 5, 6]);

        assert!(handover.command_data.is_some());
        assert!(handover.response_data.is_some());
    }

    #[test]
    fn test_qr_handover_default() {
        let handover = QrHandover::default();
        assert_eq!(handover.handover_type, HandoverType::Qr);
    }
}
