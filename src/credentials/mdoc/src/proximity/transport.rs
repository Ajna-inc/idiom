//! Transport types for proximity presentations (BLE, NFC, WiFi, WebAPI)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Device Retrieval Methods - available transport options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRetrievalMethods {
    /// Transport type identifier
    #[serde(rename = "type")]
    pub transport_type: TransportType,

    /// Version of the transport protocol
    pub version: i32,

    /// Transport-specific options
    #[serde(flatten)]
    pub options: TransportOptions,
}

impl DeviceRetrievalMethods {
    /// Create new BLE retrieval method
    pub fn ble(options: BleOptions) -> Self {
        Self {
            transport_type: TransportType::Ble,
            version: 1,
            options: TransportOptions::Ble(options),
        }
    }

    /// Create new NFC retrieval method
    pub fn nfc(options: NfcOptions) -> Self {
        Self {
            transport_type: TransportType::Nfc,
            version: 1,
            options: TransportOptions::Nfc(options),
        }
    }

    /// Create new WiFi-Aware retrieval method
    pub fn wifi(options: WifiOptions) -> Self {
        Self {
            transport_type: TransportType::Wifi,
            version: 1,
            options: TransportOptions::Wifi(options),
        }
    }

    /// Create new WebAPI retrieval method
    pub fn web_api(options: WebApiOptions) -> Self {
        Self {
            transport_type: TransportType::WebApi,
            version: 1,
            options: TransportOptions::WebApi(options),
        }
    }
}

/// Transport type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Bluetooth Low Energy
    #[serde(rename = "ble")]
    Ble,

    /// Near Field Communication
    #[serde(rename = "nfc")]
    Nfc,

    /// WiFi-Aware
    #[serde(rename = "wifi-aware")]
    Wifi,

    /// Web API (HTTP/HTTPS)
    #[serde(rename = "webapi")]
    WebApi,
}

/// Transport-specific options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportOptions {
    Ble(BleOptions),
    Nfc(NfcOptions),
    Wifi(WifiOptions),
    WebApi(WebApiOptions),
}

/// BLE (Bluetooth Low Energy) transport options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleOptions {
    /// Whether BLE peripheral server mode is supported
    #[serde(rename = "supportsPeripheralServerMode")]
    pub supports_peripheral_server_mode: bool,

    /// Whether BLE central client mode is supported
    #[serde(rename = "supportsCentralClientMode")]
    pub supports_central_client_mode: bool,

    /// Optional peripheral server mode UUID
    #[serde(
        rename = "peripheralServerModeUuid",
        skip_serializing_if = "Option::is_none"
    )]
    pub peripheral_server_mode_uuid: Option<String>,

    /// Optional central client mode UUID
    #[serde(
        rename = "centralClientModeUuid",
        skip_serializing_if = "Option::is_none"
    )]
    pub central_client_mode_uuid: Option<String>,
}

impl BleOptions {
    /// Create BLE options with peripheral server mode
    pub fn peripheral_server(uuid: Option<String>) -> Self {
        Self {
            supports_peripheral_server_mode: true,
            supports_central_client_mode: false,
            peripheral_server_mode_uuid: uuid,
            central_client_mode_uuid: None,
        }
    }

    /// Create BLE options with central client mode
    pub fn central_client(uuid: Option<String>) -> Self {
        Self {
            supports_peripheral_server_mode: false,
            supports_central_client_mode: true,
            peripheral_server_mode_uuid: None,
            central_client_mode_uuid: uuid,
        }
    }

    /// Create BLE options supporting both modes
    pub fn dual_mode(peripheral_uuid: Option<String>, central_uuid: Option<String>) -> Self {
        Self {
            supports_peripheral_server_mode: true,
            supports_central_client_mode: true,
            peripheral_server_mode_uuid: peripheral_uuid,
            central_client_mode_uuid: central_uuid,
        }
    }
}

/// NFC (Near Field Communication) transport options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NfcOptions {
    /// Maximum length of command data field
    #[serde(rename = "maxLengthOfCommandDataField")]
    pub max_length_of_command_data_field: u32,

    /// Maximum length of response data field
    #[serde(rename = "maxLengthOfResponseDataField")]
    pub max_length_of_response_data_field: u32,

    /// Optional command data
    #[serde(rename = "commandData", skip_serializing_if = "Option::is_none")]
    pub command_data: Option<Vec<u8>>,
}

impl NfcOptions {
    /// Create NFC options with default field lengths
    pub fn new() -> Self {
        Self {
            max_length_of_command_data_field: 255,
            max_length_of_response_data_field: 256,
            command_data: None,
        }
    }

    /// Create NFC options with custom field lengths
    pub fn with_lengths(command_length: u32, response_length: u32) -> Self {
        Self {
            max_length_of_command_data_field: command_length,
            max_length_of_response_data_field: response_length,
            command_data: None,
        }
    }

    /// Set command data
    pub fn with_command_data(mut self, data: Vec<u8>) -> Self {
        self.command_data = Some(data);
        self
    }
}

impl Default for NfcOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// WiFi-Aware transport options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiOptions {
    /// WiFi-Aware service name
    #[serde(rename = "serviceName")]
    pub service_name: String,

    /// Optional passphrase for security
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,

    /// Optional channel information
    #[serde(rename = "channelInfo", skip_serializing_if = "Option::is_none")]
    pub channel_info: Option<HashMap<String, serde_json::Value>>,
}

impl WifiOptions {
    /// Create WiFi-Aware options with service name
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            passphrase: None,
            channel_info: None,
        }
    }

    /// Set passphrase for secure WiFi-Aware connection
    pub fn with_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }

    /// Set channel information
    pub fn with_channel_info(mut self, info: HashMap<String, serde_json::Value>) -> Self {
        self.channel_info = Some(info);
        self
    }
}

/// WebAPI transport options (HTTP/HTTPS endpoints)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebApiOptions {
    /// Base URL for the WebAPI endpoint
    #[serde(rename = "baseUrl")]
    pub base_url: String,

    /// Optional authentication token
    #[serde(rename = "authToken", skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    /// Optional custom headers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// Optional timeout in milliseconds
    #[serde(rename = "timeoutMs", skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl WebApiOptions {
    /// Create WebAPI options with base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth_token: None,
            headers: None,
            timeout_ms: None,
        }
    }

    /// Set authentication token
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Add a custom header
    pub fn add_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_peripheral_server() {
        let options = BleOptions::peripheral_server(Some("uuid-123".to_string()));
        assert!(options.supports_peripheral_server_mode);
        assert!(!options.supports_central_client_mode);
    }

    #[test]
    fn test_ble_central_client() {
        let options = BleOptions::central_client(Some("uuid-456".to_string()));
        assert!(!options.supports_peripheral_server_mode);
        assert!(options.supports_central_client_mode);
    }

    #[test]
    fn test_ble_dual_mode() {
        let options =
            BleOptions::dual_mode(Some("uuid-123".to_string()), Some("uuid-456".to_string()));
        assert!(options.supports_peripheral_server_mode);
        assert!(options.supports_central_client_mode);
    }

    #[test]
    fn test_nfc_default() {
        let options = NfcOptions::default();
        assert_eq!(options.max_length_of_command_data_field, 255);
        assert_eq!(options.max_length_of_response_data_field, 256);
    }

    #[test]
    fn test_nfc_custom_lengths() {
        let options = NfcOptions::with_lengths(512, 1024);
        assert_eq!(options.max_length_of_command_data_field, 512);
        assert_eq!(options.max_length_of_response_data_field, 1024);
    }

    #[test]
    fn test_wifi_options() {
        let options = WifiOptions::new("mdoc-service").with_passphrase("secret123");

        assert_eq!(options.service_name, "mdoc-service");
        assert_eq!(options.passphrase, Some("secret123".to_string()));
    }

    #[test]
    fn test_webapi_options() {
        let options = WebApiOptions::new("https://example.com/api")
            .with_auth_token("bearer-token")
            .add_header("X-Custom", "value")
            .with_timeout(5000);

        assert_eq!(options.base_url, "https://example.com/api");
        assert_eq!(options.auth_token, Some("bearer-token".to_string()));
        assert_eq!(options.timeout_ms, Some(5000));
        assert!(options.headers.is_some());
    }

    #[test]
    fn test_device_retrieval_methods() {
        let ble_method =
            DeviceRetrievalMethods::ble(BleOptions::peripheral_server(Some("uuid".to_string())));
        assert_eq!(ble_method.transport_type, TransportType::Ble);

        let nfc_method = DeviceRetrievalMethods::nfc(NfcOptions::default());
        assert_eq!(nfc_method.transport_type, TransportType::Nfc);

        let wifi_method = DeviceRetrievalMethods::wifi(WifiOptions::new("service"));
        assert_eq!(wifi_method.transport_type, TransportType::Wifi);

        let webapi_method =
            DeviceRetrievalMethods::web_api(WebApiOptions::new("https://api.example.com"));
        assert_eq!(webapi_method.transport_type, TransportType::WebApi);
    }
}
