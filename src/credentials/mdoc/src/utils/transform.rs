//! Data transformation utilities for encoding/decoding

use crate::error::{MdocError, Result};
use base64::Engine;

/// Convert bytes to hexadecimal string (lowercase)
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert bytes to hexadecimal string (uppercase)
pub fn bytes_to_hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Convert hexadecimal string to bytes
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(Into::into)
}

/// Base64 encode bytes (standard encoding)
pub fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Base64 encode bytes (URL-safe encoding, no padding)
pub fn base64_encode_url_safe(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64 decode string (standard encoding)
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(Into::into)
}

/// Base64 decode string (URL-safe encoding, no padding)
pub fn base64_decode_url_safe(encoded: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(Into::into)
}

/// Convert CBOR value to JSON (for debugging/display)
pub fn cbor_to_json(cbor_bytes: &[u8]) -> Result<serde_json::Value> {
    let value: ciborium::Value = ciborium::de::from_reader(cbor_bytes)
        .map_err(|e| MdocError::Other(format!("Failed to parse CBOR: {}", e)))?;

    cbor_value_to_json(&value)
}

/// Convert ciborium::Value to serde_json::Value
fn cbor_value_to_json(value: &ciborium::Value) -> Result<serde_json::Value> {
    match value {
        ciborium::Value::Integer(i) => {
            let num = i128::from(*i);
            if let Ok(n) = i64::try_from(num) {
                Ok(serde_json::Value::Number(n.into()))
            } else {
                Ok(serde_json::Value::String(num.to_string()))
            }
        }
        ciborium::Value::Bytes(b) => Ok(serde_json::Value::String(base64_encode(b))),
        ciborium::Value::Text(s) => Ok(serde_json::Value::String(s.clone())),
        ciborium::Value::Array(arr) => {
            let json_arr: Result<Vec<_>> = arr.iter().map(cbor_value_to_json).collect();
            Ok(serde_json::Value::Array(json_arr?))
        }
        ciborium::Value::Map(map) => {
            let mut json_map = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    ciborium::Value::Text(s) => s.clone(),
                    ciborium::Value::Integer(i) => i128::from(*i).to_string(),
                    _ => format!("{:?}", k),
                };
                json_map.insert(key, cbor_value_to_json(v)?);
            }
            Ok(serde_json::Value::Object(json_map))
        }
        ciborium::Value::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        ciborium::Value::Null => Ok(serde_json::Value::Null),
        ciborium::Value::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(*f) {
                Ok(serde_json::Value::Number(num))
            } else {
                Err(MdocError::Other("Invalid float value".to_string()))
            }
        }
        ciborium::Value::Tag(_, value) => cbor_value_to_json(value),
        _ => Ok(serde_json::Value::String(format!("{:?}", value))),
    }
}

/// Pretty-print CBOR data as JSON (for debugging)
pub fn debug_cbor(cbor_bytes: &[u8]) -> String {
    match cbor_to_json(cbor_bytes) {
        Ok(json) => serde_json::to_string_pretty(&json)
            .unwrap_or_else(|_| "Failed to format JSON".to_string()),
        Err(e) => format!("Failed to parse CBOR: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encoding() {
        let bytes = vec![0x01, 0x02, 0xAB, 0xCD];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0102abcd");

        let hex_upper = bytes_to_hex_upper(&bytes);
        assert_eq!(hex_upper, "0102ABCD");
    }

    #[test]
    fn test_hex_decoding() {
        let hex = "0102abcd";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0xAB, 0xCD]);
    }

    #[test]
    fn test_base64_encoding() {
        let bytes = b"Hello, World!";
        let encoded = base64_encode(bytes);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_base64_url_safe() {
        let bytes = b"Hello+World/Test=";
        let encoded = base64_encode_url_safe(bytes);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        let decoded = base64_decode_url_safe(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_cbor_to_json_simple() {
        let value = ciborium::Value::Text("Hello".to_string());
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&value, &mut buffer).unwrap();

        let json = cbor_to_json(&buffer).unwrap();
        assert_eq!(json, serde_json::Value::String("Hello".to_string()));
    }

    #[test]
    fn test_cbor_to_json_map() {
        let map = vec![(
            ciborium::Value::Text("key".to_string()),
            ciborium::Value::Text("value".to_string()),
        )];
        let value = ciborium::Value::Map(map);

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&value, &mut buffer).unwrap();

        let json = cbor_to_json(&buffer).unwrap();
        assert!(json.is_object());
    }
}
