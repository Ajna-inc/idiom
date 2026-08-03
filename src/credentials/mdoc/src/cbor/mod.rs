//! CBOR encoding/decoding utilities for mDoc structures

use crate::error::Result;
use ciborium::value::Value;
use std::io::Cursor;

/// Encode a value to CBOR bytes
pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Decode CBOR bytes to a value
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(ciborium::de::from_reader(Cursor::new(bytes))?)
}

/// Convert serde_json::Value to ciborium::Value
pub fn json_to_cbor(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_cbor).collect()),
        serde_json::Value::Object(obj) => {
            let map: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor(v)))
                .collect();
            Value::Map(map)
        }
    }
}

/// Convert ciborium::Value to serde_json::Value
pub fn cbor_to_json(cbor: &Value) -> serde_json::Value {
    match cbor {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            let i128_val = i128::from(*i);
            if let Ok(i64_val) = TryInto::<i64>::try_into(i128_val) {
                serde_json::Value::Number(i64_val.into())
            } else {
                serde_json::Value::Null
            }
        }
        Value::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(*f) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::Null
            }
        }
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => {
            // Encode bytes as base64 string
            use base64::Engine;
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(cbor_to_json).collect()),
        Value::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| {
                    if let Value::Text(key) = k {
                        Some((key.clone(), cbor_to_json(v)))
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_to_cbor_roundtrip() {
        let json = json!({
            "name": "Alice",
            "age": 30,
            "active": true
        });

        let cbor = json_to_cbor(&json);
        let back_to_json = cbor_to_json(&cbor);

        assert_eq!(json, back_to_json);
    }

    #[test]
    fn test_encode_decode() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            name: String,
            value: i32,
        }

        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
        };

        let bytes = encode(&original).unwrap();
        let decoded: TestStruct = decode(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
