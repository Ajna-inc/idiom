//! CBOR encoding/decoding for mDoc structures

use serde_cbor::Value as CborValue;
use std::collections::BTreeMap;

use super::types::*;

/// Error types for mDoc encoding/decoding
#[derive(Debug, thiserror::Error)]
pub enum MdocEncodingError {
    #[error("CBOR encoding error: {0}")]
    CborEncoding(#[from] serde_cbor::Error),

    #[error("Invalid structure: {0}")]
    InvalidStructure(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid data type: expected {expected}, got {actual}")]
    InvalidDataType { expected: String, actual: String },
}

/// CBOR encoder/decoder for mDoc
pub struct MdocEncoder;

impl MdocEncoder {
    /// Helper to extract text from CBOR value
    fn get_text(value: &CborValue) -> Option<&str> {
        match value {
            CborValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Helper to extract integer from CBOR value
    fn get_integer(value: &CborValue) -> Option<i128> {
        match value {
            CborValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Helper to extract array from CBOR value
    fn get_array(value: &CborValue) -> Option<&Vec<CborValue>> {
        match value {
            CborValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Helper to extract bytes from CBOR value
    fn get_bytes(value: &CborValue) -> Option<&Vec<u8>> {
        match value {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Encode an mDoc to CBOR bytes
    pub fn encode_mdoc(mdoc: &MDoc) -> Result<Vec<u8>, MdocEncodingError> {
        let cbor_value = Self::mdoc_to_cbor(mdoc)?;
        let bytes = serde_cbor::to_vec(&cbor_value)?;
        Ok(bytes)
    }

    /// Decode CBOR bytes to an mDoc
    pub fn decode_mdoc(bytes: &[u8]) -> Result<MDoc, MdocEncodingError> {
        let cbor_value: CborValue = serde_cbor::from_slice(bytes)?;
        Self::cbor_to_mdoc(&cbor_value)
    }

    /// Convert mDoc to CBOR value
    fn mdoc_to_cbor(mdoc: &MDoc) -> Result<CborValue, MdocEncodingError> {
        let mut map = BTreeMap::new();

        // Doc type
        map.insert(
            CborValue::Text("docType".to_string()),
            CborValue::Text(mdoc.doc_type.clone()),
        );

        // Version
        map.insert(
            CborValue::Text("version".to_string()),
            CborValue::Text(mdoc.version.clone()),
        );

        // Status
        map.insert(
            CborValue::Text("status".to_string()),
            CborValue::Integer(mdoc.status as i128),
        );

        // Issuer signed
        map.insert(
            CborValue::Text("issuerSigned".to_string()),
            Self::issuer_signed_to_cbor(&mdoc.issuer_signed)?,
        );

        // Device signed (optional)
        if let Some(device_signed) = &mdoc.device_signed {
            map.insert(
                CborValue::Text("deviceSigned".to_string()),
                Self::device_signed_to_cbor(device_signed)?,
            );
        }

        Ok(CborValue::Map(map))
    }

    /// Convert CBOR value to mDoc
    fn cbor_to_mdoc(value: &CborValue) -> Result<MDoc, MdocEncodingError> {
        let map = match value {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "Expected map".to_string(),
                ))
            }
        };

        let doc_type = map
            .get(&CborValue::Text("docType".to_string()))
            .and_then(|v| Self::get_text(v))
            .ok_or_else(|| MdocEncodingError::MissingField("docType".to_string()))?
            .to_string();

        let version = map
            .get(&CborValue::Text("version".to_string()))
            .and_then(|v| Self::get_text(v))
            .unwrap_or("1.0")
            .to_string();

        let status = map
            .get(&CborValue::Text("status".to_string()))
            .and_then(Self::get_integer)
            .unwrap_or(0) as u8;

        let issuer_signed_cbor = map
            .get(&CborValue::Text("issuerSigned".to_string()))
            .ok_or_else(|| MdocEncodingError::MissingField("issuerSigned".to_string()))?;
        let issuer_signed = Self::cbor_to_issuer_signed(issuer_signed_cbor)?;

        let device_signed = map
            .get(&CborValue::Text("deviceSigned".to_string()))
            .map(Self::cbor_to_device_signed)
            .transpose()?;

        Ok(MDoc {
            doc_type,
            version,
            issuer_signed,
            device_signed,
            status,
        })
    }

    /// Convert IssuerSigned to CBOR
    fn issuer_signed_to_cbor(issuer_signed: &IssuerSigned) -> Result<CborValue, MdocEncodingError> {
        let mut map = BTreeMap::new();

        // Name spaces
        let mut ns_map = BTreeMap::new();
        for (ns_name, items) in &issuer_signed.name_spaces {
            let items_array: Vec<CborValue> = items
                .iter()
                .map(Self::issuer_signed_item_to_cbor)
                .collect::<Result<Vec<_>, _>>()?;

            ns_map.insert(
                CborValue::Text(ns_name.clone()),
                CborValue::Array(items_array),
            );
        }
        map.insert(
            CborValue::Text("nameSpaces".to_string()),
            CborValue::Map(ns_map),
        );

        // Issuer auth (raw CBOR bytes)
        map.insert(
            CborValue::Text("issuerAuth".to_string()),
            CborValue::Bytes(issuer_signed.issuer_auth.clone()),
        );

        Ok(CborValue::Map(map))
    }

    /// Convert CBOR to IssuerSigned
    fn cbor_to_issuer_signed(value: &CborValue) -> Result<IssuerSigned, MdocEncodingError> {
        let map = match value {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "Expected map".to_string(),
                ))
            }
        };

        // Parse namespaces
        let ns_cbor = map
            .get(&CborValue::Text("nameSpaces".to_string()))
            .ok_or_else(|| MdocEncodingError::MissingField("nameSpaces".to_string()))?;
        let ns_map = match ns_cbor {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "nameSpaces must be map".to_string(),
                ))
            }
        };

        let mut name_spaces = std::collections::HashMap::new();
        for (ns_name, ns_items) in ns_map {
            let ns_name_str = Self::get_text(ns_name)
                .ok_or_else(|| {
                    MdocEncodingError::InvalidStructure("namespace name must be text".to_string())
                })?
                .to_string();

            let items_array = Self::get_array(ns_items).ok_or_else(|| {
                MdocEncodingError::InvalidStructure("namespace items must be array".to_string())
            })?;

            let items: Vec<IssuerSignedItem> = items_array
                .iter()
                .map(Self::cbor_to_issuer_signed_item)
                .collect::<Result<Vec<_>, _>>()?;

            name_spaces.insert(ns_name_str, items);
        }

        // Parse issuer auth
        let issuer_auth = map
            .get(&CborValue::Text("issuerAuth".to_string()))
            .and_then(|v| Self::get_bytes(v))
            .ok_or_else(|| MdocEncodingError::MissingField("issuerAuth".to_string()))?
            .to_vec();

        Ok(IssuerSigned {
            name_spaces,
            issuer_auth,
        })
    }

    /// Convert IssuerSignedItem to CBOR
    fn issuer_signed_item_to_cbor(item: &IssuerSignedItem) -> Result<CborValue, MdocEncodingError> {
        let mut map = BTreeMap::new();

        map.insert(
            CborValue::Text("digestID".to_string()),
            CborValue::Integer(item.digest_id as i128),
        );

        map.insert(
            CborValue::Text("random".to_string()),
            CborValue::Bytes(item.random.clone()),
        );

        map.insert(
            CborValue::Text("elementIdentifier".to_string()),
            CborValue::Text(item.element_identifier.clone()),
        );

        // Convert JSON value to CBOR value
        let element_value = Self::json_to_cbor(&item.element_value)?;
        map.insert(CborValue::Text("elementValue".to_string()), element_value);

        Ok(CborValue::Map(map))
    }

    /// Convert CBOR to IssuerSignedItem
    fn cbor_to_issuer_signed_item(
        value: &CborValue,
    ) -> Result<IssuerSignedItem, MdocEncodingError> {
        let map = match value {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "Expected map".to_string(),
                ))
            }
        };

        let digest_id = map
            .get(&CborValue::Text("digestID".to_string()))
            .and_then(Self::get_integer)
            .ok_or_else(|| MdocEncodingError::MissingField("digestID".to_string()))?
            as u32;

        let random = map
            .get(&CborValue::Text("random".to_string()))
            .and_then(|v| Self::get_bytes(v))
            .ok_or_else(|| MdocEncodingError::MissingField("random".to_string()))?
            .to_vec();

        let element_identifier = map
            .get(&CborValue::Text("elementIdentifier".to_string()))
            .and_then(|v| Self::get_text(v))
            .ok_or_else(|| MdocEncodingError::MissingField("elementIdentifier".to_string()))?
            .to_string();

        let element_value_cbor = map
            .get(&CborValue::Text("elementValue".to_string()))
            .ok_or_else(|| MdocEncodingError::MissingField("elementValue".to_string()))?;
        let element_value = Self::cbor_to_json(element_value_cbor)?;

        Ok(IssuerSignedItem {
            digest_id,
            random,
            element_identifier,
            element_value,
        })
    }

    /// Convert DeviceSigned to CBOR
    fn device_signed_to_cbor(device_signed: &DeviceSigned) -> Result<CborValue, MdocEncodingError> {
        let mut map = BTreeMap::new();

        // Name spaces (usually empty)
        map.insert(
            CborValue::Text("nameSpaces".to_string()),
            CborValue::Map(BTreeMap::new()),
        );

        // Device auth
        let device_auth_cbor = match &device_signed.device_auth {
            DeviceAuthPayload::DeviceSignature { device_signature } => {
                let mut auth_map = BTreeMap::new();
                auth_map.insert(
                    CborValue::Text("deviceSignature".to_string()),
                    CborValue::Bytes(device_signature.clone()),
                );
                CborValue::Map(auth_map)
            }
            DeviceAuthPayload::DeviceMac { device_mac } => {
                let mut auth_map = BTreeMap::new();
                auth_map.insert(
                    CborValue::Text("deviceMac".to_string()),
                    CborValue::Bytes(device_mac.clone()),
                );
                CborValue::Map(auth_map)
            }
        };

        map.insert(CborValue::Text("deviceAuth".to_string()), device_auth_cbor);

        Ok(CborValue::Map(map))
    }

    /// Convert CBOR to DeviceSigned
    fn cbor_to_device_signed(value: &CborValue) -> Result<DeviceSigned, MdocEncodingError> {
        let map = match value {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "Expected map".to_string(),
                ))
            }
        };

        let device_auth_cbor = map
            .get(&CborValue::Text("deviceAuth".to_string()))
            .ok_or_else(|| MdocEncodingError::MissingField("deviceAuth".to_string()))?;

        let device_auth_map = match device_auth_cbor {
            CborValue::Map(m) => m,
            _ => {
                return Err(MdocEncodingError::InvalidStructure(
                    "deviceAuth must be map".to_string(),
                ))
            }
        };

        let device_auth = if let Some(sig_bytes) =
            device_auth_map.get(&CborValue::Text("deviceSignature".to_string()))
        {
            let device_signature = Self::get_bytes(sig_bytes)
                .ok_or_else(|| {
                    MdocEncodingError::InvalidStructure("deviceSignature must be bytes".to_string())
                })?
                .to_vec();
            DeviceAuthPayload::DeviceSignature { device_signature }
        } else if let Some(mac_bytes) =
            device_auth_map.get(&CborValue::Text("deviceMac".to_string()))
        {
            let device_mac = Self::get_bytes(mac_bytes)
                .ok_or_else(|| {
                    MdocEncodingError::InvalidStructure("deviceMac must be bytes".to_string())
                })?
                .to_vec();
            DeviceAuthPayload::DeviceMac { device_mac }
        } else {
            return Err(MdocEncodingError::MissingField(
                "deviceSignature or deviceMac".to_string(),
            ));
        };

        Ok(DeviceSigned {
            name_spaces: std::collections::HashMap::new(),
            device_auth,
        })
    }

    /// Convert JSON value to CBOR value (simplified)
    fn json_to_cbor(json: &serde_json::Value) -> Result<CborValue, MdocEncodingError> {
        match json {
            serde_json::Value::Null => Ok(CborValue::Null),
            serde_json::Value::Bool(b) => Ok(CborValue::Bool(*b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(CborValue::Integer(i as i128))
                } else if let Some(f) = n.as_f64() {
                    Ok(CborValue::Float(f))
                } else {
                    Err(MdocEncodingError::InvalidDataType {
                        expected: "integer or float".to_string(),
                        actual: format!("{:?}", n),
                    })
                }
            }
            serde_json::Value::String(s) => Ok(CborValue::Text(s.clone())),
            serde_json::Value::Array(arr) => {
                let cbor_arr: Vec<CborValue> = arr
                    .iter()
                    .map(Self::json_to_cbor)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CborValue::Array(cbor_arr))
            }
            serde_json::Value::Object(obj) => {
                let mut cbor_map = BTreeMap::new();
                for (k, v) in obj {
                    cbor_map.insert(CborValue::Text(k.clone()), Self::json_to_cbor(v)?);
                }
                Ok(CborValue::Map(cbor_map))
            }
        }
    }

    /// Convert CBOR value to JSON value (simplified)
    fn cbor_to_json(cbor: &CborValue) -> Result<serde_json::Value, MdocEncodingError> {
        match cbor {
            CborValue::Null => Ok(serde_json::Value::Null),
            CborValue::Bool(b) => Ok(serde_json::Value::Bool(*b)),
            CborValue::Integer(i) => Ok(serde_json::json!(*i as i64)),
            CborValue::Float(f) => Ok(serde_json::json!(*f)),
            CborValue::Text(s) => Ok(serde_json::Value::String(s.clone())),
            CborValue::Bytes(b) => {
                // Encode bytes as base64 string
                Ok(serde_json::Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b,
                )))
            }
            CborValue::Array(arr) => {
                let json_arr: Vec<serde_json::Value> = arr
                    .iter()
                    .map(Self::cbor_to_json)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(serde_json::Value::Array(json_arr))
            }
            CborValue::Map(map) => {
                let mut json_obj = serde_json::Map::new();
                for (k, v) in map {
                    let key = Self::get_text(k).ok_or_else(|| {
                        MdocEncodingError::InvalidStructure("map key must be text".to_string())
                    })?;
                    json_obj.insert(key.to_string(), Self::cbor_to_json(v)?);
                }
                Ok(serde_json::Value::Object(json_obj))
            }
            _ => Err(MdocEncodingError::InvalidDataType {
                expected: "basic CBOR type".to_string(),
                actual: "complex type".to_string(),
            }),
        }
    }

    /// Encode Mobile Security Object to CBOR
    pub fn encode_mso(mso: &MobileSecurityObject) -> Result<Vec<u8>, MdocEncodingError> {
        let cbor_value = Self::mso_to_cbor(mso)?;
        let bytes = serde_cbor::to_vec(&cbor_value)?;
        Ok(bytes)
    }

    /// Convert MSO to CBOR
    fn mso_to_cbor(mso: &MobileSecurityObject) -> Result<CborValue, MdocEncodingError> {
        let mut map = BTreeMap::new();

        map.insert(
            CborValue::Text("version".to_string()),
            CborValue::Text(mso.version.clone()),
        );

        map.insert(
            CborValue::Text("digestAlgorithm".to_string()),
            CborValue::Text(mso.digest_algorithm.clone()),
        );

        // Value digests
        let mut vd_map = BTreeMap::new();
        for (ns, digests) in &mso.value_digests {
            let mut digest_map = BTreeMap::new();
            for (id, digest) in digests {
                digest_map.insert(
                    CborValue::Integer(*id as i128),
                    CborValue::Bytes(digest.clone()),
                );
            }
            vd_map.insert(CborValue::Text(ns.clone()), CborValue::Map(digest_map));
        }
        map.insert(
            CborValue::Text("valueDigests".to_string()),
            CborValue::Map(vd_map),
        );

        // Device key info
        let mut dki_map = BTreeMap::new();
        dki_map.insert(
            CborValue::Text("deviceKey".to_string()),
            CborValue::Bytes(mso.device_key_info.device_key.clone()),
        );
        map.insert(
            CborValue::Text("deviceKeyInfo".to_string()),
            CborValue::Map(dki_map),
        );

        map.insert(
            CborValue::Text("docType".to_string()),
            CborValue::Text(mso.doc_type.clone()),
        );

        map.insert(
            CborValue::Text("validFrom".to_string()),
            CborValue::Text(mso.valid_from.to_rfc3339()),
        );

        map.insert(
            CborValue::Text("validUntil".to_string()),
            CborValue::Text(mso.valid_until.to_rfc3339()),
        );

        Ok(CborValue::Map(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_mdoc() {
        let mut mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        let item = IssuerSignedItem {
            digest_id: 0,
            random: vec![1, 2, 3, 4],
            element_identifier: "family_name".to_string(),
            element_value: serde_json::json!("Doe"),
        };

        mdoc.add_issuer_signed_element(NAMESPACE_MDL.to_string(), item);

        // Encode
        let encoded = MdocEncoder::encode_mdoc(&mdoc).unwrap();
        assert!(!encoded.is_empty());

        // Decode
        let decoded = MdocEncoder::decode_mdoc(&encoded).unwrap();
        assert_eq!(decoded.doc_type, mdoc.doc_type);
        assert_eq!(decoded.version, mdoc.version);
        assert_eq!(decoded.status, mdoc.status);
    }

    #[test]
    fn test_json_to_cbor_conversion() {
        let json = serde_json::json!({
            "name": "Alice",
            "age": 30,
            "active": true
        });

        let cbor = MdocEncoder::json_to_cbor(&json).unwrap();
        let back_to_json = MdocEncoder::cbor_to_json(&cbor).unwrap();

        assert_eq!(back_to_json["name"], "Alice");
        assert_eq!(back_to_json["age"], 30);
        assert_eq!(back_to_json["active"], true);
    }
}
