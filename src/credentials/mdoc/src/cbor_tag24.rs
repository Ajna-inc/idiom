//! CBOR Tag 24 handling for IssuerSignedItem
//!
//! Real-world mDoc implementations encode IssuerSignedItem as CBOR tag 24
//! (encoded CBOR data item) per RFC 8949 section 3.4.5.1.
//!
//! Structure: Tag 24 -> Byte String -> CBOR-encoded IssuerSignedItem
//!
//! Example from Google Wallet:
//! - d8 18 = Tag 24
//! - 58 54 = Byte string (84 bytes)
//! - a4 68... = Map with 4 items (the actual IssuerSignedItem)

use ciborium::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

/// Wrapper for deserializing CBOR tag 24 encoded items
///
/// This handles the pattern: Tag(24, Bytes(cbor_encoded_item))
pub fn deserialize_tag24_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    // Deserialize as Vec<Value> to handle the tag 24 wrapper
    let values = Vec::<Value>::deserialize(deserializer)?;

    let mut items = Vec::with_capacity(values.len());

    for value in values {
        // Check if this is a tag 24 wrapped item
        match value {
            Value::Tag(24, boxed_value) => {
                // The inner value should be bytes containing CBOR
                if let Value::Bytes(cbor_bytes) = *boxed_value {
                    // Deserialize the inner CBOR
                    let item: T = ciborium::de::from_reader(&cbor_bytes[..])
                        .map_err(serde::de::Error::custom)?;
                    items.push(item);
                } else {
                    return Err(serde::de::Error::custom(
                        "Tag 24 must wrap bytes containing CBOR",
                    ));
                }
            }
            // Also support non-tagged items for backwards compatibility
            _ => {
                // Try to serialize back to bytes and deserialize as T
                let mut bytes = Vec::new();
                ciborium::ser::into_writer(&value, &mut bytes).map_err(serde::de::Error::custom)?;
                let item: T =
                    ciborium::de::from_reader(&bytes[..]).map_err(serde::de::Error::custom)?;
                items.push(item);
            }
        }
    }

    Ok(items)
}

/// Serialize items with CBOR tag 24 wrapping
///
/// This creates the pattern: Tag(24, Bytes(cbor_encoded_item))
pub fn serialize_tag24_vec<S, T>(items: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(items.len()))?;

    for item in items {
        // Encode the item as CBOR bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(item, &mut cbor_bytes).map_err(serde::ser::Error::custom)?;

        // Create Tag(24, Bytes(cbor))
        let tagged = Value::Tag(24, Box::new(Value::Bytes(cbor_bytes)));
        seq.serialize_element(&tagged)?;
    }

    seq.end()
}

/// Deserialize HashMap<String, Vec<T>> where Vec<T> items are tag 24 wrapped
///
/// This handles nameSpaces map in IssuerSigned
pub fn deserialize_tag24_hashmap<'de, D, T>(
    deserializer: D,
) -> Result<HashMap<String, Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    // Deserialize as HashMap<String, Value>
    let map = HashMap::<String, Value>::deserialize(deserializer)?;

    let mut result = HashMap::new();

    for (key, value) in map {
        // The value should be an array of tag 24 wrapped items
        if let Value::Array(values) = value {
            let mut items = Vec::with_capacity(values.len());

            for mut val in values {
                match &val {
                    Value::Tag(24, boxed_value) => {
                        // The inner value should be bytes containing CBOR
                        if let Value::Bytes(cbor_bytes) = &**boxed_value {
                            // Decode to Value first to normalize keys
                            let mut inner_value: Value = ciborium::de::from_reader(&cbor_bytes[..])
                                .map_err(serde::de::Error::custom)?;

                            // Normalize integer keys to text keys (for Ubique compatibility)
                            normalize_issuer_signed_item_keys(&mut inner_value);

                            // Now deserialize to T
                            let mut normalized_bytes = Vec::new();
                            ciborium::ser::into_writer(&inner_value, &mut normalized_bytes)
                                .map_err(serde::de::Error::custom)?;
                            let item: T = ciborium::de::from_reader(&normalized_bytes[..])
                                .map_err(serde::de::Error::custom)?;
                            items.push(item);
                        } else {
                            return Err(serde::de::Error::custom(
                                "Tag 24 must wrap bytes containing CBOR",
                            ));
                        }
                    }
                    // Also support non-tagged items for backwards compatibility
                    _ => {
                        // Normalize integer keys to text keys
                        normalize_issuer_signed_item_keys(&mut val);

                        // Try to serialize back to bytes and deserialize as T
                        let mut bytes = Vec::new();
                        ciborium::ser::into_writer(&val, &mut bytes)
                            .map_err(serde::de::Error::custom)?;
                        let item: T = ciborium::de::from_reader(&bytes[..])
                            .map_err(serde::de::Error::custom)?;
                        items.push(item);
                    }
                }
            }

            result.insert(key, items);
        } else {
            return Err(serde::de::Error::custom("nameSpaces values must be arrays"));
        }
    }

    Ok(result)
}

/// Serialize HashMap<String, Vec<T>> with tag 24 wrapping for values
pub fn serialize_tag24_hashmap<S, T>(
    map: &HashMap<String, Vec<T>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    use serde::ser::SerializeMap;

    let mut ser_map = serializer.serialize_map(Some(map.len()))?;

    for (key, items) in map {
        // Create array of tag 24 wrapped items
        let mut tagged_items = Vec::new();

        for item in items {
            // Encode the item as CBOR bytes
            let mut cbor_bytes = Vec::new();
            ciborium::ser::into_writer(item, &mut cbor_bytes).map_err(serde::ser::Error::custom)?;

            // Create Tag(24, Bytes(cbor))
            let tagged = Value::Tag(24, Box::new(Value::Bytes(cbor_bytes)));
            tagged_items.push(tagged);
        }

        ser_map.serialize_entry(key, &Value::Array(tagged_items))?;
    }

    ser_map.end()
}

/// Deserialize a HashMap that might be tag 24 wrapped as a whole
///
/// This handles: Tag(24, Bytes(cbor_encoded_map))
pub fn deserialize_maybe_tag24_map<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: for<'a> Deserialize<'a> + std::cmp::Eq + std::hash::Hash,
    V: for<'a> Deserialize<'a>,
{
    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Tag(24, boxed_value) => {
            // Extract bytes and decode as map
            if let Value::Bytes(cbor_bytes) = *boxed_value {
                let map: HashMap<K, V> =
                    ciborium::de::from_reader(&cbor_bytes[..]).map_err(serde::de::Error::custom)?;
                Ok(map)
            } else {
                Err(serde::de::Error::custom(
                    "Tag 24 must wrap bytes containing CBOR map",
                ))
            }
        }
        // Direct map (backwards compatibility)
        Value::Map(_) => {
            // Serialize back to bytes and deserialize as HashMap
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&value, &mut bytes).map_err(serde::de::Error::custom)?;
            let map: HashMap<K, V> =
                ciborium::de::from_reader(&bytes[..]).map_err(serde::de::Error::custom)?;
            Ok(map)
        }
        _ => Err(serde::de::Error::custom(
            "Expected map or tag 24 wrapped map",
        )),
    }
}

/// Serialize HashMap with optional tag 24 wrapping
pub fn serialize_maybe_tag24_map<S, K, V>(
    map: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    K: Serialize + std::cmp::Eq + std::hash::Hash,
    V: Serialize,
{
    // For now, just serialize as regular map
    // Can add tag 24 wrapping later if needed
    map.serialize(serializer)
}

/// Normalize CBOR map keys from integers to text for IssuerSignedItem
///
/// ISO 18013-5 allows both integer and text labels:
/// - 0 / "digestID"
/// - 1 / "random"
/// - 2 / "elementIdentifier"
/// - 3 / "elementValue"
///
/// This function converts integer keys to their text equivalents
pub fn normalize_issuer_signed_item_keys(value: &mut Value) {
    if let Value::Map(ref mut map) = value {
        let mut normalized_entries = Vec::new();

        for (key, val) in map.iter_mut() {
            let text_key = match key {
                Value::Integer(i) => {
                    let i64_val: i64 = match TryInto::<i64>::try_into(i128::from(*i)) {
                        Ok(v) => v,
                        Err(_) => continue, // Skip if conversion fails
                    };

                    match i64_val {
                        0 => Value::Text("digestID".to_string()),
                        1 => Value::Text("random".to_string()),
                        2 => Value::Text("elementIdentifier".to_string()),
                        3 => Value::Text("elementValue".to_string()),
                        _ => continue, // Skip unknown integer keys
                    }
                }
                Value::Text(_) => key.clone(), // Already text, keep as-is
                _ => continue,                 // Skip other key types
            };

            normalized_entries.push((text_key, val.clone()));
        }

        // Replace the map with normalized entries
        *map = normalized_entries;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestItem {
        #[serde(rename = "digestID")]
        digest_id: u32,
        random: Vec<u8>,
        #[serde(rename = "elementIdentifier")]
        element_identifier: String,
        #[serde(rename = "elementValue")]
        element_value: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestContainer {
        #[serde(
            deserialize_with = "deserialize_tag24_vec",
            serialize_with = "serialize_tag24_vec"
        )]
        items: Vec<TestItem>,
    }

    #[test]
    fn test_deserialize_tag24_wrapped_items() {
        // Create a test item
        let item = TestItem {
            digest_id: 0,
            random: vec![0x12, 0x34, 0x56],
            element_identifier: "test".to_string(),
            element_value: "value".to_string(),
        };

        // Encode the item as CBOR
        let mut item_cbor = Vec::new();
        ciborium::ser::into_writer(&item, &mut item_cbor).unwrap();

        // Create tag 24 wrapper
        let tagged = Value::Tag(24, Box::new(Value::Bytes(item_cbor)));
        let items_array = Value::Array(vec![tagged]);

        // Create container with the items field
        let container_value = Value::Map(vec![(Value::Text("items".to_string()), items_array)]);

        // Serialize to CBOR
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&container_value, &mut cbor).unwrap();

        // Deserialize
        let container: TestContainer = ciborium::de::from_reader(&cbor[..]).unwrap();

        assert_eq!(container.items.len(), 1);
        assert_eq!(container.items[0].digest_id, 0);
        assert_eq!(container.items[0].element_identifier, "test");
        assert_eq!(container.items[0].element_value, "value");
    }

    #[test]
    fn test_serialize_with_tag24() {
        let item = TestItem {
            digest_id: 1,
            random: vec![0xaa, 0xbb],
            element_identifier: "name".to_string(),
            element_value: "John".to_string(),
        };

        let container = TestContainer {
            items: vec![item.clone()],
        };

        // Serialize
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&container, &mut cbor).unwrap();

        // Deserialize back
        let decoded: TestContainer = ciborium::de::from_reader(&cbor[..]).unwrap();

        assert_eq!(decoded.items.len(), 1);
        assert_eq!(decoded.items[0], item);
    }

    #[test]
    fn test_backwards_compatibility_non_tagged() {
        // Create a test item without tag 24 wrapping
        let _item = TestItem {
            digest_id: 2,
            random: vec![0x01, 0x02],
            element_identifier: "age".to_string(),
            element_value: "25".to_string(),
        };

        // Create container without tag 24 wrapping (direct items)
        let items_array = Value::Array(vec![Value::Map(vec![
            (
                Value::Text("digestID".to_string()),
                Value::Integer(2.into()),
            ),
            (
                Value::Text("random".to_string()),
                Value::Bytes(vec![0x01, 0x02]),
            ),
            (
                Value::Text("elementIdentifier".to_string()),
                Value::Text("age".to_string()),
            ),
            (
                Value::Text("elementValue".to_string()),
                Value::Text("25".to_string()),
            ),
        ])]);

        let container_value = Value::Map(vec![(Value::Text("items".to_string()), items_array)]);

        // Serialize to CBOR
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&container_value, &mut cbor).unwrap();

        // Deserialize (should work without tag 24)
        let container: TestContainer = ciborium::de::from_reader(&cbor[..]).unwrap();

        assert_eq!(container.items.len(), 1);
        assert_eq!(container.items[0].digest_id, 2);
        assert_eq!(container.items[0].element_identifier, "age");
    }
}
