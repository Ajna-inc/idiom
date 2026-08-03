//! Comprehensive unit tests for CBOR Tag 24 functionality
//!
//! Tests cover:
//! - Tag 24 wrapping/unwrapping for IssuerSignedItem
//! - Integer key normalization (ISO 18013-5 compact labels)
//! - Map-level vs item-level tag 24 wrapping
//! - Backwards compatibility with non-tagged formats
//! - Edge cases and error handling

use ciborium::Value;
use mdoc::cbor_tag24::normalize_issuer_signed_item_keys;
use mdoc::IssuerSignedItem;
use std::collections::HashMap;

#[test]
fn test_normalize_integer_keys_to_text() {
    // Create a CBOR map with integer keys (ISO 18013-5 compact form)
    let map = vec![
        (Value::Integer(0.into()), Value::Integer(42.into())), // digestID
        (Value::Integer(1.into()), Value::Bytes(vec![1, 2, 3])), // random
        (
            Value::Integer(2.into()),
            Value::Text("family_name".to_string()),
        ), // elementIdentifier
        (Value::Integer(3.into()), Value::Text("Doe".to_string())), // elementValue
    ];

    let mut value = Value::Map(map.clone());

    // Normalize keys
    normalize_issuer_signed_item_keys(&mut value);

    // Verify keys are now text
    if let Value::Map(normalized_map) = value {
        let keys: Vec<String> = normalized_map
            .iter()
            .filter_map(|(k, _v)| {
                if let Value::Text(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        assert!(keys.contains(&"digestID".to_string()));
        assert!(keys.contains(&"random".to_string()));
        assert!(keys.contains(&"elementIdentifier".to_string()));
        assert!(keys.contains(&"elementValue".to_string()));
        assert_eq!(keys.len(), 4);
    } else {
        panic!("Expected Map after normalization");
    }
}

#[test]
fn test_normalize_preserves_text_keys() {
    // Create a CBOR map with text keys (already in correct form)
    let map = vec![
        (
            Value::Text("digestID".to_string()),
            Value::Integer(42.into()),
        ),
        (
            Value::Text("random".to_string()),
            Value::Bytes(vec![1, 2, 3]),
        ),
        (
            Value::Text("elementIdentifier".to_string()),
            Value::Text("family_name".to_string()),
        ),
        (
            Value::Text("elementValue".to_string()),
            Value::Text("Doe".to_string()),
        ),
    ];

    let mut value = Value::Map(map.clone());
    let original_len = 4;

    // Normalize should not change text keys
    normalize_issuer_signed_item_keys(&mut value);

    if let Value::Map(normalized_map) = value {
        assert_eq!(normalized_map.len(), original_len);

        let keys: Vec<String> = normalized_map
            .iter()
            .filter_map(|(k, _v)| {
                if let Value::Text(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(keys.len(), 4);
    } else {
        panic!("Expected Map after normalization");
    }
}

#[test]
fn test_normalize_handles_mixed_keys() {
    // Create a CBOR map with mixed integer and text keys
    let map = vec![
        (Value::Integer(0.into()), Value::Integer(42.into())), // digestID as int
        (
            Value::Text("random".to_string()),
            Value::Bytes(vec![1, 2, 3]),
        ), // random as text
        (
            Value::Integer(2.into()),
            Value::Text("family_name".to_string()),
        ), // elementIdentifier as int
        (
            Value::Text("elementValue".to_string()),
            Value::Text("Doe".to_string()),
        ), // elementValue as text
    ];

    let mut value = Value::Map(map);

    normalize_issuer_signed_item_keys(&mut value);

    if let Value::Map(normalized_map) = value {
        // All keys should now be text
        for (k, _v) in &normalized_map {
            assert!(
                matches!(k, Value::Text(_)),
                "All keys should be text after normalization"
            );
        }

        assert_eq!(normalized_map.len(), 4);
    } else {
        panic!("Expected Map after normalization");
    }
}

#[test]
fn test_normalize_skips_unknown_integer_keys() {
    // Create a CBOR map with unknown integer key (should be skipped)
    let map = vec![
        (Value::Integer(0.into()), Value::Integer(42.into())), // digestID - valid
        (
            Value::Integer(99.into()),
            Value::Text("unknown".to_string()),
        ), // unknown key
        (
            Value::Integer(2.into()),
            Value::Text("family_name".to_string()),
        ), // elementIdentifier - valid
    ];

    let mut value = Value::Map(map);

    normalize_issuer_signed_item_keys(&mut value);

    if let Value::Map(normalized_map) = value {
        // Should only have 2 entries (unknown key skipped)
        assert_eq!(normalized_map.len(), 2);

        let keys: Vec<String> = normalized_map
            .iter()
            .filter_map(|(k, _v)| {
                if let Value::Text(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        assert!(keys.contains(&"digestID".to_string()));
        assert!(keys.contains(&"elementIdentifier".to_string()));
        assert!(!keys.contains(&"unknown".to_string()));
    } else {
        panic!("Expected Map after normalization");
    }
}

#[test]
fn test_tag24_hashmap_deserialize_with_integer_keys() {
    // This test verifies the integer key normalization works correctly
    // We test it through the IssuerSigned structure which uses our custom deserializer

    use mdoc::IssuerSigned;

    // First, create an IssuerSignedItem with integer keys
    let item_map = vec![
        (Value::Integer(0.into()), Value::Integer(1.into())), // digestID = 1
        (Value::Integer(1.into()), Value::Bytes(vec![0xaa, 0xbb])), // random
        (
            Value::Integer(2.into()),
            Value::Text("family_name".to_string()),
        ), // elementIdentifier
        (Value::Integer(3.into()), Value::Text("Smith".to_string())), // elementValue
    ];

    // Encode this map as CBOR bytes
    let mut item_cbor = Vec::new();
    ciborium::ser::into_writer(&Value::Map(item_map), &mut item_cbor).unwrap();

    // Wrap in tag 24
    let tagged_item = Value::Tag(24, Box::new(Value::Bytes(item_cbor)));

    // Create issuerAuth (mock COSE_Sign1 array)
    let issuer_auth = Value::Array(vec![
        Value::Bytes(vec![]), // protected
        Value::Map(vec![]),   // unprotected
        Value::Bytes(vec![]), // payload
        Value::Bytes(vec![]), // signature
    ]);

    // Create IssuerSigned structure
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".to_string()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".to_string()),
                Value::Array(vec![tagged_item]),
            )]),
        ),
        (Value::Text("issuerAuth".to_string()), issuer_auth),
    ]);

    // Serialize to CBOR
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&issuer_signed, &mut cbor_bytes).unwrap();

    // Deserialize as IssuerSigned (which uses our custom deserializer)
    let result: Result<IssuerSigned, _> = ciborium::de::from_reader(&cbor_bytes[..]);

    // Should successfully deserialize despite integer keys
    assert!(
        result.is_ok(),
        "Should deserialize items with integer keys: {:?}",
        result.err()
    );

    let issuer_signed = result.unwrap();
    assert_eq!(issuer_signed.name_spaces.len(), 1);
    assert!(issuer_signed.name_spaces.contains_key("org.iso.18013.5.1"));

    let items = &issuer_signed.name_spaces["org.iso.18013.5.1"];
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].digest_id, 1);
    assert_eq!(items[0].element_identifier, "family_name");
}

#[test]
fn test_tag24_backwards_compatibility_no_tag() {
    // Test that we can still deserialize items that are NOT wrapped in tag 24
    // (backwards compatibility)

    // Create an IssuerSignedItem with text keys (NOT wrapped in tag 24)
    let item_map = vec![
        (
            Value::Text("digestID".to_string()),
            Value::Integer(2.into()),
        ),
        (
            Value::Text("random".to_string()),
            Value::Bytes(vec![0xcc, 0xdd]),
        ),
        (
            Value::Text("elementIdentifier".to_string()),
            Value::Text("given_name".to_string()),
        ),
        (
            Value::Text("elementValue".to_string()),
            Value::Text("John".to_string()),
        ),
    ];

    // Create nameSpaces structure WITHOUT tag 24 wrapping
    let namespaces = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".to_string()),
        Value::Array(vec![Value::Map(item_map)]),
    )]);

    // Serialize to CBOR
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&namespaces, &mut cbor_bytes).unwrap();

    // Deserialize
    let result: Result<HashMap<String, Vec<IssuerSignedItem>>, _> =
        ciborium::de::from_reader(&cbor_bytes[..]);

    assert!(
        result.is_ok(),
        "Should support non-tagged items for backwards compatibility"
    );

    let map = result.unwrap();
    let items = &map["org.iso.18013.5.1"];
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].digest_id, 2);
    assert_eq!(items[0].element_identifier, "given_name");
}

#[test]
fn test_maybe_tag24_map_with_wrapping() {
    // Test map-level tag 24 wrapping (used for DeviceSigned.nameSpaces)
    // We test this through DeviceSigned structure which uses deserialize_maybe_tag24_map

    use mdoc::DeviceSigned;

    // Create a DeviceSignedItem
    let item_map = vec![
        (
            Value::Text("digestID".to_string()),
            Value::Integer(1.into()),
        ),
        (Value::Text("random".to_string()), Value::Bytes(vec![0xaa])),
        (
            Value::Text("elementIdentifier".to_string()),
            Value::Text("test_item".to_string()),
        ),
        (
            Value::Text("elementValue".to_string()),
            Value::Text("test_value".to_string()),
        ),
    ];

    // Create inner nameSpaces map
    let inner_namespaces = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".to_string()),
        Value::Array(vec![Value::Map(item_map)]),
    )]);

    // Encode inner map as CBOR
    let mut inner_cbor = Vec::new();
    ciborium::ser::into_writer(&inner_namespaces, &mut inner_cbor).unwrap();

    // Wrap entire nameSpaces map in tag 24
    let wrapped = Value::Tag(24, Box::new(Value::Bytes(inner_cbor)));

    // Create deviceAuth (mock COSE_Sign1 signature)
    let device_auth = Value::Map(vec![(
        Value::Text("deviceSignature".to_string()),
        Value::Array(vec![
            Value::Bytes(vec![]), // protected
            Value::Map(vec![]),   // unprotected
            Value::Bytes(vec![]), // payload
            Value::Bytes(vec![]), // signature
        ]),
    )]);

    // Create DeviceSigned structure
    let device_signed = Value::Map(vec![
        (Value::Text("nameSpaces".to_string()), wrapped),
        (Value::Text("deviceAuth".to_string()), device_auth),
    ]);

    // Serialize
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&device_signed, &mut cbor_bytes).unwrap();

    // Deserialize through DeviceSigned
    let result: Result<DeviceSigned, _> = ciborium::de::from_reader(&cbor_bytes[..]);

    assert!(
        result.is_ok(),
        "Should deserialize map wrapped in tag 24: {:?}",
        result.err()
    );

    let device_signed = result.unwrap();
    assert_eq!(device_signed.name_spaces.len(), 1);
    assert!(device_signed.name_spaces.contains_key("org.iso.18013.5.1"));

    let items = &device_signed.name_spaces["org.iso.18013.5.1"];
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].element_identifier, "test_item");
}

#[test]
fn test_maybe_tag24_map_without_wrapping() {
    // Test backwards compatibility - direct map without tag 24

    let inner_map: HashMap<String, Vec<String>> =
        vec![("key1".to_string(), vec!["value1".to_string()])]
            .into_iter()
            .collect();

    // Serialize directly without tag 24
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&inner_map, &mut cbor_bytes).unwrap();

    // Deserialize
    let result: Result<HashMap<String, Vec<String>>, _> =
        ciborium::de::from_reader(&cbor_bytes[..]);

    assert!(result.is_ok(), "Should handle non-wrapped maps");

    let map = result.unwrap();
    assert_eq!(map["key1"], vec!["value1"]);
}

#[test]
fn test_multiple_items_with_tag24() {
    // Test deserializing multiple tag 24 wrapped items in an array
    // We test this through IssuerSigned which uses our custom deserializer

    use mdoc::IssuerSigned;

    // Create two items with different keys (one integer, one text)
    let item1_map = vec![
        (Value::Integer(0.into()), Value::Integer(1.into())),
        (Value::Integer(1.into()), Value::Bytes(vec![0x11])),
        (Value::Integer(2.into()), Value::Text("item1".to_string())),
        (Value::Integer(3.into()), Value::Text("value1".to_string())),
    ];

    let item2_map = vec![
        (
            Value::Text("digestID".to_string()),
            Value::Integer(2.into()),
        ),
        (Value::Text("random".to_string()), Value::Bytes(vec![0x22])),
        (
            Value::Text("elementIdentifier".to_string()),
            Value::Text("item2".to_string()),
        ),
        (
            Value::Text("elementValue".to_string()),
            Value::Text("value2".to_string()),
        ),
    ];

    // Encode and wrap each item
    let mut item1_cbor = Vec::new();
    ciborium::ser::into_writer(&Value::Map(item1_map), &mut item1_cbor).unwrap();
    let tagged_item1 = Value::Tag(24, Box::new(Value::Bytes(item1_cbor)));

    let mut item2_cbor = Vec::new();
    ciborium::ser::into_writer(&Value::Map(item2_map), &mut item2_cbor).unwrap();
    let tagged_item2 = Value::Tag(24, Box::new(Value::Bytes(item2_cbor)));

    // Create issuerAuth (mock COSE_Sign1 array)
    let issuer_auth = Value::Array(vec![
        Value::Bytes(vec![]), // protected
        Value::Map(vec![]),   // unprotected
        Value::Bytes(vec![]), // payload
        Value::Bytes(vec![]), // signature
    ]);

    // Create IssuerSigned structure with both items
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".to_string()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".to_string()),
                Value::Array(vec![tagged_item1, tagged_item2]),
            )]),
        ),
        (Value::Text("issuerAuth".to_string()), issuer_auth),
    ]);

    // Serialize and deserialize
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&issuer_signed, &mut cbor_bytes).unwrap();

    let result: Result<IssuerSigned, _> = ciborium::de::from_reader(&cbor_bytes[..]);

    assert!(
        result.is_ok(),
        "Should deserialize multiple tagged items: {:?}",
        result.err()
    );

    let issuer_signed = result.unwrap();
    let items = &issuer_signed.name_spaces["org.iso.18013.5.1"];
    assert_eq!(items.len(), 2);

    // Verify both items deserialized correctly
    assert_eq!(items[0].digest_id, 1);
    assert_eq!(items[0].element_identifier, "item1");
    assert_eq!(items[1].digest_id, 2);
    assert_eq!(items[1].element_identifier, "item2");
}

#[test]
fn test_empty_namespaces() {
    // Test deserializing empty nameSpaces map
    let empty_map: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&empty_map, &mut cbor_bytes).unwrap();

    let result: Result<HashMap<String, Vec<IssuerSignedItem>>, _> =
        ciborium::de::from_reader(&cbor_bytes[..]);

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

#[test]
fn test_element_value_preserves_cbor_types() {
    // Test that element_value using ciborium::Value preserves all CBOR types
    // We test this through IssuerSigned which uses our custom deserializer

    use mdoc::IssuerSigned;

    // Create items with different CBOR value types
    let items_data = vec![
        ("bool_item", Value::Bool(true)),
        ("int_item", Value::Integer(42.into())),
        ("text_item", Value::Text("hello".to_string())),
        ("bytes_item", Value::Bytes(vec![1, 2, 3])),
        (
            "array_item",
            Value::Array(vec![Value::Integer(1.into()), Value::Integer(2.into())]),
        ),
    ];

    for (identifier, value) in items_data {
        let item_map = vec![
            (
                Value::Text("digestID".to_string()),
                Value::Integer(0.into()),
            ),
            (Value::Text("random".to_string()), Value::Bytes(vec![0xff])),
            (
                Value::Text("elementIdentifier".to_string()),
                Value::Text(identifier.to_string()),
            ),
            (Value::Text("elementValue".to_string()), value.clone()),
        ];

        // Encode and wrap item
        let mut item_cbor = Vec::new();
        ciborium::ser::into_writer(&Value::Map(item_map), &mut item_cbor).unwrap();
        let tagged = Value::Tag(24, Box::new(Value::Bytes(item_cbor)));

        // Create issuerAuth (mock COSE_Sign1 array)
        let issuer_auth = Value::Array(vec![
            Value::Bytes(vec![]), // protected
            Value::Map(vec![]),   // unprotected
            Value::Bytes(vec![]), // payload
            Value::Bytes(vec![]), // signature
        ]);

        // Create IssuerSigned structure
        let issuer_signed = Value::Map(vec![
            (
                Value::Text("nameSpaces".to_string()),
                Value::Map(vec![(
                    Value::Text("test".to_string()),
                    Value::Array(vec![tagged]),
                )]),
            ),
            (Value::Text("issuerAuth".to_string()), issuer_auth),
        ]);

        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&issuer_signed, &mut cbor_bytes).unwrap();

        let result: Result<IssuerSigned, _> = ciborium::de::from_reader(&cbor_bytes[..]);

        assert!(
            result.is_ok(),
            "Failed for {}: {:?}",
            identifier,
            result.err()
        );

        let issuer_signed = result.unwrap();
        let item = &issuer_signed.name_spaces["test"][0];

        // Verify element_value preserved the type
        match (&value, &item.element_value) {
            (Value::Bool(expected), Value::Bool(actual)) => assert_eq!(expected, actual),
            (Value::Integer(_), Value::Integer(_)) => {} // Just check type preserved
            (Value::Text(expected), Value::Text(actual)) => assert_eq!(expected, actual),
            (Value::Bytes(expected), Value::Bytes(actual)) => assert_eq!(expected, actual),
            (Value::Array(_), Value::Array(_)) => {} // Just check type preserved
            _ => panic!("Type not preserved for {}", identifier),
        }
    }
}
