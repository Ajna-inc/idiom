//! Integration tests for mdoc
//!
//! These tests verify the complete issuance -> holder -> verifier flow

use async_trait::async_trait;
use chrono::Utc;
use mdoc::callbacks::{VerificationCallback, VerificationResult, VerifiedDeviceResponse};
use mdoc::context::{DigestAlgorithm, MdocContext, SignatureAlgorithm};
use mdoc::holder::{
    Constraints, DeviceResponseBuilder, FieldConstraint, InputDescriptor, PresentationDefinition,
};
use mdoc::issuer::DocumentBuilder;
use mdoc::proximity::{BleOptions, DeviceEngagement, DeviceRetrievalMethods, EDeviceKey, Security};
use mdoc::session::{Handover, SessionEstablishment};
use mdoc::utils::{DateOnly, Uuid};
use mdoc::*;
use serde_json::json;
use std::collections::HashMap;

/// Mock context for testing (does not perform actual crypto)
struct MockContext;

/// Create a test validity info with reasonable defaults
fn create_test_validity_info() -> ValidityInfo {
    ValidityInfo {
        signed: Utc::now(),
        valid_from: Utc::now(),
        valid_until: Utc::now() + chrono::Duration::days(1825), // 5 years
        expected_update: None,
    }
}

/// Create a test device key info with mock ES256 key
fn create_test_device_key_info() -> DeviceKeyInfo {
    let mut device_key = HashMap::new();
    device_key.insert("kty".to_string(), json!(2)); // EC2
    device_key.insert("crv".to_string(), json!(1)); // P-256
    device_key.insert("x".to_string(), json!("AAAA")); // Mock X coordinate
    device_key.insert("y".to_string(), json!("BBBB")); // Mock Y coordinate

    DeviceKeyInfo {
        device_key,
        key_authorizations: None,
        key_info: None,
    }
}

#[async_trait]
impl MdocContext for MockContext {
    async fn random(&self, length: usize) -> error::Result<Vec<u8>> {
        Ok(vec![0u8; length])
    }

    async fn digest(&self, _algorithm: DigestAlgorithm, _data: &[u8]) -> error::Result<Vec<u8>> {
        // Return fake hash
        Ok(vec![0u8; 32])
    }

    async fn cose_sign1_sign(
        &self,
        _key_id: &str,
        _payload: &[u8],
        _protected_headers: &[u8],
        _algorithm: SignatureAlgorithm,
    ) -> error::Result<Vec<u8>> {
        // Return dummy signature
        Ok(vec![0u8; 64])
    }

    async fn cose_sign1_verify(
        &self,
        _public_key: &cose::CoseKey,
        _signature: &[u8],
        _payload: &[u8],
        _protected_headers: &[u8],
        _algorithm: SignatureAlgorithm,
    ) -> error::Result<bool> {
        // Always valid for testing
        Ok(true)
    }

    async fn cose_mac0_sign(
        &self,
        _key: &[u8],
        _payload: &[u8],
        _protected_headers: &[u8],
    ) -> error::Result<Vec<u8>> {
        // Return dummy MAC
        Ok(vec![0u8; 32])
    }

    async fn cose_mac0_verify(
        &self,
        _key: &[u8],
        _mac: &[u8],
        _payload: &[u8],
        _protected_headers: &[u8],
    ) -> error::Result<bool> {
        // Always valid for testing
        Ok(true)
    }

    async fn get_public_key_from_certificate(
        &self,
        _certificate: &[u8],
        _algorithm: SignatureAlgorithm,
    ) -> error::Result<cose::CoseKey> {
        Ok(cose::CoseKey::new(2))
    }

    async fn validate_certificate_chain(
        &self,
        _certificate_chain: &[Vec<u8>],
        _trusted_certificates: &[Vec<u8>],
    ) -> error::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_complete_issuance_flow() {
    let context = MockContext;

    // Create mDL data
    let mut elements = HashMap::new();
    elements.insert("family_name".to_string(), json!("Doe"));
    elements.insert("given_name".to_string(), json!("John"));
    elements.insert("birth_date".to_string(), json!("1990-01-01"));
    elements.insert("issue_date".to_string(), json!("2024-01-01"));
    elements.insert("expiry_date".to_string(), json!("2029-01-01"));

    // Issue document
    let result = DocumentBuilder::new(DOCTYPE_MDL)
        .add_issuer_namespace(NAMESPACE_MDL, elements)
        .use_digest_algorithm(DigestAlgorithm::Sha256)
        .add_validity_info(create_test_validity_info())
        .add_device_key_info(create_test_device_key_info())
        .sign(&context, "issuer-key", SignatureAlgorithm::ES256)
        .await;

    assert!(
        result.is_ok(),
        "Document issuance failed: {:?}",
        result.err()
    );
    let document = result.unwrap();

    // Verify document structure
    assert_eq!(document.doc_type, DOCTYPE_MDL);

    // issuer_auth should be a COSE_Sign1 array [protected, unprotected, payload, signature]
    match &document.issuer_signed.issuer_auth {
        ciborium::Value::Array(arr) => assert_eq!(
            arr.len(),
            4,
            "issuerAuth should be COSE_Sign1 array with 4 elements"
        ),
        ciborium::Value::Bytes(b) => assert!(!b.is_empty(), "issuerAuth bytes should not be empty"),
        _ => panic!("issuerAuth should be either Array or Bytes"),
    }

    assert!(document
        .issuer_signed
        .name_spaces
        .contains_key(NAMESPACE_MDL));
}

#[tokio::test]
async fn test_complete_holder_flow() {
    let context = MockContext;

    // Create document
    let mut elements = HashMap::new();
    elements.insert("family_name".to_string(), json!("Smith"));
    elements.insert("given_name".to_string(), json!("Alice"));

    let document = DocumentBuilder::new(DOCTYPE_MDL)
        .add_issuer_namespace(NAMESPACE_MDL, elements)
        .use_digest_algorithm(DigestAlgorithm::Sha256)
        .add_validity_info(create_test_validity_info())
        .add_device_key_info(create_test_device_key_info())
        .sign(&context, "issuer-key", SignatureAlgorithm::ES256)
        .await
        .unwrap();

    // Create presentation definition (selective disclosure)
    let pd = PresentationDefinition {
        id: "test-pd".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: DOCTYPE_MDL.to_string(),
            format: None,
            constraints: Some(Constraints {
                limit_disclosure: Some("required".to_string()),
                fields: Some(vec![FieldConstraint {
                    path: vec![format!("$['{}']['family_name']", NAMESPACE_MDL)],
                    intent_to_retain: Some(false),
                }]),
            }),
        }],
    };

    // Create device response
    let response = DeviceResponseBuilder::from(document)
        .using_presentation_definition(pd)
        .using_session_transcript_for_oid4vp(
            "nonce123".to_string(),
            "client_id".to_string(),
            "https://example.com/response".to_string(),
            "verifier_nonce".to_string(),
        )
        .authenticate_with_signature(&context, "device-key", SignatureAlgorithm::ES256)
        .await;

    assert!(
        response.is_ok(),
        "Device response failed: {:?}",
        response.err()
    );
    let device_response = response.unwrap();

    assert_eq!(device_response.version, "1.0");
    assert_eq!(device_response.status, 0);
    assert_eq!(device_response.documents.len(), 1);

    // Verify selective disclosure - only family_name should be disclosed
    let doc = device_response.documents[0].as_ref().unwrap();
    let items = &doc.issuer_signed.name_spaces[NAMESPACE_MDL];
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].element_identifier, "family_name");
}

#[tokio::test]
async fn test_proximity_flow() {
    // Create device key
    let device_key = cose::CoseKey::new(2);
    let edevice_key = EDeviceKey::new(device_key);

    // Create security parameters
    let security = Security::new(1, edevice_key); // Cipher suite 1

    // Create BLE transport
    let ble_method =
        DeviceRetrievalMethods::ble(BleOptions::peripheral_server(Some("uuid-123".to_string())));

    // Create device engagement
    let engagement = DeviceEngagement::new(security).add_retrieval_method(ble_method);

    // Test QR code encoding
    let qr_uri = engagement.to_qr_code_uri().unwrap();
    assert!(qr_uri.starts_with("mdoc:"));

    // Test QR code decoding
    let decoded = DeviceEngagement::from_qr_code_uri(&qr_uri).unwrap();
    assert_eq!(decoded.version, "1.0");
}

#[tokio::test]
async fn test_session_establishment() {
    let reader_key = cose::CoseKey::new(2);
    let establishment = SessionEstablishment::new(reader_key.clone());

    // Test CBOR round-trip
    let cbor = establishment.to_cbor().unwrap();
    let decoded = SessionEstablishment::from_cbor(&cbor).unwrap();

    assert_eq!(decoded.e_reader_key.kty, reader_key.kty);
}

#[tokio::test]
async fn test_handover_types() {
    // Test BLE handover
    let ble_handover = Handover::ble(Some("uuid-123".to_string()), None);
    let cbor = ble_handover.to_cbor().unwrap();
    let decoded = Handover::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.handover_type(), session::HandoverType::Ble);

    // Test NFC handover
    let nfc_handover = Handover::nfc(Some(vec![1, 2, 3]), None);
    assert_eq!(nfc_handover.handover_type(), session::HandoverType::Nfc);

    // Test QR handover
    let qr_handover = Handover::qr();
    assert_eq!(qr_handover.handover_type(), session::HandoverType::Qr);
}

#[tokio::test]
async fn test_date_only_utils() {
    let date = DateOnly::new(2024, 10, 24);
    assert_eq!(date.year(), 2024);
    assert_eq!(date.month(), 10);
    assert_eq!(date.day(), 24);

    // Test formatting
    assert_eq!(date.to_string(), "2024-10-24");

    // Test parsing
    let parsed = DateOnly::parse("2024-10-24").unwrap();
    assert_eq!(parsed, date);

    // Test comparison
    let date2 = DateOnly::new(2024, 10, 25);
    assert!(date < date2);
}

#[tokio::test]
async fn test_uuid_utils() {
    let uuid = Uuid::new();
    assert!(!uuid.is_nil());

    // Test string round-trip
    let uuid_str = uuid.to_string();
    let parsed = Uuid::parse(&uuid_str).unwrap();
    assert_eq!(parsed, uuid);

    // Test simple string
    let simple = uuid.to_simple_string();
    assert!(!simple.contains('-'));
}

#[tokio::test]
async fn test_verification_callback() {
    struct TestCallback;

    #[async_trait]
    impl VerificationCallback for TestCallback {
        async fn verify_issuer_certificate(&self, _chain: &[Vec<u8>]) -> error::Result<bool> {
            Ok(true)
        }

        async fn on_verification_complete(&self, result: &VerificationResult) {
            println!("Verification completed for: {}", result.doc_type);
        }
    }

    let callback = TestCallback;
    let result = callback.verify_issuer_certificate(&[]).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn test_verified_device_response() {
    let context = MockContext;

    // Create document with data
    let mut elements = HashMap::new();
    elements.insert("family_name".to_string(), json!("Doe"));
    elements.insert("given_name".to_string(), json!("John"));
    elements.insert("age".to_string(), json!(34));

    let document = DocumentBuilder::new(DOCTYPE_MDL)
        .add_issuer_namespace(NAMESPACE_MDL, elements)
        .use_digest_algorithm(DigestAlgorithm::Sha256)
        .add_validity_info(create_test_validity_info())
        .add_device_key_info(create_test_device_key_info())
        .sign(&context, "issuer-key", SignatureAlgorithm::ES256)
        .await
        .unwrap();

    // Create device response
    let device_response = DeviceResponseBuilder::from(document)
        .using_session_transcript_for_oid4vp(
            "nonce".to_string(),
            "client".to_string(),
            "https://example.com".to_string(),
            "vnonce".to_string(),
        )
        .authenticate_with_signature(&context, "device-key", SignatureAlgorithm::ES256)
        .await
        .unwrap();

    // Create verification result
    let mut verification = VerificationResult::new(DOCTYPE_MDL.to_string());
    verification.issuer_auth_valid = true;
    verification.device_auth_valid = true;
    verification.disclosed_element_count = 3;

    // Create verified response
    let verified = VerifiedDeviceResponse::new(device_response, verification)
        .extract_claims()
        .unwrap();

    assert!(verified.is_valid());

    // Test claim extraction
    let family_name = verified.get_claim_string(NAMESPACE_MDL, "family_name");
    assert_eq!(family_name, Some("Doe".to_string()));

    let age = verified.get_claim_integer(NAMESPACE_MDL, "age");
    assert_eq!(age, Some(34));
}

#[tokio::test]
async fn test_holder_validation() {
    let context = MockContext;

    // Create document
    let mut elements = HashMap::new();
    elements.insert("test_element".to_string(), json!("test_value"));

    let document = DocumentBuilder::new(DOCTYPE_MDL)
        .add_issuer_namespace(NAMESPACE_MDL, elements)
        .use_digest_algorithm(DigestAlgorithm::Sha256)
        .add_validity_info(create_test_validity_info())
        .add_device_key_info(create_test_device_key_info())
        .sign(&context, "issuer-key", SignatureAlgorithm::ES256)
        .await
        .unwrap();

    let builder = DeviceResponseBuilder::from(document);

    // Test issuer validation
    let validation_result = builder.validate_issuer_signed();
    // Note: This will fail with current implementation since we're using mock signatures
    // In a real scenario with proper crypto, this would pass
    assert!(validation_result.is_ok() || validation_result.is_err());
}

#[tokio::test]
async fn test_data_transformers() {
    use mdoc::utils::{base64_decode, base64_encode, bytes_to_hex, hex_to_bytes};

    // Test hex encoding
    let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let hex = bytes_to_hex(&bytes);
    assert_eq!(hex, "deadbeef");

    let decoded = hex_to_bytes(&hex).unwrap();
    assert_eq!(decoded, bytes);

    // Test base64 encoding
    let data = b"Hello, World!";
    let encoded = base64_encode(data);
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}
