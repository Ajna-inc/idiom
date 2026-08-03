//! Core ISO 18013-5 data structures for mDoc

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crate::context::{DigestAlgorithm, SignatureAlgorithm};

/// Main mDoc document structure per ISO 18013-5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// Document type (e.g., "org.iso.18013.5.1.mDL")
    #[serde(rename = "docType")]
    pub doc_type: String,

    /// Issuer-signed portion with data elements and MSO
    #[serde(rename = "issuerSigned")]
    pub issuer_signed: IssuerSigned,

    /// Device-signed portion (optional, for device authentication)
    #[serde(rename = "deviceSigned", skip_serializing_if = "Option::is_none")]
    pub device_signed: Option<DeviceSigned>,

    /// Errors (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<HashMap<String, ErrorItem>>,
}

/// Issuer-signed portion of the document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSigned {
    /// Namespaced data elements
    ///
    /// Note: In real-world mDocs, IssuerSignedItem is encoded as CBOR tag 24
    /// (encoded CBOR data item). The custom deserializer handles both tagged
    /// and non-tagged formats for backwards compatibility.
    #[serde(
        rename = "nameSpaces",
        deserialize_with = "crate::cbor_tag24::deserialize_tag24_hashmap",
        serialize_with = "crate::cbor_tag24::serialize_tag24_hashmap"
    )]
    pub name_spaces: HashMap<String, Vec<IssuerSignedItem>>,

    /// COSE_Sign1 containing the Mobile Security Object
    ///
    /// Note: This is a COSE_Sign1 array [protected, unprotected, payload, signature],
    /// not CBOR-encoded bytes. Real-world mDocs encode this as the array directly.
    /// We store it as Value to handle both array and bytes representations.
    #[serde(rename = "issuerAuth")]
    pub issuer_auth: ciborium::Value,
}

/// Single data element in issuer-signed namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// Digest identifier (unique within namespace)
    #[serde(rename = "digestID")]
    pub digest_id: u32,

    /// Random salt for digest calculation
    pub random: Vec<u8>,

    /// Element identifier (e.g., "family_name")
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,

    /// Element value (can be any CBOR type)
    ///
    /// Uses ciborium::Value to properly represent all CBOR types including:
    /// - Integers, Text, Bytes, Arrays, Maps
    /// - CBOR-specific types like Tags, Booleans, Null
    /// - DateOnly (tag 1004), full-date (tag 1004), etc.
    #[serde(rename = "elementValue")]
    pub element_value: ciborium::Value,
}

/// Mobile Security Object (MSO) - the signed metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    /// Version (currently "1.0")
    pub version: String,

    /// Digest algorithm used (e.g., "SHA-256")
    #[serde(rename = "digestAlgorithm")]
    pub digest_algorithm: String,

    /// Digests of all data elements, organized by namespace
    #[serde(rename = "valueDigests")]
    pub value_digests: HashMap<String, HashMap<u32, Vec<u8>>>,

    /// Information about the device public key
    #[serde(rename = "deviceKeyInfo")]
    pub device_key_info: DeviceKeyInfo,

    /// Document type
    #[serde(rename = "docType")]
    pub doc_type: String,

    /// Validity information
    #[serde(rename = "validityInfo")]
    pub validity_info: ValidityInfo,
}

/// Information about the device's public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// Device public key as COSE_Key
    #[serde(rename = "deviceKey")]
    pub device_key: HashMap<String, serde_json::Value>,

    /// Optional key authorizations
    #[serde(rename = "keyAuthorizations", skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<HashMap<String, serde_json::Value>>,

    /// Optional key info
    #[serde(rename = "keyInfo", skip_serializing_if = "Option::is_none")]
    pub key_info: Option<HashMap<String, serde_json::Value>>,
}

/// Validity period information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityInfo {
    /// Date when the document was signed
    pub signed: DateTime<Utc>,

    /// Date from which the document is valid
    #[serde(rename = "validFrom")]
    pub valid_from: DateTime<Utc>,

    /// Date until which the document is valid
    #[serde(rename = "validUntil")]
    pub valid_until: DateTime<Utc>,

    /// Optional expected update date
    #[serde(rename = "expectedUpdate", skip_serializing_if = "Option::is_none")]
    pub expected_update: Option<DateTime<Utc>>,
}

/// Device-signed portion of the document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSigned {
    /// Namespaced device-signed elements
    ///
    /// Note: In real-world mDocs, the entire nameSpaces map may be tag 24 wrapped
    #[serde(
        rename = "nameSpaces",
        deserialize_with = "crate::cbor_tag24::deserialize_maybe_tag24_map",
        serialize_with = "crate::cbor_tag24::serialize_maybe_tag24_map"
    )]
    pub name_spaces: HashMap<String, Vec<DeviceSignedItem>>,

    /// Device authentication (COSE_Sign1 or COSE_Mac0)
    #[serde(rename = "deviceAuth")]
    pub device_auth: DeviceAuth,
}

/// Single device-signed element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSignedItem {
    /// Element identifier
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,

    /// Element value (can be any CBOR type)
    ///
    /// Uses ciborium::Value to properly represent all CBOR types
    #[serde(rename = "elementValue")]
    pub element_value: ciborium::Value,
}

/// Device authentication - either signature or MAC
///
/// Note: In real-world mDocs, these may be COSE arrays [protected, unprotected, payload, signature/tag]
/// rather than raw bytes. We use ciborium::Value to handle both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceAuth {
    Signature {
        #[serde(rename = "deviceSignature")]
        device_signature: ciborium::Value,
    },
    Mac {
        #[serde(rename = "deviceMac")]
        device_mac: ciborium::Value,
    },
}

/// Session transcript for device authentication binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript {
    /// Device engagement bytes (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_engagement: Option<Vec<u8>>,

    /// Reader's ephemeral key (optional)
    #[serde(rename = "eReaderKey", skip_serializing_if = "Option::is_none")]
    pub e_reader_key: Option<Vec<u8>>,

    /// Handover data
    pub handover: Vec<u8>,
}

/// Error item in document response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorItem {
    /// Error code
    pub error: u32,

    /// Error message
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

/// Device response containing one or more documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse {
    /// Version
    pub version: String,

    /// Array of documents (or null for each)
    pub documents: Vec<Option<Document>>,

    /// Document errors (optional)
    #[serde(rename = "documentErrors", skip_serializing_if = "Option::is_none")]
    pub document_errors: Option<Vec<HashMap<String, ErrorItem>>>,

    /// Status code
    pub status: u32,
}

/// Device request containing one or more document requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// Version
    pub version: String,

    /// Array of document requests
    #[serde(rename = "docRequests")]
    pub doc_requests: Vec<DocRequest>,
}

/// Request for specific data elements (for selective disclosure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocRequest {
    /// Document type
    #[serde(rename = "docType")]
    pub doc_type: String,

    /// Requested namespaces and elements
    #[serde(rename = "nameSpaces")]
    pub name_spaces: HashMap<String, NamespaceRequest>,

    /// Optional reader authentication (proves reader is authorized)
    #[serde(rename = "readerAuth", skip_serializing_if = "Option::is_none")]
    pub reader_auth: Option<Vec<u8>>, // CBOR-encoded ReaderAuth
}

/// Request for elements within a namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceRequest {
    /// If true, request all elements in namespace
    #[serde(rename = "requestAll", skip_serializing_if = "Option::is_none")]
    pub request_all: Option<bool>,

    /// Specific elements to request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elements: Option<Vec<String>>,
}

// mDL-specific element names from ISO 18013-5
pub mod mdl_elements {
    pub const FAMILY_NAME: &str = "family_name";
    pub const GIVEN_NAME: &str = "given_name";
    pub const BIRTH_DATE: &str = "birth_date";
    pub const ISSUE_DATE: &str = "issue_date";
    pub const EXPIRY_DATE: &str = "expiry_date";
    pub const ISSUING_COUNTRY: &str = "issuing_country";
    pub const ISSUING_AUTHORITY: &str = "issuing_authority";
    pub const DOCUMENT_NUMBER: &str = "document_number";
    pub const PORTRAIT: &str = "portrait";
    pub const DRIVING_PRIVILEGES: &str = "driving_privileges";
    pub const UN_DISTINGUISHING_SIGN: &str = "un_distinguishing_sign";
    pub const ADMINISTRATIVE_NUMBER: &str = "administrative_number";
    pub const SEX: &str = "sex";
    pub const HEIGHT: &str = "height";
    pub const WEIGHT: &str = "weight";
    pub const EYE_COLOUR: &str = "eye_colour";
    pub const HAIR_COLOUR: &str = "hair_colour";
    pub const BIRTH_PLACE: &str = "birth_place";
    pub const RESIDENT_ADDRESS: &str = "resident_address";
    pub const PORTRAIT_CAPTURE_DATE: &str = "portrait_capture_date";
    pub const AGE_IN_YEARS: &str = "age_in_years";
    pub const AGE_BIRTH_YEAR: &str = "age_birth_year";
    pub const AGE_OVER_18: &str = "age_over_18";
    pub const AGE_OVER_21: &str = "age_over_21";
    pub const ISSUING_JURISDICTION: &str = "issuing_jurisdiction";
    pub const NATIONALITY: &str = "nationality";
    pub const RESIDENT_CITY: &str = "resident_city";
    pub const RESIDENT_STATE: &str = "resident_state";
    pub const RESIDENT_POSTAL_CODE: &str = "resident_postal_code";
    pub const RESIDENT_COUNTRY: &str = "resident_country";
    pub const FAMILY_NAME_NATIONAL_CHARACTER: &str = "family_name_national_character";
    pub const GIVEN_NAME_NATIONAL_CHARACTER: &str = "given_name_national_character";
    pub const SIGNATURE_USUAL_MARK: &str = "signature_usual_mark";
}
