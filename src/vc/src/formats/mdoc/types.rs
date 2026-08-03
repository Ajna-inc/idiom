//! Core data types for mDoc following ISO 18013-5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Mobile Document (mDoc) - top level structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MDoc {
    /// Document type (e.g., "org.iso.18013.5.1.mDL")
    pub doc_type: String,

    /// Version of the mDoc format
    pub version: String,

    /// Issuer-signed data
    pub issuer_signed: IssuerSigned,

    /// Device-signed data (optional, for device authentication)
    pub device_signed: Option<DeviceSigned>,

    /// Status of the document (0 = OK)
    pub status: u8,
}

/// Issuer-signed portion of the mDoc
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSigned {
    /// Namespaced data elements
    pub name_spaces: HashMap<String, Vec<IssuerSignedItem>>,

    /// Issuer authentication (COSE_Sign1)
    pub issuer_auth: Vec<u8>, // CBOR-encoded COSE_Sign1
}

/// Single issuer-signed data element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// Digest ID for selective disclosure
    pub digest_id: u32,

    /// Random salt for hashing
    pub random: Vec<u8>,

    /// Element identifier (name)
    pub element_identifier: String,

    /// Element value (CBOR-encoded)
    pub element_value: serde_json::Value,
}

/// Device-signed portion of the mDoc
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSigned {
    /// Namespaces (typically empty for device-signed)
    pub name_spaces: HashMap<String, Vec<DeviceSignedItem>>,

    /// Device authentication
    pub device_auth: DeviceAuthPayload,
}

/// Device-signed data element (rarely used)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSignedItem {
    pub element_identifier: String,
    pub element_value: serde_json::Value,
}

/// Device authentication payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DeviceAuthPayload {
    /// Device signature (COSE_Sign1)
    #[serde(rename = "deviceSignature")]
    DeviceSignature {
        device_signature: Vec<u8>, // CBOR-encoded COSE_Sign1
    },

    /// Device MAC (COSE_Mac0)
    #[serde(rename = "deviceMac")]
    DeviceMac {
        device_mac: Vec<u8>, // CBOR-encoded COSE_Mac0
    },
}

/// Mobile Security Object (MSO) - signed by issuer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    /// Version of MSO (always "1.0")
    pub version: String,

    /// Digest algorithm (e.g., "SHA-256")
    pub digest_algorithm: String,

    /// Value digests per namespace
    pub value_digests: HashMap<String, HashMap<u32, Vec<u8>>>,

    /// Device key info
    pub device_key_info: DeviceKeyInfo,

    /// Document type
    pub doc_type: String,

    /// Valid from date
    pub valid_from: DateTime<Utc>,

    /// Valid until date
    pub valid_until: DateTime<Utc>,

    /// Expected update date (optional)
    pub expected_update: Option<DateTime<Utc>>,
}

/// Information about the device public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyInfo {
    /// Device public key (COSE_Key format)
    pub device_key: Vec<u8>, // CBOR-encoded COSE_Key

    /// Key authorizations (optional)
    pub key_authorizations: Option<KeyAuthorizations>,

    /// Additional key info (optional)
    pub key_info: Option<HashMap<String, serde_json::Value>>,
}

/// Key authorization structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuthorizations {
    /// Authorized namespaces
    pub name_spaces: Option<Vec<String>>,

    /// Authorized data elements per namespace
    pub data_elements: Option<HashMap<String, Vec<String>>>,
}

/// Standard ISO namespace for mDL (mobile driver's license)
pub const NAMESPACE_MDL: &str = "org.iso.18013.5.1";

/// Standard doc type for mDL
pub const DOCTYPE_MDL: &str = "org.iso.18013.5.1.mDL";

/// Standard data elements for mDL namespace
pub mod mdl_elements {
    /// Family name
    pub const FAMILY_NAME: &str = "family_name";

    /// Given name
    pub const GIVEN_NAME: &str = "given_name";

    /// Birth date (YYYY-MM-DD)
    pub const BIRTH_DATE: &str = "birth_date";

    /// Issue date
    pub const ISSUE_DATE: &str = "issue_date";

    /// Expiry date
    pub const EXPIRY_DATE: &str = "expiry_date";

    /// Issuing country (ISO 3166-1 alpha-2)
    pub const ISSUING_COUNTRY: &str = "issuing_country";

    /// Issuing authority
    pub const ISSUING_AUTHORITY: &str = "issuing_authority";

    /// Document number
    pub const DOCUMENT_NUMBER: &str = "document_number";

    /// Portrait image (JPEG)
    pub const PORTRAIT: &str = "portrait";

    /// Driving privileges
    pub const DRIVING_PRIVILEGES: &str = "driving_privileges";

    /// UN distinguishing sign
    pub const UN_DISTINGUISHING_SIGN: &str = "un_distinguishing_sign";

    /// Administrative number
    pub const ADMINISTRATIVE_NUMBER: &str = "administrative_number";

    /// Sex (1=male, 2=female)
    pub const SEX: &str = "sex";

    /// Height (cm)
    pub const HEIGHT: &str = "height";

    /// Weight (kg)
    pub const WEIGHT: &str = "weight";

    /// Eye color
    pub const EYE_COLOUR: &str = "eye_colour";

    /// Hair color
    pub const HAIR_COLOUR: &str = "hair_colour";

    /// Birth place
    pub const BIRTH_PLACE: &str = "birth_place";

    /// Resident address
    pub const RESIDENT_ADDRESS: &str = "resident_address";

    /// Portrait capture date
    pub const PORTRAIT_CAPTURE_DATE: &str = "portrait_capture_date";

    /// Age in years
    pub const AGE_IN_YEARS: &str = "age_in_years";

    /// Age birth year
    pub const AGE_BIRTH_YEAR: &str = "age_birth_year";

    /// Age over 18
    pub const AGE_OVER_18: &str = "age_over_18";

    /// Age over 21
    pub const AGE_OVER_21: &str = "age_over_21";

    /// Issuing jurisdiction
    pub const ISSUING_JURISDICTION: &str = "issuing_jurisdiction";

    /// Nationality
    pub const NATIONALITY: &str = "nationality";

    /// Resident city
    pub const RESIDENT_CITY: &str = "resident_city";

    /// Resident state
    pub const RESIDENT_STATE: &str = "resident_state";

    /// Resident postal code
    pub const RESIDENT_POSTAL_CODE: &str = "resident_postal_code";

    /// Resident country
    pub const RESIDENT_COUNTRY: &str = "resident_country";
}

impl MDoc {
    /// Create a new mDoc with minimal required fields
    pub fn new(doc_type: String) -> Self {
        Self {
            doc_type,
            version: "1.0".to_string(),
            issuer_signed: IssuerSigned {
                name_spaces: HashMap::new(),
                issuer_auth: Vec::new(),
            },
            device_signed: None,
            status: 0,
        }
    }

    /// Add an issuer-signed element to a namespace
    pub fn add_issuer_signed_element(&mut self, namespace: String, item: IssuerSignedItem) {
        self.issuer_signed
            .name_spaces
            .entry(namespace)
            .or_default()
            .push(item);
    }

    /// Get all elements in a namespace
    pub fn get_namespace_elements(&self, namespace: &str) -> Option<&Vec<IssuerSignedItem>> {
        self.issuer_signed.name_spaces.get(namespace)
    }

    /// Check if document is valid (based on status)
    pub fn is_valid(&self) -> bool {
        self.status == 0
    }
}

impl MobileSecurityObject {
    /// Create a new MSO
    pub fn new(
        doc_type: String,
        device_key_info: DeviceKeyInfo,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        Self {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            value_digests: HashMap::new(),
            device_key_info,
            doc_type,
            valid_from,
            valid_until,
            expected_update: None,
        }
    }

    /// Add a digest for a data element
    pub fn add_digest(&mut self, namespace: String, digest_id: u32, digest: Vec<u8>) {
        self.value_digests
            .entry(namespace)
            .or_default()
            .insert(digest_id, digest);
    }

    /// Check if MSO is currently valid (based on dates)
    pub fn is_currently_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_from && now <= self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdoc_creation() {
        let mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        assert_eq!(mdoc.doc_type, DOCTYPE_MDL);
        assert_eq!(mdoc.version, "1.0");
        assert!(mdoc.is_valid());
        assert_eq!(mdoc.issuer_signed.name_spaces.len(), 0);
    }

    #[test]
    fn test_add_issuer_signed_element() {
        let mut mdoc = MDoc::new(DOCTYPE_MDL.to_string());

        let item = IssuerSignedItem {
            digest_id: 0,
            random: vec![1, 2, 3, 4],
            element_identifier: mdl_elements::FAMILY_NAME.to_string(),
            element_value: serde_json::json!("Doe"),
        };

        mdoc.add_issuer_signed_element(NAMESPACE_MDL.to_string(), item);

        assert_eq!(mdoc.issuer_signed.name_spaces.len(), 1);
        assert!(mdoc.get_namespace_elements(NAMESPACE_MDL).is_some());
    }

    #[test]
    fn test_mso_validity() {
        let device_key_info = DeviceKeyInfo {
            device_key: vec![],
            key_authorizations: None,
            key_info: None,
        };

        let valid_from = Utc::now() - chrono::Duration::hours(1);
        let valid_until = Utc::now() + chrono::Duration::days(30);

        let mso = MobileSecurityObject::new(
            DOCTYPE_MDL.to_string(),
            device_key_info,
            valid_from,
            valid_until,
        );

        assert!(mso.is_currently_valid());
    }

    #[test]
    fn test_mso_expired() {
        let device_key_info = DeviceKeyInfo {
            device_key: vec![],
            key_authorizations: None,
            key_info: None,
        };

        let valid_from = Utc::now() - chrono::Duration::days(60);
        let valid_until = Utc::now() - chrono::Duration::days(1);

        let mso = MobileSecurityObject::new(
            DOCTYPE_MDL.to_string(),
            device_key_info,
            valid_from,
            valid_until,
        );

        assert!(!mso.is_currently_valid());
    }
}
