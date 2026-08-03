//! mDL-specific certificate validation
//!
//! ISO 18013-5 requires specific validation rules for mobile driver's licenses:
//! - issuing_country must match certificate countryName
//! - issuing_jurisdiction must match certificate stateOrProvinceName

use crate::error::{MdocError, Result};
use crate::types::IssuerSignedItem;
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// mDL certificate validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdlCertificateCheck {
    /// Check passed
    Passed,
    /// Check failed with reason
    Failed(String),
    /// Check skipped (e.g., attribute not present)
    Skipped,
}

impl MdlCertificateCheck {
    pub fn is_passed(&self) -> bool {
        matches!(self, MdlCertificateCheck::Passed)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, MdlCertificateCheck::Failed(_))
    }
}

/// mDL certificate validation results
#[derive(Debug, Clone)]
pub struct MdlCertificateValidation {
    /// Country name validation result
    pub country_check: MdlCertificateCheck,
    /// Jurisdiction (state/province) validation result
    pub jurisdiction_check: MdlCertificateCheck,
}

impl MdlCertificateValidation {
    /// Check if all validations passed
    pub fn is_valid(&self) -> bool {
        !self.country_check.is_failed() && !self.jurisdiction_check.is_failed()
    }
}

/// Validate mDL certificate against document elements
///
/// For mDL documents (org.iso.18013.5.1), ISO 18013-5 requires:
/// - If `issuing_country` is present, it must match the certificate's countryName
/// - If `issuing_jurisdiction` is present, it must match the certificate's stateOrProvinceName
///
/// # Example
///
/// ```rust,ignore
/// let validation = validate_mdl_certificate(
///     &issuer_cert_bytes,
///     &namespace_items
/// )?;
///
/// if !validation.is_valid() {
///     println!("Certificate validation failed!");
/// }
/// ```
pub fn validate_mdl_certificate(
    certificate_bytes: &[u8],
    namespace_items: &[IssuerSignedItem],
) -> Result<MdlCertificateValidation> {
    // Parse certificate
    let cert = Certificate::from_der(certificate_bytes)
        .map_err(|e| MdocError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

    // Extract country and jurisdiction from certificate subject
    let (cert_country, cert_jurisdiction) = extract_country_and_jurisdiction(&cert)?;

    // Find issuing_country and issuing_jurisdiction in document
    let doc_country = find_element_value(namespace_items, "issuing_country");
    let doc_jurisdiction = find_element_value(namespace_items, "issuing_jurisdiction");

    // Validate country
    let country_check = match (doc_country, &cert_country) {
        (Some(doc_c), Some(cert_c)) => {
            if doc_c.eq_ignore_ascii_case(cert_c) {
                MdlCertificateCheck::Passed
            } else {
                MdlCertificateCheck::Failed(format!(
                    "issuing_country '{}' does not match certificate countryName '{}'",
                    doc_c, cert_c
                ))
            }
        }
        (Some(doc_c), None) => MdlCertificateCheck::Failed(format!(
            "issuing_country '{}' present but certificate has no countryName",
            doc_c
        )),
        (None, _) => MdlCertificateCheck::Skipped, // No issuing_country in document
    };

    // Validate jurisdiction
    let jurisdiction_check = match (doc_jurisdiction, &cert_jurisdiction) {
        (Some(doc_j), Some(cert_j)) => {
            if doc_j.eq_ignore_ascii_case(cert_j) {
                MdlCertificateCheck::Passed
            } else {
                MdlCertificateCheck::Failed(format!(
                    "issuing_jurisdiction '{}' does not match certificate stateOrProvinceName '{}'",
                    doc_j, cert_j
                ))
            }
        }
        (Some(doc_j), None) => MdlCertificateCheck::Failed(format!(
            "issuing_jurisdiction '{}' present but certificate has no stateOrProvinceName",
            doc_j
        )),
        (None, _) => MdlCertificateCheck::Skipped, // No issuing_jurisdiction in document
    };

    Ok(MdlCertificateValidation {
        country_check,
        jurisdiction_check,
    })
}

/// Extract country and jurisdiction (state/province) from certificate subject
fn extract_country_and_jurisdiction(
    cert: &Certificate,
) -> Result<(Option<String>, Option<String>)> {
    let subject = &cert.tbs_certificate.subject;

    let mut country = None;
    let mut jurisdiction = None;

    // Iterate through RDN sequences in the subject
    for rdn_sequence in subject.0.iter() {
        for attribute_type_and_value in rdn_sequence.0.iter() {
            let oid = &attribute_type_and_value.oid;

            // Check for countryName (2.5.4.6)
            if oid.to_string() == "2.5.4.6" {
                if let Ok(value_str) = std::str::from_utf8(attribute_type_and_value.value.value()) {
                    country = Some(value_str.to_string());
                }
            }

            // Check for stateOrProvinceName (2.5.4.8)
            if oid.to_string() == "2.5.4.8" {
                if let Ok(value_str) = std::str::from_utf8(attribute_type_and_value.value.value()) {
                    jurisdiction = Some(value_str.to_string());
                }
            }
        }
    }

    Ok((country, jurisdiction))
}

/// Find element value by element identifier
fn find_element_value(items: &[IssuerSignedItem], element_id: &str) -> Option<String> {
    items
        .iter()
        .find(|item| item.element_identifier == element_id)
        .and_then(|item| match &item.element_value {
            ciborium::Value::Text(s) => Some(s.clone()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn create_item(element_id: &str, value: &str) -> IssuerSignedItem {
        IssuerSignedItem {
            digest_id: 0,
            random: vec![],
            element_identifier: element_id.to_string(),
            element_value: Value::Text(value.to_string()),
        }
    }

    #[test]
    fn test_country_validation() {
        // This test would need a real certificate to work properly
        // For now, we just test the structure
        let _items = [
            create_item("issuing_country", "US"),
            create_item("family_name", "Doe"),
        ];

        // In a real test, we'd create a certificate with countryName="US"
        // and verify that validation passes
    }

    #[test]
    fn test_jurisdiction_validation() {
        let _items = [
            create_item("issuing_jurisdiction", "CA"),
            create_item("family_name", "Doe"),
        ];

        // In a real test, we'd create a certificate with stateOrProvinceName="CA"
        // and verify that validation passes
    }

    #[test]
    fn test_find_element_value() {
        let items = vec![
            create_item("issuing_country", "US"),
            create_item("issuing_jurisdiction", "CA"),
            create_item("family_name", "Doe"),
        ];

        assert_eq!(
            find_element_value(&items, "issuing_country"),
            Some("US".to_string())
        );
        assert_eq!(
            find_element_value(&items, "issuing_jurisdiction"),
            Some("CA".to_string())
        );
        assert_eq!(
            find_element_value(&items, "family_name"),
            Some("Doe".to_string())
        );
        assert_eq!(find_element_value(&items, "nonexistent"), None);
    }

    #[test]
    fn test_mdl_certificate_check() {
        let passed = MdlCertificateCheck::Passed;
        let failed = MdlCertificateCheck::Failed("error".to_string());
        let skipped = MdlCertificateCheck::Skipped;

        assert!(passed.is_passed());
        assert!(!failed.is_passed());
        assert!(!skipped.is_passed());

        assert!(!passed.is_failed());
        assert!(failed.is_failed());
        assert!(!skipped.is_failed());
    }

    #[test]
    fn test_mdl_validation_is_valid() {
        let valid = MdlCertificateValidation {
            country_check: MdlCertificateCheck::Passed,
            jurisdiction_check: MdlCertificateCheck::Skipped,
        };
        assert!(valid.is_valid());

        let invalid = MdlCertificateValidation {
            country_check: MdlCertificateCheck::Failed("mismatch".to_string()),
            jurisdiction_check: MdlCertificateCheck::Passed,
        };
        assert!(!invalid.is_valid());
    }
}
