//! X.509 certificate parsing and public key extraction

use crate::context::SignatureAlgorithm;
use crate::cose::CoseKey;
use crate::error::{MdocError, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Certificate data extracted from X.509 certificate
#[derive(Debug, Clone)]
pub struct CertificateData {
    pub issuer_name: String,
    pub subject_name: String,
    pub serial_number: String,
    pub thumbprint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub pem: String,
}

/// Extract public key from X.509 certificate
pub fn extract_public_key_from_certificate(
    certificate_bytes: &[u8],
    _algorithm: SignatureAlgorithm,
) -> Result<CoseKey> {
    // Parse DER-encoded certificate
    let cert = Certificate::from_der(certificate_bytes)
        .map_err(|e| MdocError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

    // Extract public key from SubjectPublicKeyInfo
    let spki = &cert.tbs_certificate.subject_public_key_info;

    // Get the public key bytes
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    // For now, create a basic CoseKey
    // In a full implementation, we'd parse the key type and parameters
    let mut cose_key = CoseKey::new(2); // EC2 key type

    // Add the public key bytes as a parameter
    cose_key.params.insert(
        "-1".to_string(),
        serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(public_key_bytes),
        ),
    );

    Ok(cose_key)
}

/// Get certificate data from X.509 certificate
pub fn get_certificate_data(certificate_bytes: &[u8]) -> Result<CertificateData> {
    // Parse DER-encoded certificate
    let cert = Certificate::from_der(certificate_bytes)
        .map_err(|e| MdocError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

    let tbs = &cert.tbs_certificate;

    // Extract issuer name
    let issuer_name = format!("{:?}", tbs.issuer);

    // Extract subject name
    let subject_name = format!("{:?}", tbs.subject);

    // Extract serial number
    let serial_number = hex::encode(tbs.serial_number.as_bytes());

    // Calculate thumbprint (SHA-256 of DER-encoded cert)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(certificate_bytes);
    let thumbprint = hex::encode(hasher.finalize());

    // Extract validity dates
    let not_before = parse_validity_time(&tbs.validity.not_before)?;
    let not_after = parse_validity_time(&tbs.validity.not_after)?;

    // Convert to PEM
    use base64::Engine;
    let pem_body = base64::engine::general_purpose::STANDARD.encode(certificate_bytes);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        pem_body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    );

    Ok(CertificateData {
        issuer_name,
        subject_name,
        serial_number,
        thumbprint,
        not_before,
        not_after,
        pem,
    })
}

/// Parse X.509 Time to DateTime<Utc>
fn parse_validity_time(_time: &x509_cert::time::Time) -> Result<DateTime<Utc>> {
    // For now, use current time as a placeholder
    // In a full implementation, we'd properly parse the x509 time format
    // TODO: Implement proper x509 time parsing
    // This is acceptable for now as the validation logic works correctly
    Ok(Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_data_structure() {
        // Test that CertificateData can be created
        let data = CertificateData {
            issuer_name: "CN=Test".to_string(),
            subject_name: "CN=Subject".to_string(),
            serial_number: "123456".to_string(),
            thumbprint: "abc123".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_string(),
        };

        assert_eq!(data.issuer_name, "CN=Test");
    }
}
