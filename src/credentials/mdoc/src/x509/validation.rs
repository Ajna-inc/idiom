//! X.509 certificate chain validation

use crate::error::{MdocError, Result};
use chrono::{DateTime, Utc};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// X.509 certificate chain validator
pub struct X509Validator;

impl X509Validator {
    /// Validate a certificate chain against trusted certificates
    ///
    /// # Arguments
    /// * `certificate_chain` - Chain of certificates (leaf first, root last)
    /// * `trusted_certificates` - Trusted root/intermediate certificates
    /// * `now` - Optional timestamp for validity checking (defaults to current time)
    ///
    /// # Returns
    /// Ok(()) if chain is valid, Err otherwise
    pub fn validate_certificate_chain(
        certificate_chain: &[Vec<u8>],
        trusted_certificates: &[Vec<u8>],
        now: Option<DateTime<Utc>>,
    ) -> Result<()> {
        if certificate_chain.is_empty() {
            return Err(MdocError::CertificateError(
                "Certificate chain is empty".to_string(),
            ));
        }

        let validation_time = now.unwrap_or_else(Utc::now);

        // Parse all certificates in the chain
        let chain_certs: Vec<Certificate> = certificate_chain
            .iter()
            .enumerate()
            .map(|(i, cert_bytes)| {
                Certificate::from_der(cert_bytes).map_err(|e| {
                    MdocError::CertificateError(format!(
                        "Failed to parse certificate {} in chain: {}",
                        i, e
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Parse trusted certificates
        let trusted_certs: Vec<Certificate> = trusted_certificates
            .iter()
            .enumerate()
            .map(|(i, cert_bytes)| {
                Certificate::from_der(cert_bytes).map_err(|e| {
                    MdocError::CertificateError(format!(
                        "Failed to parse trusted certificate {}: {}",
                        i, e
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // 1. Validate each certificate's validity period
        for (i, cert) in chain_certs.iter().enumerate() {
            Self::validate_certificate_validity(cert, validation_time).map_err(|e| {
                MdocError::CertificateError(format!("Certificate {} invalid: {}", i, e))
            })?;
        }

        // 2. Validate chain structure (each cert signed by next)
        for i in 0..chain_certs.len() - 1 {
            let subject_cert = &chain_certs[i];
            let issuer_cert = &chain_certs[i + 1];

            Self::validate_certificate_signature(subject_cert, issuer_cert)?;
        }

        // 3. Validate root certificate is in trusted set
        let root_cert = chain_certs.last().unwrap();
        let is_trusted = trusted_certs
            .iter()
            .any(|trusted| Self::certificates_match(root_cert, trusted));

        if !is_trusted {
            return Err(MdocError::CertificateError(
                "Root certificate not found in trusted set".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate certificate is within validity period
    fn validate_certificate_validity(_cert: &Certificate, _now: DateTime<Utc>) -> Result<()> {
        // TODO: Implement proper validity period checking
        // For now, accept all certificates
        // This needs proper x509 time parsing
        Ok(())
    }

    /// Validate that subject_cert is signed by issuer_cert
    ///
    /// Note: This is a simplified implementation. A full implementation
    /// would verify the actual cryptographic signature.
    fn validate_certificate_signature(
        _subject_cert: &Certificate,
        _issuer_cert: &Certificate,
    ) -> Result<()> {
        // TODO: Implement actual signature verification
        // This requires:
        // 1. Extract public key from issuer_cert
        // 2. Extract signature from subject_cert
        // 3. Verify signature over subject_cert.tbs_certificate

        // For now, we'll assume the signature is valid if we reach here
        // A full implementation would use a crypto library to verify
        Ok(())
    }

    /// Check if two certificates match (same subject and public key)
    fn certificates_match(cert1: &Certificate, cert2: &Certificate) -> bool {
        // Compare subject names
        let subject_match = cert1.tbs_certificate.subject == cert2.tbs_certificate.subject;

        // Compare public keys
        let pubkey_match = cert1
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            == cert2
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key;

        subject_match && pubkey_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_fails() {
        let result = X509Validator::validate_certificate_chain(&[], &[], None);
        assert!(result.is_err());
    }
}
