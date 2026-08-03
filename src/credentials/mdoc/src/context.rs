//! Pluggable crypto context for mDoc operations
//!
//! Similar to animo-id/mdoc's MdocContext, this provides a pluggable interface
//! for cryptographic operations, allowing different implementations for different
//! platforms (Node.js, browser, React Native, etc.)

use crate::cose::CoseKey;
use crate::error::Result;
use async_trait::async_trait;

/// Digest algorithms supported by mDoc
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha384 => "SHA-384",
            DigestAlgorithm::Sha512 => "SHA-512",
        }
    }
}

/// Signature algorithms for COSE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    EdDSA, // Ed25519
    ES256, // ECDSA with P-256 and SHA-256
    ES384, // ECDSA with P-384 and SHA-384
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::EdDSA => "EdDSA",
            SignatureAlgorithm::ES256 => "ES256",
            SignatureAlgorithm::ES384 => "ES384",
        }
    }

    pub fn to_cose_algorithm(&self) -> coset::iana::Algorithm {
        match self {
            SignatureAlgorithm::EdDSA => coset::iana::Algorithm::EdDSA,
            SignatureAlgorithm::ES256 => coset::iana::Algorithm::ES256,
            SignatureAlgorithm::ES384 => coset::iana::Algorithm::ES384,
        }
    }
}

/// Main context trait for mDoc operations
///
/// This is similar to animo's MdocContext interface, providing pluggable
/// crypto, COSE, and X.509 operations.
#[async_trait]
pub trait MdocContext: Send + Sync {
    /// Crypto operations
    async fn random(&self, length: usize) -> Result<Vec<u8>>;

    async fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>>;

    /// COSE Sign1 operations
    async fn cose_sign1_sign(
        &self,
        key_id: &str,
        payload: &[u8],
        protected_headers: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>>;

    async fn cose_sign1_verify(
        &self,
        public_key: &CoseKey,
        signature: &[u8],
        payload: &[u8],
        protected_headers: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<bool>;

    /// COSE Mac0 operations (for device authentication alternative)
    async fn cose_mac0_sign(
        &self,
        key: &[u8],
        payload: &[u8],
        protected_headers: &[u8],
    ) -> Result<Vec<u8>>;

    async fn cose_mac0_verify(
        &self,
        key: &[u8],
        mac: &[u8],
        payload: &[u8],
        protected_headers: &[u8],
    ) -> Result<bool>;

    /// X.509 operations
    async fn get_public_key_from_certificate(
        &self,
        certificate: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<CoseKey>;

    async fn validate_certificate_chain(
        &self,
        certificate_chain: &[Vec<u8>],
        trusted_certificates: &[Vec<u8>],
    ) -> Result<()>;
}
