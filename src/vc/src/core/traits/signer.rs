use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Cryptographic key types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    P256,
    P384,
    P521,
    Rsa2048,
    Rsa4096,
    Bls12381,
}

/// Signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    EdDSA,
    ES256, // ECDSA with P-256 and SHA-256
    ES384, // ECDSA with P-384 and SHA-384
    ES512, // ECDSA with P-521 and SHA-512
    RS256, // RSASSA-PKCS1-v1_5 with SHA-256
    RS384, // RSASSA-PKCS1-v1_5 with SHA-384
    RS512, // RSASSA-PKCS1-v1_5 with SHA-512
    PS256, // RSASSA-PSS with SHA-256
    PS384, // RSASSA-PSS with SHA-384
    PS512, // RSASSA-PSS with SHA-512
}

/// Proof purposes as defined by W3C
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofPurpose {
    /// For issuing credentials
    AssertionMethod,
    /// For authentication
    Authentication,
    /// For authorization
    CapabilityInvocation,
    /// For delegation
    CapabilityDelegation,
    /// For key agreement
    KeyAgreement,
    /// Custom purpose
    Custom(String),
}

impl ProofPurpose {
    pub fn as_str(&self) -> &str {
        match self {
            ProofPurpose::AssertionMethod => "assertionMethod",
            ProofPurpose::Authentication => "authentication",
            ProofPurpose::CapabilityInvocation => "capabilityInvocation",
            ProofPurpose::CapabilityDelegation => "capabilityDelegation",
            ProofPurpose::KeyAgreement => "keyAgreement",
            ProofPurpose::Custom(s) => s,
        }
    }
}

/// Signing key information
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// Key ID (DID URL or key reference)
    pub id: String,
    /// Key type
    pub key_type: KeyType,
    /// Controller DID
    pub controller: String,
    /// Private key material (format depends on implementation)
    pub private_key: Vec<u8>,
    /// Public key material
    pub public_key: Vec<u8>,
}

/// Document signer trait for signing credentials and presentations
#[async_trait]
pub trait DocumentSigner: Send + Sync {
    /// Sign data with the specified algorithm
    async fn sign(
        &self,
        data: &[u8],
        key: &SigningKey,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Verify a signature
    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
        algorithm: SignatureAlgorithm,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    /// Get supported algorithms for a key type
    fn supported_algorithms(&self, key_type: KeyType) -> Vec<SignatureAlgorithm> {
        match key_type {
            KeyType::Ed25519 => vec![SignatureAlgorithm::EdDSA],
            KeyType::P256 => vec![SignatureAlgorithm::ES256],
            KeyType::P384 => vec![SignatureAlgorithm::ES384],
            KeyType::P521 => vec![SignatureAlgorithm::ES512],
            KeyType::Rsa2048 | KeyType::Rsa4096 => vec![
                SignatureAlgorithm::RS256,
                SignatureAlgorithm::RS384,
                SignatureAlgorithm::RS512,
                SignatureAlgorithm::PS256,
                SignatureAlgorithm::PS384,
                SignatureAlgorithm::PS512,
            ],
            KeyType::Bls12381 => vec![], // BBS+ signatures not yet implemented
        }
    }
}

/// JWT signer specifically for JWT operations
#[async_trait]
pub trait JwtSigner: Send + Sync {
    /// Sign a JWT with header and payload
    async fn sign_jwt(
        &self,
        header: &serde_json::Value,
        payload: &serde_json::Value,
        key: &SigningKey,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Verify a JWT and return header and payload if valid
    async fn verify_jwt(
        &self,
        jwt: &str,
        public_key: &[u8],
    ) -> Result<(serde_json::Value, serde_json::Value), Box<dyn std::error::Error + Send + Sync>>;
}

/// Key resolver for DID resolution and key fetching
#[async_trait]
pub trait KeyResolver: Send + Sync {
    /// Resolve a verification method from a DID URL
    async fn resolve_verification_method(
        &self,
        did_url: &str,
    ) -> Result<VerificationMethod, Box<dyn std::error::Error + Send + Sync>>;

    /// Get public key bytes from a verification method
    fn get_public_key(
        &self,
        method: &VerificationMethod,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Verification method from DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_base58: Option<String>,
}
