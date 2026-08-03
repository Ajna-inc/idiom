//! ML-DSA-65 signatures for validators (NIST FIPS 204)
//! Quantum-resistant lattice-based signatures
//! Formerly known as Dilithium3 in draft standards

use fips204::ml_dsa_65; // FIPS 204 compliant
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use parity_scale_codec::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key size in bytes (ML-DSA-65)
pub const PUBKEY_SIZE: usize = 1952;

/// Secret key size in bytes (ML-DSA-65)
pub const SECRET_KEY_SIZE: usize = 4032;

/// Signature size in bytes (ML-DSA-65, FIPS 204 final standard)
pub const SIGNATURE_SIZE: usize = 3309; // NOT 2420 from draft!

/// Domain separation tag for block headers
pub const DST_HEADER: &[u8] = b"AJNA/MLDSA65/HEADER/V1";

/// Domain separation tag for votes
pub const DST_VOTE: &[u8] = b"AJNA/MLDSA65/VOTE/V1";

/// Domain separation tag for DA attestations
pub const DST_DA: &[u8] = b"AJNA/MLDSA65/DA/V1";

/// Domain separation tag for DID operations
pub const DST_DID: &[u8] = b"AJNA/MLDSA65/DID/V1";

/// Domain separation tag for timeout votes (Pacemaker)
pub const DST_TIMEOUT: &[u8] = b"AJNA/MLDSA65/TIMEOUT/V1";

/// Domain separation tag for view change messages
pub const DST_VIEW_CHANGE: &[u8] = b"AJNA/MLDSA65/VIEWCHANGE/V1";

/// Wrapper around ML-DSA-65 public key with codec support
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorPublicKey {
    inner: [u8; PUBKEY_SIZE],
}

impl ValidatorPublicKey {
    /// Create from raw bytes with FIPS 204 validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBKEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: PUBKEY_SIZE,
                got: bytes.len(),
            });
        }

        let mut inner = [0u8; PUBKEY_SIZE];
        inner.copy_from_slice(bytes);

        // Validate cryptographic structure using FIPS 204
        ml_dsa_65::PublicKey::try_from_bytes(inner).map_err(|_| Error::InvalidPublicKey)?;

        Ok(Self { inner })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get Blake3 hash of public key (used as validator ID)
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.inner).as_bytes()
    }

    /// Get inner bytes (for fips204 API)
    pub fn as_bytes(&self) -> &[u8; PUBKEY_SIZE] {
        &self.inner
    }
}

/// Wrapper around ML-DSA-65 secret key
/// SECURITY: Implements ZeroizeOnDrop to securely clear memory when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ValidatorSecretKey {
    inner: [u8; SECRET_KEY_SIZE],
}

impl ValidatorSecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: SECRET_KEY_SIZE,
                got: bytes.len(),
            });
        }

        let mut inner = [0u8; SECRET_KEY_SIZE];
        inner.copy_from_slice(bytes);
        Ok(Self { inner })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get inner bytes (for fips204 API)
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.inner
    }
}

// Note: ZeroizeOnDrop derive macro handles secure memory clearing automatically

/// ML-DSA-65 signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSignature {
    inner: [u8; SIGNATURE_SIZE],
}

impl ValidatorSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidSignatureSize {
                expected: SIGNATURE_SIZE,
                got: bytes.len(),
            });
        }

        let mut inner = [0u8; SIGNATURE_SIZE];
        inner.copy_from_slice(bytes);
        Ok(Self { inner })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get Blake3 hash of signature (for compact storage)
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.inner).as_bytes()
    }

    /// Get inner bytes (for fips204 API)
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.inner
    }
}

/// Validator keypair for easy serialization and storage
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorKeypair {
    /// Public key (1952 bytes)
    #[serde(with = "hex_serde")]
    pub public_key: Vec<u8>,
    /// Secret key (4032 bytes)
    #[serde(with = "hex_serde")]
    pub secret_key: Vec<u8>,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        ::hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

impl ValidatorKeypair {
    /// Create from public and secret keys
    pub fn new(public_key: ValidatorPublicKey, secret_key: ValidatorSecretKey) -> Self {
        Self {
            public_key: public_key.to_bytes().to_vec(),
            secret_key: secret_key.to_bytes().to_vec(),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> Result<ValidatorPublicKey, Error> {
        ValidatorPublicKey::from_bytes(&self.public_key)
    }

    /// Get the secret key
    pub fn secret_key(&self) -> Result<ValidatorSecretKey, Error> {
        ValidatorSecretKey::from_bytes(&self.secret_key)
    }

    /// Save to JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::IoError(format!("Failed to serialize keypair: {}", e)))?;

        std::fs::write(path, json)
            .map_err(|e| Error::IoError(format!("Failed to write keypair file: {}", e)))?;

        Ok(())
    }

    /// Load from JSON file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Error> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::IoError(format!("Failed to read keypair file: {}", e)))?;

        let keypair: Self = serde_json::from_str(&json)
            .map_err(|e| Error::IoError(format!("Failed to parse keypair JSON: {}", e)))?;

        // Validate the keypair
        keypair.public_key()?;
        keypair.secret_key()?;

        Ok(keypair)
    }
}

/// Generate ML-DSA-65 keypair
pub fn keypair() -> (ValidatorPublicKey, ValidatorSecretKey) {
    // SECURITY: Use OsRng for cryptographic key generation
    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = ml_dsa_65::KG::try_keygen_with_rng(&mut rng).expect("ML-DSA-65 keygen failed");

    // Convert to byte arrays
    let pk_bytes = pk.into_bytes();
    let sk_bytes = sk.into_bytes();

    (
        ValidatorPublicKey { inner: pk_bytes },
        ValidatorSecretKey { inner: sk_bytes },
    )
}

/// Generate ML-DSA-65 keypair as a keypair structure
pub fn generate_keypair() -> ValidatorKeypair {
    let (pk, sk) = keypair();
    ValidatorKeypair::new(pk, sk)
}

/// Sign a message with domain separation per FIPS 204
pub fn sign(
    message: &[u8],
    secret_key: &ValidatorSecretKey,
    domain: &[u8],
) -> Result<ValidatorSignature, Error> {
    // Convert byte array back to PrivateKey type
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(*secret_key.as_bytes())
        .map_err(|_| Error::InvalidSecretKey)?;

    // Sign using FIPS 204 API with domain as context parameter
    // SECURITY: Use OsRng for randomized signing
    let mut rng = rand::rngs::OsRng;
    let sig = sk
        .try_sign_with_rng(&mut rng, message, domain)
        .map_err(|_| Error::SigningFailed)?;

    Ok(ValidatorSignature { inner: sig })
}

/// Verify a signature with domain separation per FIPS 204
pub fn verify(
    message: &[u8],
    signature: &ValidatorSignature,
    public_key: &ValidatorPublicKey,
    domain: &[u8],
) -> Result<bool, Error> {
    // Convert byte array back to PublicKey type
    // This validates the public key structure
    let pk = ml_dsa_65::PublicKey::try_from_bytes(*public_key.as_bytes())
        .map_err(|_| Error::InvalidPublicKey)?;

    // Verify using FIPS 204 API with domain as context parameter
    // Returns bool directly (true if valid, false if invalid)
    let is_valid = pk.verify(message, signature.as_bytes(), domain);
    Ok(is_valid)
}

/// Errors for ML-DSA-65 operations
#[derive(Debug)]
pub enum Error {
    /// Invalid key size
    InvalidKeySize {
        /// Expected size
        expected: usize,
        /// Actual size
        got: usize,
    },
    /// Invalid signature size
    InvalidSignatureSize {
        /// Expected size
        expected: usize,
        /// Actual size
        got: usize,
    },
    /// Invalid public key structure (fails FIPS 204 validation)
    InvalidPublicKey,
    /// Invalid secret key structure (fails FIPS 204 validation)
    InvalidSecretKey,
    /// Signing failed
    SigningFailed,
    /// Verification failed
    VerificationFailed,
    /// I/O error (file operations)
    IoError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, got)
            }
            Error::InvalidSignatureSize { expected, got } => {
                write!(
                    f,
                    "Invalid signature size: expected {}, got {}",
                    expected, got
                )
            }
            Error::InvalidPublicKey => write!(f, "Invalid ML-DSA-65 public key structure"),
            Error::InvalidSecretKey => write!(f, "Invalid ML-DSA-65 secret key structure"),
            Error::SigningFailed => write!(f, "ML-DSA-65 signing failed"),
            Error::IoError(msg) => write!(f, "I/O error: {}", msg),
            Error::VerificationFailed => write!(f, "ML-DSA-65 verification failed"),
        }
    }
}

impl std::error::Error for Error {}

// Codec implementations for on-chain storage
impl Encode for ValidatorPublicKey {
    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        dest.write(&self.inner);
    }
}

impl Decode for ValidatorPublicKey {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let mut bytes = [0u8; PUBKEY_SIZE];
        input.read(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| "Invalid ML-DSA-65 public key".into())
    }
}

impl Encode for ValidatorSignature {
    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        dest.write(&self.inner);
    }
}

impl Decode for ValidatorSignature {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        input.read(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| "Invalid ML-DSA-65 signature".into())
    }
}

// Serde implementations for ValidatorSignature
impl serde::Serialize for ValidatorSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.inner))
        } else {
            serializer.serialize_bytes(&self.inner)
        }
    }
}

impl<'de> serde::Deserialize<'de> for ValidatorSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: String = serde::Deserialize::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != SIGNATURE_SIZE {
                return Err(serde::de::Error::custom(format!(
                    "Invalid signature size: expected {}, got {}",
                    SIGNATURE_SIZE,
                    bytes.len()
                )));
            }
            let mut inner = [0u8; SIGNATURE_SIZE];
            inner.copy_from_slice(&bytes);
            Ok(Self { inner })
        } else {
            let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            if bytes.len() != SIGNATURE_SIZE {
                return Err(serde::de::Error::custom(format!(
                    "Invalid signature size: expected {}, got {}",
                    SIGNATURE_SIZE,
                    bytes.len()
                )));
            }
            let mut inner = [0u8; SIGNATURE_SIZE];
            inner.copy_from_slice(&bytes);
            Ok(Self { inner })
        }
    }
}

// Type aliases for eCash mint operations
/// Mint public key (same as validator public key)
pub type MintPublicKey = ValidatorPublicKey;

/// Mint secret key (same as validator secret key)
pub type MintSecretKey = ValidatorSecretKey;

/// Mint signature (same as validator signature)
pub type MintSignature = ValidatorSignature;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa65_keypair_generation() {
        let (pk, sk) = keypair();

        // Check sizes
        assert_eq!(pk.to_bytes().len(), PUBKEY_SIZE);
        assert_eq!(sk.to_bytes().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";

        // Sign with domain separation
        let signature = sign(message, &sk, DST_HEADER).unwrap();

        // Verify
        assert!(verify(message, &signature, &pk, DST_HEADER).unwrap());
    }

    #[test]
    fn test_mldsa65_wrong_domain_fails() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";

        // Sign with DST_HEADER
        let signature = sign(message, &sk, DST_HEADER).unwrap();

        // Verify with DST_VOTE (wrong domain)
        assert!(!verify(message, &signature, &pk, DST_VOTE).unwrap());
    }

    #[test]
    fn test_mldsa65_wrong_message_fails() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";
        let wrong_message = b"Wrong message";

        let signature = sign(message, &sk, DST_HEADER).unwrap();

        // Verify with wrong message
        assert!(!verify(wrong_message, &signature, &pk, DST_HEADER).unwrap());
    }

    #[test]
    fn test_mldsa65_serialization() {
        let (pk, sk) = keypair();

        // Serialize and deserialize public key
        let pk_bytes = pk.to_bytes();
        let pk_recovered = ValidatorPublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk_recovered.to_bytes());

        // Serialize and deserialize secret key
        let sk_bytes = sk.to_bytes();
        let sk_recovered = ValidatorSecretKey::from_bytes(sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk_recovered.to_bytes());
    }

    #[test]
    fn test_mldsa65_pubkey_hash() {
        let (pk, _) = keypair();

        let hash1 = pk.hash();
        let hash2 = pk.hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_mldsa65_signature_size() {
        let (_pk, sk) = keypair();
        let message = b"test";

        let sig = sign(message, &sk, DST_HEADER).unwrap();

        // Verify signature size matches FIPS 204 final standard
        assert_eq!(sig.to_bytes().len(), SIGNATURE_SIZE);
        assert_eq!(SIGNATURE_SIZE, 3309); // NOT 2420 (draft size)
    }

    #[test]
    fn test_mldsa65_codec() {
        use parity_scale_codec::{Decode, Encode};

        let (pk, _) = keypair();

        // Encode
        let encoded = pk.encode();

        // Decode
        let decoded = ValidatorPublicKey::decode(&mut &encoded[..]).unwrap();

        assert_eq!(pk.to_bytes(), decoded.to_bytes());
    }
}
