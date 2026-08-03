//! SLH-DSA signatures for users (NIST FIPS 205)
//! Quantum-resistant hash-based signatures
//! Formerly known as SPHINCS+ in draft standards

use fips205::slh_dsa_shake_128s; // FIPS 205 compliant
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use parity_scale_codec::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key size in bytes (SLH-DSA-SHAKE-128s)
pub const PUBKEY_SIZE: usize = 32;

/// Secret key size in bytes (SLH-DSA-SHAKE-128s)
pub const SECRET_KEY_SIZE: usize = 64;

/// Signature size in bytes (SLH-DSA-SHAKE-128s) - Store off-chain!
pub const SIGNATURE_SIZE: usize = 7856;

/// Domain separation tag for transactions
pub const DST_TRANSACTION: &[u8] = b"AJNA/SLHDSA/TX/V1";

/// Domain separation tag for DID updates
pub const DST_DID_UPDATE: &[u8] = b"AJNA/SLHDSA/DID/V1";

/// Wrapper around SLH-DSA public key with codec support
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPublicKey {
    inner: [u8; PUBKEY_SIZE],
}

impl UserPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBKEY_SIZE {
            return Err(Error::InvalidKeySize {
                expected: PUBKEY_SIZE,
                got: bytes.len(),
            });
        }

        let mut inner = [0u8; PUBKEY_SIZE];
        inner.copy_from_slice(bytes);
        Ok(Self { inner })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Derive 20-byte address from public key (Blake3 hash)
    pub fn to_address(&self) -> [u8; 20] {
        let hash = blake3::hash(&self.inner);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash.as_bytes()[0..20]);
        address
    }

    /// Derive DID from public key (did:ajna:<base58-hash>)
    pub fn to_did(&self) -> String {
        let hash = blake3::hash(&self.inner);
        format!("did:ajna:{}", bs58::encode(hash.as_bytes()).into_string())
    }

    /// Get inner bytes (for fips205 API)
    pub fn as_bytes(&self) -> &[u8; PUBKEY_SIZE] {
        &self.inner
    }
}

/// Wrapper around SLH-DSA secret key
/// SECURITY: Implements ZeroizeOnDrop to securely clear memory when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UserSecretKey {
    inner: [u8; SECRET_KEY_SIZE],
}

impl UserSecretKey {
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

    /// Get inner bytes (for fips205 API)
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.inner
    }
}

// Note: ZeroizeOnDrop derive macro handles secure memory clearing automatically

/// SLH-DSA signature (large, store off-chain!)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSignature {
    inner: Vec<u8>, // Vec because 7856 bytes is too large for stack
}

impl UserSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidSignatureSize {
                expected: SIGNATURE_SIZE,
                got: bytes.len(),
            });
        }

        Ok(Self {
            inner: bytes.to_vec(),
        })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get Blake3 hash of signature (for compact on-chain storage)
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.inner).as_bytes()
    }

    /// Get inner bytes (for fips205 API)
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }
}

/// Generate SLH-DSA keypair
pub fn keypair() -> (UserPublicKey, UserSecretKey) {
    // SECURITY: Use OsRng for cryptographic key generation
    let mut rng = rand::rngs::OsRng;
    let (pk, sk) =
        slh_dsa_shake_128s::KG::try_keygen_with_rng(&mut rng).expect("SLH-DSA keygen failed");

    // Convert to byte arrays
    let pk_bytes = pk.into_bytes();
    let sk_bytes = sk.into_bytes();

    (
        UserPublicKey { inner: pk_bytes },
        UserSecretKey { inner: sk_bytes },
    )
}

/// Generate SLH-DSA keypair from seed (deterministic)
///
/// Uses the seed to derive a deterministic keypair
pub fn keypair_from_seed(seed: &[u8; 32]) -> Result<(UserPublicKey, UserSecretKey), Error> {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Create deterministic RNG from seed
    let mut rng = ChaCha20Rng::from_seed(*seed);

    let (pk, sk) =
        slh_dsa_shake_128s::KG::try_keygen_with_rng(&mut rng).map_err(|_| Error::SigningFailed)?;

    // Convert to byte arrays
    let pk_bytes = pk.into_bytes();
    let sk_bytes = sk.into_bytes();

    Ok((
        UserPublicKey { inner: pk_bytes },
        UserSecretKey { inner: sk_bytes },
    ))
}

/// Sign a message with domain separation
/// Note: Uses hedged signing (randomized) for additional security
pub fn sign(
    message: &[u8],
    secret_key: &UserSecretKey,
    domain: &[u8],
) -> Result<UserSignature, Error> {
    // Prepend domain separator to message
    let mut msg_with_domain = domain.to_vec();
    msg_with_domain.extend_from_slice(message);

    // Convert byte array back to PrivateKey type (no dereference for fips205)
    let sk = slh_dsa_shake_128s::PrivateKey::try_from_bytes(secret_key.as_bytes())
        .map_err(|_| Error::SigningFailed)?;

    // Sign using API (hedged = true for randomized signing)
    let sig = sk
        .try_sign(&msg_with_domain, &[], true)
        .map_err(|_| Error::SigningFailed)?;

    Ok(UserSignature {
        inner: sig.to_vec(),
    })
}

/// Verify a signature with domain separation
pub fn verify(
    message: &[u8],
    signature: &UserSignature,
    public_key: &UserPublicKey,
    domain: &[u8],
) -> Result<bool, Error> {
    // Prepend domain separator to message
    let mut msg_with_domain = domain.to_vec();
    msg_with_domain.extend_from_slice(message);

    // Convert byte array back to PublicKey type (no dereference for fips205)
    let pk = slh_dsa_shake_128s::PublicKey::try_from_bytes(public_key.as_bytes())
        .map_err(|_| Error::VerificationFailed)?;

    // Verify using API (returns bool, not Result)
    // Need to convert Vec<u8> to &[u8; 7856] for signature
    if signature.inner.len() != SIGNATURE_SIZE {
        return Err(Error::InvalidSignatureSize {
            expected: SIGNATURE_SIZE,
            got: signature.inner.len(),
        });
    }
    let sig_array: &[u8; SIGNATURE_SIZE] = signature
        .inner
        .as_slice()
        .try_into()
        .map_err(|_| Error::VerificationFailed)?;

    let is_valid = pk.verify(&msg_with_domain, sig_array, &[]);
    Ok(is_valid)
}

/// Errors for SLH-DSA operations
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
    /// Signing failed
    SigningFailed,
    /// Verification failed
    VerificationFailed,
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
            Error::SigningFailed => write!(f, "SLH-DSA signing failed"),
            Error::VerificationFailed => write!(f, "SLH-DSA verification failed"),
        }
    }
}

impl std::error::Error for Error {}

// Codec implementations for on-chain storage
impl Encode for UserPublicKey {
    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        dest.write(&self.inner);
    }
}

impl Decode for UserPublicKey {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let mut bytes = [0u8; PUBKEY_SIZE];
        input.read(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| "Invalid SLH-DSA public key".into())
    }
}

// Note: UserSignature codec stores only the hash on-chain (32 bytes)
// Full signature (7856 bytes) must be stored off-chain
impl Encode for UserSignature {
    fn encode_to<W: parity_scale_codec::Output + ?Sized>(&self, dest: &mut W) {
        // Only encode the hash, not the full signature
        let hash = self.hash();
        dest.write(&hash);
    }
}

impl Decode for UserSignature {
    fn decode<I: parity_scale_codec::Input>(
        _input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        // Cannot decode signature from hash alone
        Err("Cannot decode UserSignature from hash - must provide full signature".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slhdsa_keypair_generation() {
        let (pk, sk) = keypair();

        // Check sizes
        assert_eq!(pk.to_bytes().len(), PUBKEY_SIZE);
        assert_eq!(sk.to_bytes().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_slhdsa_sign_verify() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";

        // Sign with domain separation
        let signature = sign(message, &sk, DST_TRANSACTION).unwrap();

        // Verify
        assert!(verify(message, &signature, &pk, DST_TRANSACTION).unwrap());
    }

    #[test]
    fn test_slhdsa_wrong_domain_fails() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";

        // Sign with DST_TRANSACTION
        let signature = sign(message, &sk, DST_TRANSACTION).unwrap();

        // Verify with DST_DID_UPDATE (wrong domain)
        assert!(!verify(message, &signature, &pk, DST_DID_UPDATE).unwrap());
    }

    #[test]
    fn test_slhdsa_wrong_message_fails() {
        let (pk, sk) = keypair();
        let message = b"Hello, Ajna!";
        let wrong_message = b"Wrong message";

        let signature = sign(message, &sk, DST_TRANSACTION).unwrap();

        // Verify with wrong message
        assert!(!verify(wrong_message, &signature, &pk, DST_TRANSACTION).unwrap());
    }

    #[test]
    fn test_slhdsa_serialization() {
        let (pk, sk) = keypair();

        // Serialize and deserialize public key
        let pk_bytes = pk.to_bytes();
        let pk_recovered = UserPublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk_recovered.to_bytes());

        // Serialize and deserialize secret key
        let sk_bytes = sk.to_bytes();
        let sk_recovered = UserSecretKey::from_bytes(sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk_recovered.to_bytes());
    }

    #[test]
    fn test_slhdsa_address_derivation() {
        let (pk, _) = keypair();

        let address1 = pk.to_address();
        let address2 = pk.to_address();

        // Address should be deterministic
        assert_eq!(address1, address2);

        // Address should be 20 bytes
        assert_eq!(address1.len(), 20);
    }

    #[test]
    fn test_slhdsa_did_derivation() {
        let (pk, _) = keypair();

        let did = pk.to_did();

        // DID should start with "did:ajna:"
        assert!(did.starts_with("did:ajna:"));

        // DID should be deterministic
        assert_eq!(did, pk.to_did());
    }

    #[test]
    fn test_slhdsa_signature_size() {
        let (_pk, sk) = keypair();
        let message = b"test";

        let sig = sign(message, &sk, DST_TRANSACTION).unwrap();

        // Verify signature size matches FIPS 205 standard
        assert_eq!(sig.to_bytes().len(), SIGNATURE_SIZE);
        assert_eq!(SIGNATURE_SIZE, 7856);
    }

    #[test]
    fn test_slhdsa_signature_hash() {
        let (_pk, sk) = keypair();
        let message = b"test";

        let sig = sign(message, &sk, DST_TRANSACTION).unwrap();

        let hash1 = sig.hash();
        let hash2 = sig.hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_slhdsa_codec_pubkey() {
        use parity_scale_codec::{Decode, Encode};

        let (pk, _) = keypair();

        // Encode
        let encoded = pk.encode();

        // Decode
        let decoded = UserPublicKey::decode(&mut &encoded[..]).unwrap();

        assert_eq!(pk.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_slhdsa_signature_codec_hash_only() {
        use parity_scale_codec::Encode;

        let (_pk, sk) = keypair();
        let message = b"test";

        let sig = sign(message, &sk, DST_TRANSACTION).unwrap();

        // Encode signature (should only encode hash, 32 bytes)
        let encoded = sig.encode();

        // Verify only hash is encoded, not full signature
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, sig.hash());
    }
}
