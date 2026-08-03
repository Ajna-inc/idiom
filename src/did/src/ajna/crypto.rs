//! Cryptographic primitives for did:ajna
//!
//! This module implements the cryptographic operations for did:ajna,
//! including Blake3 hashing with domain separation tags.

use blake3;

/// Domain Separation Tags (DSTs)
pub const DST_AJNA_ROOT: &[u8] = b"AJNA/ROOT/V1";
pub const DST_AJNA_OP: &[u8] = b"AJNA/OP/V1";
pub const DST_AJNA_SIGN: &[u8] = b"AJNA/SIGN/V1";
pub const DST_AJNA_FIELD: &[u8] = b"AJNA/FIELD/V1";

/// Hash size in bytes (Blake3 produces 32 bytes)
pub const HASH_SIZE: usize = 32;

/// Hash type (32-byte array)
pub type Hash = [u8; HASH_SIZE];

/// Hash data with Blake3 using a domain separation tag
///
/// # Arguments
/// * `dst` - Domain separation tag
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte Blake3 hash
pub fn hash_with_dst(dst: &[u8], data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(dst);
    hasher.update(data);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Hash an operation to produce op_id
///
/// Uses DST_AJNA_OP
pub fn hash_operation(canonical_bytes: &[u8]) -> Hash {
    hash_with_dst(DST_AJNA_OP, canonical_bytes)
}

/// Hash for signature generation
///
/// Uses DST_AJNA_SIGN
pub fn hash_for_signature(canonical_bytes: &[u8]) -> Hash {
    hash_with_dst(DST_AJNA_SIGN, canonical_bytes)
}

/// Hash for Merkle root computation
///
/// Uses DST_AJNA_ROOT
pub fn hash_merkle_root(data: &[u8]) -> Hash {
    hash_with_dst(DST_AJNA_ROOT, data)
}

/// Hash a field for selective disclosure
///
/// Uses DST_AJNA_FIELD
pub fn hash_field(path: &str, value: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DST_AJNA_FIELD);
    hasher.update(path.as_bytes());
    hasher.update(value);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Convert hash to base64url string (for op_id)
pub fn hash_to_base64url(hash: &Hash) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(hash)
}

/// Convert base64url string back to hash
pub fn base64url_to_hash(s: &str) -> Result<Hash, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("Invalid base64url: {}", e))?;

    if bytes.len() != HASH_SIZE {
        return Err(format!(
            "Invalid hash size: expected {}, got {}",
            HASH_SIZE,
            bytes.len()
        ));
    }

    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Merkle pair hash (for Merkle tree construction)
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DST_AJNA_ROOT);
    hasher.update(left);
    hasher.update(right);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_with_dst() {
        let data = b"test data";
        let hash1 = hash_with_dst(DST_AJNA_OP, data);
        let hash2 = hash_with_dst(DST_AJNA_OP, data);

        // Deterministic
        assert_eq!(hash1, hash2);

        // Different DST produces different hash
        let hash3 = hash_with_dst(DST_AJNA_SIGN, data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_operation() {
        let op_bytes = b"canonical operation bytes";
        let hash = hash_operation(op_bytes);
        assert_eq!(hash.len(), HASH_SIZE);
    }

    #[test]
    fn test_hash_to_base64url() {
        let hash = [0u8; HASH_SIZE];
        let b64 = hash_to_base64url(&hash);

        // base64url of 32 zero bytes
        assert_eq!(b64.len(), 43); // ceil(32 * 8 / 6) = 43
        assert!(!b64.contains('=')); // No padding
        assert!(!b64.contains('+')); // URL-safe
        assert!(!b64.contains('/')); // URL-safe
    }

    #[test]
    fn test_base64url_roundtrip() {
        let original = [42u8; HASH_SIZE];
        let b64 = hash_to_base64url(&original);
        let decoded = base64url_to_hash(&b64).expect("Failed to decode");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hash_pair() {
        let left = [1u8; HASH_SIZE];
        let right = [2u8; HASH_SIZE];

        let hash1 = hash_pair(&left, &right);
        let hash2 = hash_pair(&left, &right);

        // Deterministic
        assert_eq!(hash1, hash2);

        // Order matters (not commutative)
        let hash3 = hash_pair(&right, &left);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_different_dsts_produce_different_hashes() {
        let data = b"same data";

        let h1 = hash_with_dst(DST_AJNA_OP, data);
        let h2 = hash_with_dst(DST_AJNA_SIGN, data);
        let h3 = hash_with_dst(DST_AJNA_ROOT, data);
        let h4 = hash_with_dst(DST_AJNA_FIELD, data);

        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h1, h4);
        assert_ne!(h2, h3);
        assert_ne!(h2, h4);
        assert_ne!(h3, h4);
    }
}
