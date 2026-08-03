use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
/// SD-JWT Hasher for creating disclosure digests
use sha2::{Digest, Sha256};

/// Hasher for SD-JWT disclosures
#[derive(Debug, Clone)]
pub struct SdJwtHasher {
    algorithm: HashAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    // Add more algorithms as needed
}

impl Default for SdJwtHasher {
    fn default() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
        }
    }
}

impl SdJwtHasher {
    /// Create a new hasher with specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Get the algorithm identifier string
    pub fn algorithm_identifier(&self) -> &str {
        match self.algorithm {
            HashAlgorithm::Sha256 => "sha-256",
        }
    }

    /// Hash a disclosure string
    pub fn hash_disclosure(&self, disclosure: &str) -> String {
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(disclosure.as_bytes());
                let result = hasher.finalize();
                URL_SAFE_NO_PAD.encode(result)
            }
        }
    }

    /// Hash multiple disclosures
    pub fn hash_disclosures(&self, disclosures: &[String]) -> Vec<String> {
        disclosures
            .iter()
            .map(|d| self.hash_disclosure(d))
            .collect()
    }

    /// Create a salt for disclosure (16 bytes, base64url encoded)
    pub fn create_salt() -> String {
        use rand::Rng;
        let salt: [u8; 16] = rand::thread_rng().gen();
        URL_SAFE_NO_PAD.encode(salt)
    }

    /// Hash the SD-JWT for key binding
    pub fn hash_sd_jwt(&self, sd_jwt: &str) -> String {
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(sd_jwt.as_bytes());
                let result = hasher.finalize();
                URL_SAFE_NO_PAD.encode(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_disclosure() {
        let hasher = SdJwtHasher::default();
        let disclosure = "test_disclosure";
        let hash = hasher.hash_disclosure(disclosure);

        // Hash should be base64url encoded
        assert!(!hash.contains('+'));
        assert!(!hash.contains('/'));
        assert!(!hash.contains('='));

        // Hash should be deterministic
        let hash2 = hasher.hash_disclosure(disclosure);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_create_salt() {
        let salt1 = SdJwtHasher::create_salt();
        let salt2 = SdJwtHasher::create_salt();

        // Salts should be different
        assert_ne!(salt1, salt2);

        // Salts should be base64url encoded
        assert!(!salt1.contains('+'));
        assert!(!salt1.contains('/'));
        assert!(!salt1.contains('='));
    }

    #[test]
    fn test_algorithm_identifier() {
        let hasher = SdJwtHasher::new(HashAlgorithm::Sha256);
        assert_eq!(hasher.algorithm_identifier(), "sha-256");
    }
}
