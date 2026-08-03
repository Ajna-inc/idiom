//! Key type utilities for quantum-resistant cryptography

use agent_core::traits::KeyType;

use crate::askar::error::Result;

/// Get the signature algorithm name for a key type
pub fn signature_algorithm_for_key_type(key_type: KeyType) -> Result<&'static str> {
    match key_type {
        // Quantum-resistant algorithms
        KeyType::SLHDSA => Ok("SLH-DSA-SHAKE-128s"),
        KeyType::MLDSA65 => Ok("ML-DSA-65"),

        // Classical algorithms (for SSI interoperability)
        KeyType::Ed25519 => Ok("Ed25519"),
        KeyType::X25519 => Ok("X25519"),
        KeyType::P256 | KeyType::EcdsaSecp256r1 => Ok("ES256"),
        KeyType::Bls12381G1 => Ok("BLS12381_G1"),
        KeyType::Bls12381G2 => Ok("BLS12381_G2"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithms() {
        assert_eq!(
            signature_algorithm_for_key_type(KeyType::SLHDSA).unwrap(),
            "SLH-DSA-SHAKE-128s"
        );
        assert_eq!(
            signature_algorithm_for_key_type(KeyType::MLDSA65).unwrap(),
            "ML-DSA-65"
        );
    }
}
