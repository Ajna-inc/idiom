use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
/// DID-based JWT signature verification
///
/// This module provides real cryptographic signature verification for JWTs
/// signed by DIDs, using DID resolution to get public keys.
use std::sync::Arc;

use did::core::{DidDocument, VerificationMethod, DID};
use did::registry::DidRegistry;

/// Error type for DID verification
#[derive(Debug, thiserror::Error)]
pub enum DidVerificationError {
    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("DID resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Verification method not found: {0}")]
    VerificationMethodNotFound(String),

    #[error("Public key extraction failed: {0}")]
    PublicKeyExtractionFailed(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Invalid JWT format")]
    InvalidJwtFormat,
}

/// DID-based JWT verifier
pub struct DidJwtVerifier {
    did_registry: Arc<DidRegistry>,
}

impl DidJwtVerifier {
    pub fn new(did_registry: Arc<DidRegistry>) -> Self {
        Self { did_registry }
    }

    /// Verify a JWT signed by a DID
    pub async fn verify_jwt(
        &self,
        jwt: &str,
        issuer_did: &str,
    ) -> Result<(Value, Value), DidVerificationError> {
        // Parse JWT parts
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(DidVerificationError::InvalidJwtFormat);
        }

        // Decode header and payload
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_e| DidVerificationError::InvalidJwtFormat)?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_e| DidVerificationError::InvalidJwtFormat)?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_e| DidVerificationError::InvalidJwtFormat)?;

        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|_e| DidVerificationError::InvalidJwtFormat)?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_e| DidVerificationError::InvalidJwtFormat)?;

        // Resolve DID document
        let did = DID::try_from(issuer_did)
            .map_err(|e| DidVerificationError::InvalidDid(e.to_string()))?;

        let did_doc = self
            .did_registry
            .resolve(&did)
            .await
            .map_err(|e| DidVerificationError::ResolutionFailed(e.to_string()))?;

        // Get verification method ID from kid header or derive from DID
        // For DID-based issuers, if the kid is a UUID (wallet key ID), we should
        // ignore it and use the issuer DID to find the verification method
        let verification_method_id = if let Some(kid) = header.get("kid").and_then(|v| v.as_str()) {
            // Check if kid looks like a DID-based verification method
            if kid.starts_with("did:") {
                kid.to_string()
            } else {
                // kid is probably a wallet UUID, derive from issuer DID instead
                issuer_did.to_string()
            }
        } else {
            // No kid, use issuer DID
            issuer_did.to_string()
        };

        // Find verification method in DID document
        let verification_method =
            self.find_verification_method(&did_doc, &verification_method_id)?;

        // Extract public key
        let public_key = self.extract_public_key(verification_method)?;

        // Get algorithm from header
        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or(DidVerificationError::InvalidJwtFormat)?;

        // Verify signature
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        self.verify_signature(
            signing_input.as_bytes(),
            &signature_bytes,
            &public_key,
            alg,
            &verification_method.type_,
        )?;

        Ok((header, payload))
    }

    /// Find verification method in DID document
    fn find_verification_method<'a>(
        &self,
        did_doc: &'a DidDocument,
        vm_id: &str,
    ) -> Result<&'a VerificationMethod, DidVerificationError> {
        // Check verification_method array
        for vm in &did_doc.verification_method {
            if vm.id == vm_id || vm.id.ends_with(&format!("#{}", vm_id)) {
                return Ok(vm);
            }
        }

        // If not found, check if it's the DID itself (for did:key)
        if vm_id == did_doc.id && !did_doc.verification_method.is_empty() {
            return Ok(&did_doc.verification_method[0]);
        }

        Err(DidVerificationError::VerificationMethodNotFound(
            vm_id.to_string(),
        ))
    }

    /// Extract public key from verification method
    fn extract_public_key(&self, vm: &VerificationMethod) -> Result<Vec<u8>, DidVerificationError> {
        // Try different public key encodings

        // 1. publicKeyBase58
        if let Some(ref pk_b58) = vm.public_key_base58 {
            return bs58::decode(pk_b58).into_vec().map_err(|e| {
                DidVerificationError::PublicKeyExtractionFailed(format!(
                    "Base58 decode failed: {}",
                    e
                ))
            });
        }

        // 2. publicKeyMultibase
        if let Some(ref pk_mb) = vm.public_key_multibase {
            let (_base, decoded) = multibase::decode(pk_mb).map_err(|e| {
                DidVerificationError::PublicKeyExtractionFailed(format!(
                    "Multibase decode failed: {}",
                    e
                ))
            })?;

            // Strip multicodec prefix if present
            if decoded.len() > 2 && (decoded[0] == 0xed || decoded[0] == 0xec) {
                return Ok(decoded[2..].to_vec());
            }
            return Ok(decoded);
        }

        // 3. publicKeyJwk
        if let Some(ref pk_jwk) = vm.public_key_jwk {
            return self.extract_key_from_jwk(pk_jwk);
        }

        Err(DidVerificationError::PublicKeyExtractionFailed(
            "No public key found in verification method".to_string(),
        ))
    }

    /// Extract key bytes from JWK
    fn extract_key_from_jwk(&self, jwk: &Value) -> Result<Vec<u8>, DidVerificationError> {
        let kty = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
            DidVerificationError::PublicKeyExtractionFailed("Missing 'kty' in JWK".to_string())
        })?;

        match kty {
            "OKP" => {
                // Ed25519 or X25519
                let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                    DidVerificationError::PublicKeyExtractionFailed(
                        "Missing 'x' in OKP JWK".to_string(),
                    )
                })?;

                URL_SAFE_NO_PAD.decode(x).map_err(|e| {
                    DidVerificationError::PublicKeyExtractionFailed(format!(
                        "Failed to decode 'x': {}",
                        e
                    ))
                })
            }
            "EC" => {
                // P-256, P-384, etc.
                // For now, we'll extract x and y coordinates
                // Full implementation would construct the proper public key
                let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                    DidVerificationError::PublicKeyExtractionFailed(
                        "Missing 'x' in EC JWK".to_string(),
                    )
                })?;
                let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                    DidVerificationError::PublicKeyExtractionFailed(
                        "Missing 'y' in EC JWK".to_string(),
                    )
                })?;

                let x_bytes = URL_SAFE_NO_PAD.decode(x).map_err(|e| {
                    DidVerificationError::PublicKeyExtractionFailed(format!(
                        "Failed to decode 'x': {}",
                        e
                    ))
                })?;
                let y_bytes = URL_SAFE_NO_PAD.decode(y).map_err(|e| {
                    DidVerificationError::PublicKeyExtractionFailed(format!(
                        "Failed to decode 'y': {}",
                        e
                    ))
                })?;

                // Combine x and y (uncompressed format)
                let mut public_key = vec![0x04]; // Uncompressed point indicator
                public_key.extend_from_slice(&x_bytes);
                public_key.extend_from_slice(&y_bytes);
                Ok(public_key)
            }
            _ => Err(DidVerificationError::UnsupportedKeyType(kty.to_string())),
        }
    }

    /// Verify signature using the appropriate algorithm
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        alg: &str,
        vm_type: &str,
    ) -> Result<(), DidVerificationError> {
        match (alg, vm_type) {
            ("EdDSA", "Ed25519VerificationKey2018")
            | ("EdDSA", "Ed25519VerificationKey2020")
            | ("EdDSA", "JsonWebKey2020") => self.verify_ed25519(message, signature, public_key),
            ("ES256", "EcdsaSecp256r1VerificationKey2019") | ("ES256", "JsonWebKey2020") => {
                self.verify_es256(message, signature, public_key)
            }
            _ => Err(DidVerificationError::UnsupportedKeyType(format!(
                "Unsupported algorithm/type combination: {} / {}",
                alg, vm_type
            ))),
        }
    }

    /// Verify Ed25519 signature
    fn verify_ed25519(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), DidVerificationError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Validate public key length
        if public_key.len() != 32 {
            return Err(DidVerificationError::PublicKeyExtractionFailed(format!(
                "Invalid Ed25519 public key length: {}",
                public_key.len()
            )));
        }

        // Validate signature length
        if signature.len() != 64 {
            return Err(DidVerificationError::SignatureVerificationFailed(format!(
                "Invalid Ed25519 signature length: {}",
                signature.len()
            )));
        }

        // Convert to array
        let pk_array: [u8; 32] = public_key.try_into().map_err(|_| {
            DidVerificationError::PublicKeyExtractionFailed(
                "Failed to convert public key to array".to_string(),
            )
        })?;

        let sig_array: [u8; 64] = signature.try_into().map_err(|_| {
            DidVerificationError::SignatureVerificationFailed(
                "Failed to convert signature to array".to_string(),
            )
        })?;

        // Create public key
        let pk = VerifyingKey::from_bytes(&pk_array).map_err(|e| {
            DidVerificationError::PublicKeyExtractionFailed(format!(
                "Failed to parse Ed25519 public key: {}",
                e
            ))
        })?;

        // Create signature
        let sig = Signature::from_bytes(&sig_array);

        // Verify
        pk.verify(message, &sig).map_err(|e| {
            DidVerificationError::SignatureVerificationFailed(format!(
                "Ed25519 signature verification failed: {}",
                e
            ))
        })
    }

    /// Verify ES256 (P-256) signature
    fn verify_es256(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), DidVerificationError> {
        use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
        use sha2::{Digest, Sha256};

        // Hash the message with SHA-256 (ES256 = ECDSA with SHA-256)
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = hasher.finalize();

        // Create verifying key from public key bytes
        let vk = VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            DidVerificationError::PublicKeyExtractionFailed(format!(
                "Failed to parse P-256 public key: {}",
                e
            ))
        })?;

        // Create signature from bytes
        let sig = Signature::from_bytes(signature.into()).map_err(|e| {
            DidVerificationError::SignatureVerificationFailed(format!(
                "Failed to parse ECDSA signature: {}",
                e
            ))
        })?;

        // Verify
        vk.verify(&message_hash, &sig).map_err(|e| {
            DidVerificationError::SignatureVerificationFailed(format!(
                "ES256 signature verification failed: {}",
                e
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_key_from_jwk_okp() {
        let verifier = DidJwtVerifier::new(Arc::new(DidRegistry::new()));

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });

        let result = verifier.extract_key_from_jwk(&jwk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32); // Ed25519 public key is 32 bytes
    }

    #[test]
    fn test_find_verification_method() {
        let verifier = DidJwtVerifier::new(Arc::new(DidRegistry::new()));

        let vm = VerificationMethod {
            id: "did:example:123#key-1".to_string(),
            type_: "Ed25519VerificationKey2018".to_string(),
            controller: "did:example:123".to_string(),
            public_key_base58: Some("HBTcN2MrXNRj9xF9oi8QqYyuEPY3RELHBLfQQQYUb5".to_string()),
            public_key_jwk: None,
            public_key_multibase: None,
        };

        let did_doc = DidDocument {
            id: "did:example:123".to_string(),
            context: Some(serde_json::json!("https://www.w3.org/ns/did/v1")),
            verification_method: vec![vm],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            also_known_as: vec![],
            controller: None,
        };

        let result = verifier.find_verification_method(&did_doc, "did:example:123#key-1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, "did:example:123#key-1");
    }
}
