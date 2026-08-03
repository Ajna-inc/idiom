//! did:key Method Implementation
//!
//! Implements did:key creation and resolution using Askar's cryptography.
//! This avoids dependency conflicts with external did-key crates.
//!
//! # Format
//! did:key:z<multibase-multicodec-pubkey>
//!
//! # Example
//! did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::core::{
    CreateDidOptions, CreateDidResult, DidCreator, DidDocument, DidDocumentKey, DidRecord,
    DidResolver, DidRole, ResolutionError, ResolutionResult, VerificationMethod,
    VerificationRelationship, DID,
};
use agent_core::traits::{KeyPurpose, KeyType, WalletProvider};

/// Strip the base58btc multibase `z` prefix + 2-byte multicodec prefix from a
/// multibase key (e.g. `z6Mk…` Ed25519, `z6LS…` X25519) to recover the raw
/// base58 verkey. Returns `None` if the input is not `z`-multibase or too short.
///
/// Canonical converter: agent / didcomm / connections code should delegate here
/// rather than re-implementing the `bs58 decode → [2..] → encode` idiom.
pub fn multibase_to_base58_verkey(multibase: &str) -> Option<String> {
    let body = multibase.strip_prefix('z')?;
    let decoded = bs58::decode(body).into_vec().ok()?;
    if decoded.len() <= 2 {
        return None;
    }
    Some(bs58::encode(&decoded[2..]).into_string())
}

/// Convert a `did:key:z…` DID (tolerating a trailing `#fragment`) to its raw
/// base58 verkey. Returns `None` for non-`did:key:` input or a malformed key.
/// Delegates to [`multibase_to_base58_verkey`].
pub fn did_key_to_base58_verkey(did_key: &str) -> Option<String> {
    let did_key = did_key.split('#').next().unwrap_or(did_key);
    let multibase = did_key.strip_prefix("did:key:")?;
    multibase_to_base58_verkey(multibase)
}

/// did:key Resolver - Resolves did:key DIDs to DID Documents
pub struct KeyDidResolver;

impl Default for KeyDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDidResolver {
    pub fn new() -> Self {
        Self
    }

    /// Parse multibase-encoded public key from did:key
    fn parse_did_key(did: &str) -> Result<(Vec<u8>, KeyType), ResolutionError> {
        // did:key:z6Mkp... -> z6Mkp...
        let key_part = did
            .strip_prefix("did:key:")
            .ok_or_else(|| ResolutionError::InvalidDid("Invalid did:key format".to_string()))?;

        // Strip fragment if present (e.g., "z6Mk...#z6Mk..." -> "z6Mk...")
        // DID URLs can include fragments; we only need the key part
        let key_part = key_part.split('#').next().unwrap_or(key_part);

        // Decode multibase
        let (_base, decoded) = multibase::decode(key_part).map_err(|e| {
            ResolutionError::ResolutionFailed(format!("Multibase decode failed: {}", e))
        })?;

        if decoded.len() < 2 {
            return Err(ResolutionError::ResolutionFailed(
                "Multicodec too short".to_string(),
            ));
        }

        // Parse multicodec prefix
        let (key_type, public_key) = match (decoded[0], decoded[1]) {
            // Ed25519 public key: 0xed 0x01
            (0xed, 0x01) => (KeyType::Ed25519, decoded[2..].to_vec()),
            // X25519 public key: 0xec 0x01
            (0xec, 0x01) => (KeyType::X25519, decoded[2..].to_vec()),
            _ => {
                return Err(ResolutionError::ResolutionFailed(format!(
                    "Unsupported multicodec: 0x{:02x}{:02x}",
                    decoded[0], decoded[1]
                )))
            }
        };

        Ok((public_key, key_type))
    }

    /// Create DID Document from did:key
    fn create_did_document(
        did: &DID,
        public_key: &[u8],
        key_type: KeyType,
    ) -> Result<DidDocument, ResolutionError> {
        let did_str = did.as_str();

        // Create verification method ID (the full DID with #fragment)
        let key_id = format!("{}#{}", did_str, &did_str["did:key:".len()..]);

        // Encode public key as base58
        let public_key_base58 = bs58::encode(public_key).into_string();

        // Determine verification method type
        let vm_type = match key_type {
            KeyType::Ed25519 => "Ed25519VerificationKey2018",
            KeyType::X25519 => "X25519KeyAgreementKey2019",
            _ => {
                return Err(ResolutionError::ResolutionFailed(
                    "Unsupported key type for did:key".to_string(),
                ))
            }
        };

        let verification_method = VerificationMethod {
            id: key_id.clone(),
            type_: vm_type.to_string(),
            controller: did_str.to_string(),
            public_key_base58: Some(public_key_base58),
            public_key_jwk: None,
            public_key_multibase: None,
        };

        let mut verification_methods = vec![verification_method];

        // For Ed25519 keys, also add the derived X25519 key for key agreement
        let mut key_agreement_refs = vec![];
        if key_type == KeyType::Ed25519 {
            // Convert Ed25519 public key to X25519 using the canonical
            // free helper in `crate::methods::x25519`.
            let x25519_key = crate::methods::x25519::ed25519_public_to_x25519(public_key)
                .map(|arr| arr.to_vec())
                .map_err(|e| {
                    ResolutionError::ResolutionFailed(format!(
                        "Ed25519 to X25519 conversion failed: {}",
                        e
                    ))
                })?;

            // Create multicodec for X25519: 0xec 0x01
            let mut x25519_multicodec = vec![0xec, 0x01];
            x25519_multicodec.extend_from_slice(&x25519_key);

            // Encode as did:key
            let x25519_did_key = multibase::encode(multibase::Base::Base58Btc, &x25519_multicodec);
            let x25519_key_id = format!("{}#{}", did_str, x25519_did_key);

            // Encode X25519 key as base58
            let x25519_base58 = bs58::encode(&x25519_key).into_string();

            // Create X25519 verification method for key agreement
            let x25519_vm = VerificationMethod {
                id: x25519_key_id.clone(),
                type_: "X25519KeyAgreementKey2019".to_string(),
                controller: did_str.to_string(),
                public_key_base58: Some(x25519_base58),
                public_key_jwk: None,
                public_key_multibase: None,
            };

            verification_methods.push(x25519_vm);
            key_agreement_refs.push(VerificationRelationship::Reference(x25519_key_id));
        }

        let mut doc = DidDocument {
            id: did_str.to_string(),
            verification_method: verification_methods,
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: key_agreement_refs,
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            context: None,
            also_known_as: vec![],
            controller: None,
        };

        // Ed25519 is used for authentication, X25519 for key agreement
        match key_type {
            KeyType::Ed25519 => {
                doc.authentication.push(VerificationRelationship::Reference(key_id.clone()));
                doc.assertion_method.push(VerificationRelationship::Reference(key_id.clone()));
                doc.capability_invocation.push(VerificationRelationship::Reference(key_id.clone()));
                doc.capability_delegation.push(VerificationRelationship::Reference(key_id.clone()));
            }
            KeyType::X25519
                // For pure X25519 keys, add to key_agreement
                if doc.key_agreement.is_empty() => {
                    doc.key_agreement.push(VerificationRelationship::Reference(key_id));
                }
            _ => {}
        }

        Ok(doc)
    }

    // Ed25519 → X25519 lives in `crate::methods::x25519::ed25519_public_to_x25519`
    // — the canonical free function for the workspace.
}

#[async_trait]
impl DidResolver for KeyDidResolver {
    fn method_name(&self) -> &str {
        "key"
    }

    fn allows_caching(&self) -> bool {
        false // did:key is deterministic, no caching needed
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        let (public_key, key_type) = Self::parse_did_key(did.as_str())?;
        Self::create_did_document(did, &public_key, key_type)
    }
}

/// did:key Creator - Creates new did:key DIDs and stores keys in wallet
pub struct KeyDidCreator {
    wallet: Arc<dyn WalletProvider>,
}

impl KeyDidCreator {
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        Self { wallet }
    }

    /// Encode public key as did:key
    fn encode_did_key(public_key: &[u8], key_type: KeyType) -> Result<String, ResolutionError> {
        // Multicodec prefix for Ed25519 or X25519
        let multicodec = match key_type {
            KeyType::Ed25519 => vec![0xed, 0x01],
            KeyType::X25519 => vec![0xec, 0x01],
            _ => {
                return Err(ResolutionError::ResolutionFailed(
                    "Unsupported key type for did:key".to_string(),
                ))
            }
        };

        // Combine multicodec + public key
        let mut multicodec_key = multicodec;
        multicodec_key.extend_from_slice(public_key);

        // Encode as multibase (base58btc = 'z' prefix)
        let encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec_key);

        Ok(format!("did:key:{}", encoded))
    }
}

#[async_trait]
impl DidCreator for KeyDidCreator {
    async fn create(&self, options: CreateDidOptions) -> ResolutionResult<CreateDidResult> {
        // Use Ed25519 by default for did:key
        let key_type_str = options.key_type.as_deref().unwrap_or("Ed25519");
        let key_type = match key_type_str {
            "Ed25519" => KeyType::Ed25519,
            "X25519" => KeyType::X25519,
            _ => {
                return Err(ResolutionError::ResolutionFailed(format!(
                    "did:key only supports Ed25519 and X25519 keys, got: {}",
                    key_type_str
                )));
            }
        };

        // Create key in wallet for DID operations
        let wallet_key = self
            .wallet
            .create_key(key_type, KeyPurpose::AgentDID)
            .await
            .map_err(|e| ResolutionError::InternalError(format!("Failed to create key: {}", e)))?;

        // Get public key bytes (public_key is Vec<u8>, not Option)
        let public_key_bytes = &wallet_key.public_key;

        // Create did:key string
        let did_string = Self::encode_did_key(public_key_bytes, key_type)?;
        let did =
            DID::parse(&did_string).map_err(|e| ResolutionError::InvalidDid(e.to_string()))?;

        // Create DID Document
        let did_document = KeyDidResolver::create_did_document(&did, public_key_bytes, key_type)?;

        // Create key fingerprint (the multibase part of the DID)
        let key_fingerprint = did_string
            .strip_prefix("did:key:")
            .unwrap_or(&did_string)
            .to_string();

        let record_id = Uuid::new_v4().to_string();
        let did_record = DidRecord {
            id: record_id,
            did: did_string.clone(),
            role: DidRole::Created,
            did_document: Some(did_document.clone()),
            keys: vec![DidDocumentKey {
                kms_key_id: wallet_key.id.clone(),
                did_document_relative_key_id: format!("#{}", key_fingerprint),
            }],
            created_at: Utc::now(),
            updated_at: None,
        };

        Ok(CreateDidResult::new(did, did_document, did_record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_did_key_ed25519() {
        let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        let (public_key, key_type) = KeyDidResolver::parse_did_key(did).unwrap();

        assert_eq!(key_type, KeyType::Ed25519);
        assert_eq!(public_key.len(), 32); // Ed25519 public key is 32 bytes
    }

    #[tokio::test]
    async fn test_resolve_did_key() {
        let resolver = KeyDidResolver::new();
        let did = DID::parse("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();

        let doc = resolver.resolve(&did).await.unwrap();

        assert_eq!(doc.id, did.as_str());
        // For did:key, an Ed25519 key resolves to TWO verification
        // methods: the Ed25519 signing key plus a derived X25519 key for key
        // agreement. The stale `== 1` assertion predated the X25519 derivation.
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(
            doc.verification_method[0].type_,
            "Ed25519VerificationKey2018"
        );
        assert_eq!(
            doc.verification_method[1].type_,
            "X25519KeyAgreementKey2019"
        );
        assert!(!doc.authentication.is_empty());
        // The derived X25519 key must be referenced from keyAgreement.
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[tokio::test]
    async fn test_did_key_no_caching() {
        let resolver = KeyDidResolver::new();
        assert!(!resolver.allows_caching());
    }

    #[tokio::test]
    async fn test_encode_did_key() {
        // Known Ed25519 public key
        let public_key = vec![0u8; 32]; // Dummy key for testing
        let did = KeyDidCreator::encode_did_key(&public_key, KeyType::Ed25519).unwrap();

        assert!(did.starts_with("did:key:z"));
    }
}
