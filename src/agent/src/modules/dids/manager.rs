//! DID management utilities
//!
//! This module provides utilities for creating and managing DIDs
//! (Decentralized Identifiers) used by the agent.

use crate::error::{AgentError, Result};
use agent_core::traits::WalletProvider;
use did::core::DidRepository;
use std::sync::Arc;

/// Verification-method and service `type` values used in the DID documents
/// this module builds. These are wire-format constants: the exact string
/// values are load-bearing (they are serialized into DID documents and, for
/// did:peer:1, hashed to derive the DID), so they must never change.
mod vm_type {
    /// Ed25519 verification method (2018 suite, `publicKeyBase58`).
    pub const ED25519_2018: &str = "Ed25519VerificationKey2018";
    /// Ed25519 verification method (2020 suite, `publicKeyMultibase`).
    pub const ED25519_2020: &str = "Ed25519VerificationKey2020";
    /// X25519 key-agreement method (2019 suite, `publicKeyBase58`).
    pub const X25519_2019: &str = "X25519KeyAgreementKey2019";
    /// X25519 key-agreement method (2020 suite, `publicKeyMultibase`).
    pub const X25519_2020: &str = "X25519KeyAgreementKey2020";
    /// Aries DIDComm v1 service type.
    pub const DID_COMMUNICATION: &str = "did-communication";
    /// DIDComm v2 service type.
    pub const DIDCOMM_MESSAGING: &str = "DIDCommMessaging";
}

/// Multicodec prefixes for key encoding
pub mod multicodec {
    /// Ed25519 public key multicodec prefix (0xed01)
    pub const ED25519_PUB: [u8; 2] = [0xed, 0x01];
    /// X25519 public key multicodec prefix (0xec01)
    pub const X25519_PUB: [u8; 2] = [0xec, 0x01];
    /// ML-DSA-65 public key multicodec prefix (0x1307 varint encoded)
    /// Using provisional code for post-quantum ML-DSA-65
    pub const MLDSA65_PUB: [u8; 2] = [0x87, 0x26];
}

/// Encode an ML-DSA-65 public key as multibase (z-prefix base58btc)
///
/// # Arguments
/// * `public_key` - Raw ML-DSA-65 public key bytes (1952 bytes)
///
/// # Returns
/// Multibase-encoded string starting with 'z'
pub fn encode_mldsa65_multibase(public_key: &[u8]) -> String {
    let mut multicodec_key = multicodec::MLDSA65_PUB.to_vec();
    multicodec_key.extend_from_slice(public_key);
    multibase::encode(multibase::Base::Base58Btc, &multicodec_key)
}

/// Decode an ML-DSA-65 public key from multibase format
///
/// # Arguments
/// * `multibase_str` - Multibase-encoded string (z-prefix)
///
/// # Returns
/// Raw ML-DSA-65 public key bytes, or error if invalid format
pub fn decode_mldsa65_multibase(multibase_str: &str) -> Result<Vec<u8>> {
    let (_, decoded) = multibase::decode(multibase_str)
        .map_err(|e| AgentError::Did(format!("Failed to decode multibase: {}", e)))?;

    // Check prefix
    if decoded.len() < 2 || decoded[0..2] != multicodec::MLDSA65_PUB {
        return Err(AgentError::Did(
            "Invalid ML-DSA-65 multicodec prefix".to_string(),
        ));
    }

    Ok(decoded[2..].to_vec())
}

/// Encode an Ed25519 public key as multibase
pub fn encode_ed25519_multibase(public_key: &[u8]) -> String {
    let mut multicodec_key = multicodec::ED25519_PUB.to_vec();
    multicodec_key.extend_from_slice(public_key);
    multibase::encode(multibase::Base::Base58Btc, &multicodec_key)
}

/// Encode an X25519 public key as multibase
pub fn encode_x25519_multibase(public_key: &[u8]) -> String {
    let mut multicodec_key = multicodec::X25519_PUB.to_vec();
    multicodec_key.extend_from_slice(public_key);
    multibase::encode(multibase::Base::Base58Btc, &multicodec_key)
}

/// DID management utilities
pub struct DidManager {
    wallet_provider: Arc<dyn WalletProvider>,
    did_repository: Arc<DidRepository>,
}

impl DidManager {
    /// Create a new DidManager
    pub fn new(
        wallet_provider: Arc<dyn WalletProvider>,
        did_repository: Arc<DidRepository>,
    ) -> Self {
        Self {
            wallet_provider,
            did_repository,
        }
    }

    /// Create a did:key DID
    ///
    /// Creates an Ed25519 key in the wallet and converts it to did:key format.
    ///
    /// # Returns
    /// Tuple of (did, key_id)
    pub async fn create_peer_did(&self) -> Result<(String, String)> {
        // Create Ed25519 key in wallet
        let key = self
            .wallet_provider
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentDID,
            )
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to create key: {}", e)))?;

        // Convert public key to did:key format using multibase encoding
        // Multicodec prefix for Ed25519: 0xed 0x01
        let mut multicodec_key = vec![0xed, 0x01];
        multicodec_key.extend_from_slice(&key.public_key);

        // Encode as multibase (base58btc = 'z' prefix)
        let did_key = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multicodec_key)
        );

        tracing::info!("✓ Created agent DID: {}", did_key);
        tracing::debug!("  Key ID in wallet: {}", key.id);

        Ok((did_key, key.id))
    }

    /// Create a did:peer:2 DID with embedded keys and service endpoint
    ///
    /// This creates a did:peer:2 (numalgo 2) which encodes keys and service directly in the DID.
    /// This is SELF-RESOLVING - no external storage or blockchain needed!
    ///
    /// Format: did:peer:2.V<auth_key>.E<agreement_key>.S<service>
    ///
    /// Perfect for bootstrap connections before blockchain is ready.
    ///
    /// # Arguments
    /// * `service_endpoint` - The HTTP endpoint where this agent receives DIDComm messages
    ///
    /// # Returns
    /// Tuple of (did, key_id, did_document)
    pub async fn create_peer_did_2_with_service(
        &self,
        service_endpoint: &str,
    ) -> Result<(String, String, serde_json::Value)> {
        // Create Ed25519 key in wallet (for authentication)
        let key = self
            .wallet_provider
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentDID,
            )
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to create key: {}", e)))?;

        let ed25519_public_key = &key.public_key;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| AgentError::Did(format!("Invalid Ed25519 key: {}", e)))?
                .decompress()
                .ok_or_else(|| AgentError::Did("Failed to decompress Ed25519 key".to_string()))?
                .to_montgomery()
                .to_bytes();

        // Encode keys as multibase (base58btc = 'z' prefix)
        // V = Verification method (authentication)
        let mut auth_multicodec = vec![0xed, 0x01]; // Ed25519 multicodec
        auth_multicodec.extend_from_slice(ed25519_public_key);
        let auth_key_encoded = multibase::encode(multibase::Base::Base58Btc, &auth_multicodec);

        // E = Encryption (key agreement)
        let mut agreement_multicodec = vec![0xec, 0x01]; // X25519 multicodec
        agreement_multicodec.extend_from_slice(&x25519_public_key);
        let agreement_key_encoded =
            multibase::encode(multibase::Base::Base58Btc, &agreement_multicodec);

        // S = Service endpoint
        // IMPORTANT: For did:peer:2, service is encoded as base64url (NOT multibase!)
        // Unlike V and E elements which use multibase (z prefix), service uses raw base64url
        let service_json = serde_json::json!({
            "t": "dm",  // Type: DIDComm messaging
            "s": service_endpoint,  // Service endpoint
            "r": [],    // Routing keys (empty for direct connection)
            "a": ["didcomm/v2"]  // Accept
        });
        let service_str = serde_json::to_string(&service_json)
            .map_err(|e| AgentError::Did(format!("Failed to serialize service: {}", e)))?;

        // Encode as base64url (NO padding, NO prefix) - this is for did:peer:2
        use base64::engine::Engine;
        let service_encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(service_str.as_bytes());

        // Construct did:peer:2
        let peer_did = format!(
            "did:peer:2.V{}.E{}.S{}",
            auth_key_encoded, agreement_key_encoded, service_encoded
        );

        // Create the full DID document (for local storage and use)
        let _ed25519_base58 = bs58::encode(ed25519_public_key).into_string();
        let _x25519_base58 = bs58::encode(&x25519_public_key).into_string();

        let did_document = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://w3id.org/security/suites/x25519-2020/v1"
            ],
            "id": &peer_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", &peer_did),
                "type": vm_type::ED25519_2020,
                "controller": &peer_did,
                "publicKeyMultibase": auth_key_encoded
            }, {
                "id": format!("{}#key-2", &peer_did),
                "type": vm_type::X25519_2020,
                "controller": &peer_did,
                "publicKeyMultibase": agreement_key_encoded
            }],
            "authentication": [format!("{}#key-1", &peer_did)],
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#didcomm",
                "type": vm_type::DIDCOMM_MESSAGING,
                "serviceEndpoint": service_endpoint,
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }]
        });

        // Store in DidRepository for local use
        let did_doc_parsed: did::core::DidDocument =
            serde_json::from_value(did_document.clone())
                .map_err(|e| AgentError::Did(format!("Failed to parse DID document: {}", e)))?;

        // IMPORTANT: Register BOTH key-1 (Ed25519 auth) and key-2 (X25519 keyAgreement)
        // Both map to the same wallet key ID because X25519 is derived from Ed25519.
        // The secrets resolver needs key-2 to decrypt incoming DIDComm messages.
        let keys = vec![
            did::core::DidDocumentKey::new(key.id.clone(), format!("{}#key-1", peer_did)),
            did::core::DidDocumentKey::new(key.id.clone(), format!("{}#key-2", peer_did)),
        ];

        self.did_repository
            .store_created_did(peer_did.clone(), Some(did_doc_parsed), keys)
            .map_err(|e| AgentError::Did(format!("Failed to store DID: {}", e)))?;

        tracing::info!("✓ Created did:peer:2 DID (self-resolving): {}", peer_did);
        tracing::debug!("  Service endpoint: {}", service_endpoint);
        tracing::debug!("  Key ID in wallet: {}", key.id);
        tracing::debug!("  Note: This DID is self-resolving - no blockchain needed!");

        Ok((peer_did, key.id, did_document))
    }

    /// Create a **did:peer:2** (self-resolving) whose service points at a
    /// mediator (endpoint + routing keys) and whose verification key is the
    /// caller-supplied, already-mediator-registered recipient key.
    ///
    /// This is the mediated analogue of `create_peer_did_1_with_registered_key`,
    /// but numalgo-2 so that resolver-only counterparties (notably some
    /// resolver-only agents, whose `store_did_document` unconditionally
    /// *resolves* the request DID) can resolve it — did:peer:1 is not
    /// self-resolving and such agents reject it with `DIDMethodNotSupported`.
    /// numalgo-2 (did:peer:2) is the default for did-exchange requests.
    ///
    /// The `.S` service advertises `accept: ["didcomm/aip2;env=rfc19"]` so the
    /// connection stays DIDComm **v1 (RFC19)** — the responder packs its reply
    /// as a v1 forward to the mediator, which our pickup loop decrypts by
    /// verkey (no v2 EnvelopeService involved).
    ///
    /// `key_id` is the wallet key id backing `registered_recipient_key`, so the
    /// self-resolving doc maps `#key-1`/`#key-2` to a decryptable wallet key.
    pub async fn create_peer_did_2_with_service_and_routing(
        &self,
        service_endpoint: &str,
        routing_keys: Vec<String>,
        registered_recipient_key: &str,
        key_id: &str,
    ) -> Result<(String, String, serde_json::Value)> {
        // Decode the Ed25519 public key from the registered did:key.
        if !registered_recipient_key.starts_with("did:key:z") {
            return Err(AgentError::Did(format!(
                "Invalid registered_recipient_key format: {}. Expected did:key:z...",
                registered_recipient_key
            )));
        }
        let decoded = bs58::decode(&registered_recipient_key[9..])
            .into_vec()
            .map_err(|e| AgentError::Did(format!("Failed to decode did:key: {}", e)))?;
        if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err(AgentError::Did(
                "Invalid Ed25519 key in registered did:key (expected 0xed01 prefix)".to_string(),
            ));
        }
        let ed25519_public_key: [u8; 32] = decoded[2..34]
            .try_into()
            .map_err(|_| AgentError::Did("Invalid Ed25519 key length".to_string()))?;

        // Derive X25519 (keyAgreement) from Ed25519.
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&ed25519_public_key)
                .map_err(|e| AgentError::Did(format!("Invalid Ed25519 key: {}", e)))?
                .decompress()
                .ok_or_else(|| AgentError::Did("Failed to decompress Ed25519 key".to_string()))?
                .to_montgomery()
                .to_bytes();

        // Multibase-encode V (Ed25519 auth) + E (X25519 keyAgreement).
        let mut auth_multicodec = vec![0xed, 0x01];
        auth_multicodec.extend_from_slice(&ed25519_public_key);
        let auth_key_encoded = multibase::encode(multibase::Base::Base58Btc, &auth_multicodec);

        let mut agreement_multicodec = vec![0xec, 0x01];
        agreement_multicodec.extend_from_slice(&x25519_public_key);
        let agreement_key_encoded =
            multibase::encode(multibase::Base::Base58Btc, &agreement_multicodec);

        // S = service (base64url for did:peer:2). This DID is used for
        // DIDComm v1 (RFC 0023 DID Exchange), so it MUST advertise an Aries
        // `did-communication` service with an explicit `recipientKeys` list —
        // that is what a v1 peer (credo) resolves to address us back. The
        // did:peer:2 `dm` (DIDCommMessaging) abbreviation is DIDComm v2 and a
        // v1 agent resolves ZERO usable services from it, reporting us as
        // undeliverable. `recipientKeys` references our first verification
        // method (`#key-1`); routing keys point at the mediator.
        let service_json = serde_json::json!({
            "t": vm_type::DID_COMMUNICATION,
            "s": service_endpoint,
            "priority": 0,
            "recipientKeys": ["#key-1"],
            "r": &routing_keys,
        });
        let service_str = serde_json::to_string(&service_json)
            .map_err(|e| AgentError::Did(format!("Failed to serialize service: {}", e)))?;
        use base64::engine::Engine;
        let service_encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(service_str.as_bytes());

        let peer_did = format!(
            "did:peer:2.V{}.E{}.S{}",
            auth_key_encoded, agreement_key_encoded, service_encoded
        );

        let did_document = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://w3id.org/security/suites/x25519-2020/v1"
            ],
            "id": &peer_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", &peer_did),
                "type": vm_type::ED25519_2020,
                "controller": &peer_did,
                "publicKeyMultibase": auth_key_encoded
            }, {
                "id": format!("{}#key-2", &peer_did),
                "type": vm_type::X25519_2020,
                "controller": &peer_did,
                "publicKeyMultibase": agreement_key_encoded
            }],
            "authentication": [format!("{}#key-1", &peer_did)],
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#didcomm",
                "type": vm_type::DIDCOMM_MESSAGING,
                "serviceEndpoint": service_endpoint,
                "accept": ["didcomm/aip2;env=rfc19"],
                "routingKeys": &routing_keys
            }]
        });

        let did_doc_parsed: did::core::DidDocument =
            serde_json::from_value(did_document.clone())
                .map_err(|e| AgentError::Did(format!("Failed to parse DID document: {}", e)))?;

        // Map both verification methods to the registered wallet key so the
        // secrets resolver can decrypt inbound messages addressed to it.
        let keys = vec![
            did::core::DidDocumentKey::new(key_id.to_string(), format!("{}#key-1", peer_did)),
            did::core::DidDocumentKey::new(key_id.to_string(), format!("{}#key-2", peer_did)),
        ];

        self.did_repository
            .store_created_did(peer_did.clone(), Some(did_doc_parsed), keys)
            .map_err(|e| AgentError::Did(format!("Failed to store DID: {}", e)))?;

        tracing::info!(
            "✓ Created did:peer:2 DID (mediated, self-resolving): {}",
            peer_did
        );
        tracing::debug!("  Service endpoint: {} (mediator)", service_endpoint);
        tracing::debug!("  Routing keys: {:?}", routing_keys);
        tracing::debug!("  Registered recipient key: {}", registered_recipient_key);

        Ok((peer_did, key_id.to_string(), did_document))
    }

    /// Create a did:peer:1 DID with service endpoint
    ///
    /// This creates a did:peer:1 (genesis doc based) with a service endpoint.
    /// Used when the agent needs to receive messages at a specific endpoint.
    ///
    /// # Arguments
    /// * `service_endpoint` - The HTTP endpoint where this agent receives DIDComm messages
    ///
    /// # Returns
    /// Tuple of (did, key_id, did_document)
    pub async fn create_peer_did_1_with_service(
        &self,
        service_endpoint: &str,
    ) -> Result<(String, String, serde_json::Value)> {
        use sha2::Digest;

        // Create Ed25519 key in wallet
        let key = self
            .wallet_provider
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentDID,
            )
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to create key: {}", e)))?;

        let ed25519_public_key = &key.public_key;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| AgentError::Did(format!("Invalid Ed25519 key: {}", e)))?
                .decompress()
                .ok_or_else(|| AgentError::Did("Failed to decompress Ed25519 key".to_string()))?
                .to_montgomery()
                .to_bytes();

        let ed25519_base58 = bs58::encode(ed25519_public_key).into_string();
        let x25519_base58 = bs58::encode(&x25519_public_key).into_string();

        // Create genesis doc (for hashing to create did:peer:1)
        let genesis_doc = serde_json::json!({
            "publicKey": [{
                "id": "#key-1",
                "type": vm_type::ED25519_2018,
                "controller": "#id",
                "publicKeyBase58": &ed25519_base58
            }, {
                "id": "#key-2",
                "type": vm_type::X25519_2019,
                "controller": "#id",
                "publicKeyBase58": &x25519_base58
            }],
            "service": [{
                "id": "#inline-0",
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": [],
                "serviceEndpoint": service_endpoint
            }]
        });

        // Hash the genesis doc to create did:peer:1
        let genesis_str = serde_json::to_string(&genesis_doc)
            .map_err(|e| AgentError::Did(format!("Failed to serialize genesis doc: {}", e)))?;
        let genesis_hash = sha2::Sha256::digest(genesis_str.as_bytes());
        let peer_did = format!("did:peer:1z{}", bs58::encode(&genesis_hash).into_string());

        // Create the full DID document (with resolved IDs)
        let did_document = serde_json::json!({
            "@context": ["https://w3id.org/did/v1"],
            "id": &peer_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", &peer_did),
                "type": vm_type::ED25519_2018,
                "controller": &peer_did,
                "publicKeyBase58": ed25519_base58
            }, {
                "id": format!("{}#key-2", &peer_did),
                "type": vm_type::X25519_2019,
                "controller": &peer_did,
                "publicKeyBase58": x25519_base58
            }],
            "authentication": [format!("{}#key-1", &peer_did)],
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#inline-0",
                "serviceEndpoint": service_endpoint,
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": []
            }]
        });

        // Store in DidRepository
        let did_doc_parsed: did::core::DidDocument =
            serde_json::from_value(did_document.clone())
                .map_err(|e| AgentError::Did(format!("Failed to parse DID document: {}", e)))?;

        let keys = vec![did::core::DidDocumentKey::new(
            key.id.clone(),
            format!("{}#key-1", peer_did),
        )];

        self.did_repository
            .store_created_did(peer_did.clone(), Some(did_doc_parsed), keys)
            .map_err(|e| AgentError::Did(format!("Failed to store DID: {}", e)))?;

        tracing::info!("✓ Created did:peer:1 DID: {}", peer_did);
        tracing::debug!("  Service endpoint: {}", service_endpoint);
        tracing::debug!("  Key ID in wallet: {}", key.id);

        Ok((peer_did, key.id, did_document))
    }

    /// Create a did:peer:1 DID with service endpoint and routing keys
    ///
    /// This creates a did:peer:1 (genesis doc based) with a service endpoint and optional routing keys.
    /// Used when the agent needs to receive messages via a mediator.
    ///
    /// # Arguments
    /// * `service_endpoint` - The HTTP endpoint (typically the mediator's endpoint)
    /// * `routing_keys` - The mediator's routing keys (for Forward envelope wrapping)
    ///
    /// # Returns
    /// Tuple of (did, key_id, did_document)
    pub async fn create_peer_did_1_with_service_and_routing(
        &self,
        service_endpoint: &str,
        routing_keys: Vec<String>,
    ) -> Result<(String, String, serde_json::Value)> {
        use sha2::Digest;

        // Create Ed25519 key in wallet
        let key = self
            .wallet_provider
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentDID,
            )
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to create key: {}", e)))?;

        let ed25519_public_key = &key.public_key;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| AgentError::Did(format!("Invalid Ed25519 key: {}", e)))?
                .decompress()
                .ok_or_else(|| AgentError::Did("Failed to decompress Ed25519 key".to_string()))?
                .to_montgomery()
                .to_bytes();

        let ed25519_base58 = bs58::encode(ed25519_public_key).into_string();
        let x25519_base58 = bs58::encode(&x25519_public_key).into_string();

        // Create genesis doc (for hashing to create did:peer:1)
        // Include routing keys in genesis doc to make the DID unique for each mediation configuration
        let genesis_doc = serde_json::json!({
            "publicKey": [{
                "id": "#key-1",
                "type": vm_type::ED25519_2018,
                "controller": "#id",
                "publicKeyBase58": &ed25519_base58
            }, {
                "id": "#key-2",
                "type": vm_type::X25519_2019,
                "controller": "#id",
                "publicKeyBase58": &x25519_base58
            }],
            "service": [{
                "id": "#inline-0",
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": &routing_keys,
                "serviceEndpoint": service_endpoint
            }]
        });

        // Hash the genesis doc to create did:peer:1
        let genesis_str = serde_json::to_string(&genesis_doc)
            .map_err(|e| AgentError::Did(format!("Failed to serialize genesis doc: {}", e)))?;
        let genesis_hash = sha2::Sha256::digest(genesis_str.as_bytes());
        let peer_did = format!("did:peer:1z{}", bs58::encode(&genesis_hash).into_string());

        // Create the full DID document (with resolved IDs)
        let did_document = serde_json::json!({
            "@context": ["https://w3id.org/did/v1"],
            "id": &peer_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", &peer_did),
                "type": vm_type::ED25519_2018,
                "controller": &peer_did,
                "publicKeyBase58": &ed25519_base58
            }, {
                "id": format!("{}#key-2", &peer_did),
                "type": vm_type::X25519_2019,
                "controller": &peer_did,
                "publicKeyBase58": &x25519_base58
            }],
            "authentication": [format!("{}#key-1", &peer_did)],
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#inline-0",
                "serviceEndpoint": service_endpoint,
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": &routing_keys
            }]
        });

        // Store in DidRepository
        let did_doc_parsed: did::core::DidDocument =
            serde_json::from_value(did_document.clone())
                .map_err(|e| AgentError::Did(format!("Failed to parse DID document: {}", e)))?;

        let keys = vec![did::core::DidDocumentKey::new(
            key.id.clone(),
            format!("{}#key-1", peer_did),
        )];

        self.did_repository
            .store_created_did(peer_did.clone(), Some(did_doc_parsed), keys)
            .map_err(|e| AgentError::Did(format!("Failed to store DID: {}", e)))?;

        tracing::info!("✓ Created did:peer:1 DID (mediated): {}", peer_did);
        tracing::debug!("  Service endpoint: {} (mediator)", service_endpoint);
        tracing::debug!("  Routing keys: {:?}", routing_keys);
        tracing::debug!("  Key ID in wallet: {}", key.id);

        Ok((peer_did, key.id, did_document))
    }

    /// Create a did:peer:1 DID using an existing registered mediation key
    ///
    /// This creates a did:peer:1 using the key that was registered with the mediator,
    /// ensuring that Forward messages addressed to this DID's recipient key will be
    /// delivered by the mediator.
    ///
    /// CRITICAL: The did:peer:1's recipient key MUST match the key registered with the
    /// mediator. Otherwise, when peers send Forward messages addressed to this DID,
    /// the mediator won't be able to deliver them (key not in keylist).
    ///
    /// # Arguments
    /// * `service_endpoint` - The HTTP endpoint (typically the mediator's endpoint)
    /// * `routing_keys` - The mediator's routing keys (for Forward envelope wrapping)
    /// * `registered_recipient_key` - The did:key that was registered with the mediator
    ///
    /// # Returns
    /// Tuple of (did, signing_key_id, did_document)
    pub async fn create_peer_did_1_with_registered_key(
        &self,
        service_endpoint: &str,
        routing_keys: Vec<String>,
        registered_recipient_key: &str,
    ) -> Result<(String, String, serde_json::Value)> {
        use sha2::Digest;

        // Extract the Ed25519 public key from the did:key
        // did:key format: did:key:z<base58btc(multicodec-prefix + public-key)>
        if !registered_recipient_key.starts_with("did:key:z") {
            return Err(AgentError::Did(format!(
                "Invalid registered_recipient_key format: {}. Expected did:key:z...",
                registered_recipient_key
            )));
        }

        let multibase_part = &registered_recipient_key[9..]; // Skip "did:key:z"
        let decoded = bs58::decode(multibase_part)
            .into_vec()
            .map_err(|e| AgentError::Did(format!("Failed to decode did:key: {}", e)))?;

        // First 2 bytes are multicodec prefix (0xed 0x01 for Ed25519)
        if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return Err(AgentError::Did(format!(
                "Invalid Ed25519 key in did:key: expected 0xed01 prefix, got {:02x}{:02x}",
                decoded.first().unwrap_or(&0),
                decoded.get(1).unwrap_or(&0)
            )));
        }

        let ed25519_public_key: [u8; 32] = decoded[2..34]
            .try_into()
            .map_err(|_| AgentError::Did("Invalid Ed25519 key length".to_string()))?;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&ed25519_public_key)
                .map_err(|e| AgentError::Did(format!("Invalid Ed25519 key: {}", e)))?
                .decompress()
                .ok_or_else(|| AgentError::Did("Failed to decompress Ed25519 key".to_string()))?
                .to_montgomery()
                .to_bytes();

        let ed25519_base58 = bs58::encode(&ed25519_public_key).into_string();
        let x25519_base58 = bs58::encode(&x25519_public_key).into_string();

        // Create a separate key in the wallet for SIGNING the did_doc~attach
        // Note: The did:peer:1 uses the registered mediation key as the RECIPIENT key,
        // but we need a wallet-accessible key for signing the JWS attachment.
        // The signing key MUST also appear in the DID document (as `#key-3`,
        // matching the responder-side pattern in protocol_connections's
        // request_handler.rs) — otherwise an interoperable verifier that
        // extracts the attached DID document rejects the attachment with
        // `DID Document signature is invalid.` because it requires the JWS
        // signer key to be present in the doc's `authentication` array.
        let signing_key = self
            .wallet_provider
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentDID,
            )
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to create signing key: {}", e)))?;

        let signing_base58 = bs58::encode(&signing_key.public_key).into_string();

        // Create genesis doc (for hashing to create did:peer:1)
        // Include routing keys + signing key in genesis doc so the DID is
        // unique per (recipient key, mediator, signing key) tuple.
        let genesis_doc = serde_json::json!({
            "publicKey": [{
                "id": "#key-1",
                "type": vm_type::ED25519_2018,
                "controller": "#id",
                "publicKeyBase58": &ed25519_base58
            }, {
                "id": "#key-2",
                "type": vm_type::X25519_2019,
                "controller": "#id",
                "publicKeyBase58": &x25519_base58
            }, {
                "id": "#key-3",
                "type": vm_type::ED25519_2018,
                "controller": "#id",
                "publicKeyBase58": &signing_base58
            }],
            "service": [{
                "id": "#inline-0",
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": &routing_keys,
                "serviceEndpoint": service_endpoint
            }]
        });

        // Hash the genesis doc to create did:peer:1
        let genesis_str = serde_json::to_string(&genesis_doc)
            .map_err(|e| AgentError::Did(format!("Failed to serialize genesis doc: {}", e)))?;
        let genesis_hash = sha2::Sha256::digest(genesis_str.as_bytes());
        let peer_did = format!("did:peer:1z{}", bs58::encode(&genesis_hash).into_string());

        // Some agents resolve service routing keys by *first* resolving
        // each one as its own DID document, then dereferencing the key
        // against that resolved document. That dereference does an
        // `endsWith` match against entries in `authentication` /
        // `keyAgreement`. A did:key document's authentication entries
        // carry the key-fragment form (`did:key:z6Mk…#z6Mk…`), so
        // looking up the bare `did:key:z6Mk…` fails: the entry only
        // *ends with* the fragment, not the bare form.
        //
        // Aries convention is to use the fragment form in
        // `service.routingKeys`. We canonicalize
        // here so the wallet's outbound `did_doc~attach` is interop-
        // compatible: a bare `did:key:z6Mk…` becomes
        // `did:key:z6Mk…#z6Mk…`.
        let routing_keys_with_fragment: Vec<String> = routing_keys
            .iter()
            .map(|rk| {
                if rk.starts_with("did:key:z") && !rk.contains('#') {
                    // Aries convention: fragment = the multibase suffix
                    // (everything after `did:key:`).
                    let suffix = &rk["did:key:".len()..];
                    format!("{}#{}", rk, suffix)
                } else {
                    rk.clone()
                }
            })
            .collect();

        let verification_methods = vec![
            serde_json::json!({
                "id": format!("{}#key-1", &peer_did),
                "type": vm_type::ED25519_2018,
                "controller": &peer_did,
                "publicKeyBase58": &ed25519_base58,
            }),
            serde_json::json!({
                "id": format!("{}#key-2", &peer_did),
                "type": vm_type::X25519_2019,
                "controller": &peer_did,
                "publicKeyBase58": &x25519_base58,
            }),
            serde_json::json!({
                "id": format!("{}#key-3", &peer_did),
                "type": vm_type::ED25519_2018,
                "controller": &peer_did,
                "publicKeyBase58": &signing_base58,
            }),
        ];

        let authentication: Vec<serde_json::Value> = vec![
            serde_json::Value::String(format!("{}#key-1", peer_did)),
            serde_json::Value::String(format!("{}#key-3", peer_did)),
        ];

        // Create the full DID document (with resolved IDs).
        //
        // `#key-3` (signing key) is added to both `verificationMethod` and
        // `authentication` so an interoperable verifier's signer-membership
        // check passes.
        let did_document = serde_json::json!({
            "@context": ["https://w3id.org/did/v1"],
            "id": &peer_did,
            "verificationMethod": verification_methods,
            "authentication": authentication,
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#inline-0",
                "serviceEndpoint": service_endpoint,
                "type": vm_type::DID_COMMUNICATION,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": &routing_keys_with_fragment
            }]
        });

        // Store in DidRepository
        let did_doc_parsed: did::core::DidDocument =
            serde_json::from_value(did_document.clone())
                .map_err(|e| AgentError::Did(format!("Failed to parse DID document: {}", e)))?;

        // Look up the wallet UUID for the registered recipient key — the
        // minter only handed us back the did:key string, but downstream
        // `KeyExtractor::find_key_for_did` needs an actual KMS key id
        // so the outbound signer can sign as #key-1. Without this the
        // wallet would try to sign with a literal "did:key:…" string
        // (no such record) and fall back to the next entry, leaking
        // the wrong sender key into the JWE — the peer then can't find
        // the connection because it indexes us by #key-1, not #key-3.
        let recipient_kms_key_id = {
            let all = self
                .wallet_provider
                .list_keys()
                .await
                .map_err(|e| AgentError::Wallet(format!("Failed to list keys: {}", e)))?;
            all.into_iter()
                .find(|k| {
                    k.key_type == agent_core::traits::KeyType::Ed25519
                        && k.public_key.as_slice() == &ed25519_public_key[..]
                })
                .map(|k| k.id)
                .unwrap_or_else(|| registered_recipient_key.to_string())
        };

        // Store mappings (order matters — `find_key_for_did` returns the
        // first match):
        //   #key-1 → registered recipient key (mediator-known, used as sender
        //            for authcrypt so the peer's connection lookup succeeds)
        //   #key-3 → wallet-resident signing key (used for JWS on did_doc~attach)
        let keys = vec![
            did::core::DidDocumentKey::new(recipient_kms_key_id, format!("{}#key-1", peer_did)),
            did::core::DidDocumentKey::new(signing_key.id.clone(), format!("{}#key-3", peer_did)),
        ];

        self.did_repository
            .store_created_did(peer_did.clone(), Some(did_doc_parsed), keys)
            .map_err(|e| AgentError::Did(format!("Failed to store DID: {}", e)))?;

        tracing::info!(
            "✓ Created did:peer:1 DID (with registered mediation key): {}",
            peer_did
        );
        tracing::debug!("  Service endpoint: {} (mediator)", service_endpoint);
        tracing::debug!("  Routing keys: {:?}", routing_keys);
        tracing::debug!("  Registered recipient key: {}", registered_recipient_key);
        tracing::debug!("  Ed25519 verkey (recipient): {}", ed25519_base58);
        tracing::debug!("  Signing key ID (in wallet): {}", signing_key.id);

        // Return the signing key ID (wallet key ID) for use in create_did_doc_attach_signed
        Ok((peer_did, signing_key.id, did_document))
    }

    /// Create a signed did_doc~attach structure from a DID document
    ///
    /// Encodes the DID document in the DIDComm attachment format with JWS signature
    pub async fn create_did_doc_attach_signed(
        &self,
        did_document: serde_json::Value,
        signing_key_id: &str,
    ) -> Result<serde_json::Value> {
        use base64::engine::general_purpose;
        use base64::Engine;

        // Encode DID document as base64
        let did_doc_json = serde_json::to_string(&did_document)
            .map_err(|e| AgentError::Did(format!("Failed to serialize DID document: {}", e)))?;
        let did_doc_base64 = general_purpose::STANDARD.encode(did_doc_json.as_bytes());

        // Get the public key for JWK
        let key = self
            .wallet_provider
            .get_key(signing_key_id)
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to get key: {}", e)))?
            .ok_or_else(|| AgentError::Wallet(format!("Key not found: {}", signing_key_id)))?;

        // Create JWK with public key
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": general_purpose::URL_SAFE_NO_PAD.encode(&key.public_key)
        });

        // Create protected header with JWK
        let protected_header = serde_json::json!({
            "alg": "EdDSA",
            "jwk": jwk
        });

        let protected_header_str = serde_json::to_string(&protected_header)
            .map_err(|e| AgentError::Did(format!("Failed to serialize protected header: {}", e)))?;
        let protected_base64 =
            general_purpose::URL_SAFE_NO_PAD.encode(protected_header_str.as_bytes());

        // Create JWS signing input: protected_base64 + "." + payload_base64
        let base64url_payload = did_doc_base64
            .replace('+', "-")
            .replace('/', "_")
            .replace("=", "");
        let signing_input = format!("{}.{}", protected_base64, base64url_payload);

        // Sign the input
        let signature = self
            .wallet_provider
            .sign(signing_key_id, signing_input.as_bytes())
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to sign: {}", e)))?;
        let signature_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature.bytes);

        // Create kid from did:key
        let kid = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, {
                let mut multicodec_key = vec![0xed, 0x01];
                multicodec_key.extend_from_slice(&key.public_key);
                multicodec_key
            })
        );

        // Create the did_doc~attach structure
        Ok(serde_json::json!({
            "@id": format!("did-doc-{}", uuid::Uuid::new_v4()),
            "mime-type": "application/json",
            "data": {
                "base64": did_doc_base64,
                "jws": {
                    "header": {
                        "kid": kid
                    },
                    "protected": protected_base64,
                    "signature": signature_base64
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    // Tests will be added when we have mock implementations
    // For now, the functions are tested through integration tests
}
