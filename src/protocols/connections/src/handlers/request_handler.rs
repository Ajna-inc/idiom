//! DIDExchange Request Handler
//!
//! Handles incoming DIDExchange request messages (responder side).
//! Implements auto-accept pattern

use crate::messages::DidExchangeRequestMessage;
use crate::services::ConnectionService;
use agent_core::traits::WalletRef;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use did::core::{DidDocument, DidRepository};
use didcomm::core::Message as DidcommMessage;
use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use protocol_oob::repository::oob_repository::OutOfBandRepositoryTrait;
use protocol_oob::repository::OutOfBandRepository;
use std::sync::{Arc, RwLock};

/// Extract the service endpoint from a did:peer:2 DID string.
///
/// did:peer:2 format: `did:peer:2.V<auth>.E<agreement>.S<base64url_service>`
/// The S element contains a base64url-encoded JSON service descriptor.
fn extract_endpoint_from_peer_did_2(did: &str) -> Option<String> {
    use base64::Engine;
    // Find the S element
    let s_prefix = ".S";
    let s_start = did.find(s_prefix)?;
    let s_data_start = s_start + s_prefix.len();
    // S element goes until next '.' or end of string
    let s_data_end = did[s_data_start..]
        .find('.')
        .map(|i| s_data_start + i)
        .unwrap_or(did.len());
    let service_encoded = &did[s_data_start..s_data_end];

    // Decode base64url
    let service_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(service_encoded)
        .ok()?;
    let service_json: serde_json::Value = serde_json::from_slice(&service_bytes).ok()?;
    service_json
        .get("s")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/// Extract and decode a base64-encoded DID document from a DIDComm attachment.
///
/// The attachment follows the DIDComm attachment format:
/// ```json
/// {
///   "data": {
///     "base64": "eyJAY29udGV4dCI6..." // base64-encoded DID document
///   }
/// }
/// ```
///
/// Returns the parsed DID document as a JSON value, or None if extraction fails.
fn decode_did_doc_attachment(attachment: &serde_json::Value) -> Option<serde_json::Value> {
    // Navigate to attachment.data.base64
    let base64_str = attachment
        .get("data")
        .and_then(|data| data.get("base64"))
        .and_then(|b64| b64.as_str())?;

    // Decode base64 string
    let decoded_bytes = general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| {
            tracing::debug!("  ⚠ Failed to decode base64: {}", e);
            e
        })
        .ok()?;

    // Parse as JSON DID document
    serde_json::from_slice(&decoded_bytes)
        .map_err(|e| {
            tracing::debug!("  ⚠ Failed to parse DID document: {}", e);
            e
        })
        .ok()
}

/// Derive the base58 X25519 keyAgreement key from a base58 Ed25519 authentication
/// key (Ed25519 point → Montgomery form). Some connections/1.0 did_docs
/// carry only the Ed25519 publicKey with no separate keyAgreement; this is
/// the same conversion used when we build our own did:peer:1
/// (`create_peer_did_with_services`) and by the envelope service's v1 fallback.
fn derive_x25519_from_ed25519_base58(ed25519_base58: &str) -> Option<String> {
    let ed_bytes = bs58::decode(ed25519_base58).into_vec().ok()?;
    let x25519 = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&ed_bytes)
        .ok()?
        .decompress()?
        .to_montgomery()
        .to_bytes();
    Some(bs58::encode(&x25519).into_string())
}

/// Extract a base58 public key from a verificationMethod (or embedded key) object,
/// accepting either `publicKeyBase58` or `publicKeyMultibase`. Some agents emit
/// multibase (z6Mk… Ed25519 / z6LS… X25519); others emit base58. Handle
/// both so key extraction never silently drops keys.
fn vm_public_key_base58(vm: &serde_json::Value) -> Option<String> {
    if let Some(b58) = vm.get("publicKeyBase58").and_then(|v| v.as_str()) {
        return Some(b58.to_string());
    }
    if let Some(mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str()) {
        return multibase_key_to_base58(mb);
    }
    None
}

/// Decode a base58btc multibase key (`z` + base58(multicodec-prefix || raw-key))
/// into the raw key re-encoded as base58, dropping the 2-byte multicodec varint
/// prefix (0xed01 Ed25519 / 0xec01 X25519). Mirrors the did:key decoding below.
fn multibase_key_to_base58(multibase: &str) -> Option<String> {
    did::methods::key::multibase_to_base58_verkey(multibase)
}

/// Match a verificationMethod's `id` against a relationship reference, tolerating
/// full-URL vs. fragment differences (e.g. `did:peer:…#key-1` vs `#key-1`) that
/// vary between different agent implementations.
fn vm_id_matches(vm: &serde_json::Value, ref_id: &str) -> bool {
    let id = match vm.get("id").and_then(|v| v.as_str()) {
        Some(i) => i,
        None => return false,
    };
    fn frag(s: &str) -> &str {
        s.rsplit('#').next().unwrap_or(s)
    }
    id == ref_id || frag(id) == frag(ref_id)
}

/// Handler for DIDExchange request messages
///
/// This handler:
/// 1. Receives a connection request from the requester (invitee)
/// 2. Validates the request against the out-of-band invitation
/// 3. Creates a connection record in RequestReceived state
/// 4. If auto-accept is enabled, immediately generates and returns a response
///
/// # Auto-Accept Pattern
///
/// Following the auto-accept pattern, the handler checks:
/// - Per-connection auto_accept_connection flag
/// - OR global auto_accept_connections config
///
/// If either is true, the handler generates a response message and returns it.
/// The dispatcher will automatically send the returned response.
pub struct DidExchangeRequestHandler {
    /// Connection service for protocol operations
    connection_service: Arc<ConnectionService>,
    /// Out-of-band repository to find invitation
    oob_repository: Arc<OutOfBandRepository>,
    /// DID repository for storing DID documents
    did_repository: Arc<DidRepository>,
    /// Wallet provider for signing (Arc on native, Rc on WASM)
    wallet_provider: WalletRef,
    /// Global auto-accept configuration
    auto_accept_connections: bool,
    /// Our DID to use in responses
    our_did: String,
    /// Registered mediation key (did:key format) for creating mediated did:peer:1 DIDs
    /// CRITICAL: When mediation is active, this key MUST be used for recipient keys in the
    /// did:peer:1 DID document. Otherwise, peers will send Forward messages to a key the
    /// mediator doesn't know about, and the mediator won't be able to deliver messages.
    registered_mediation_key: Arc<RwLock<Option<String>>>,
    /// Mediation routing keys from the mediator grant message
    /// These are the ONLY keys that should go into DID document routingKeys field.
    /// routingKeys = mediator keys only, NOT agent's own key.
    mediation_routing_keys: Arc<RwLock<Option<Vec<String>>>>,
    /// Pending key registrations - keys that need to be registered with the mediator
    /// via keylist-update BEFORE the response is sent. Each connection gets a
    /// unique key registered with the mediator.
    pending_key_registrations: Arc<RwLock<Vec<String>>>,
}

impl DidExchangeRequestHandler {
    /// Create a new request handler
    ///
    /// # Arguments
    /// * `connection_service` - Service for connection protocol operations
    /// * `oob_repository` - Repository to look up out-of-band invitations
    /// * `did_repository` - Repository for storing DID documents
    /// * `wallet_provider` - Wallet provider for signing operations
    /// * `auto_accept_connections` - Global auto-accept setting
    /// * `our_did` - The DID to use in responses
    /// * `registered_mediation_key` - Shared reference to the registered mediation key (did:key format)
    /// * `mediation_routing_keys` - Shared reference to mediator routing keys from grant (for DID doc routingKeys)
    /// * `pending_key_registrations` - Shared queue for keys needing mediator registration
    pub fn new(
        connection_service: Arc<ConnectionService>,
        oob_repository: Arc<OutOfBandRepository>,
        did_repository: Arc<DidRepository>,
        wallet_provider: WalletRef,
        auto_accept_connections: bool,
        our_did: String,
        registered_mediation_key: Arc<RwLock<Option<String>>>,
        mediation_routing_keys: Arc<RwLock<Option<Vec<String>>>>,
        pending_key_registrations: Arc<RwLock<Vec<String>>>,
    ) -> Self {
        Self {
            connection_service,
            oob_repository,
            did_repository,
            wallet_provider,
            auto_accept_connections,
            our_did,
            registered_mediation_key,
            mediation_routing_keys,
            pending_key_registrations,
        }
    }

    /// Extract both authentication and keyAgreement public keys from DID document attachment
    ///
    /// Extracts:
    /// - Ed25519 authentication key (verificationMethod[0].publicKeyBase58) - used as `kid` in JWE
    /// - X25519 keyAgreement key (keyAgreement[0].publicKeyBase58) - used for ECDH encryption
    ///
    /// Returns: (auth_key, key_agreement) tuple if both found, None otherwise
    fn extract_recipient_keys(
        &self,
        request: &DidExchangeRequestMessage,
    ) -> Option<(String, String)> {
        // Check if there's a DID document attachment
        let did_doc_attach = request.did_doc_attach.as_ref()?;

        tracing::debug!("  Extracting recipient keys from did_doc~attach...");

        // Decode the base64-encoded DID document
        let did_document = decode_did_doc_attachment(did_doc_attach)?;

        // Get verificationMethod array (optional - might not exist for embedded keys)
        let verification_methods = did_document
            .get("verificationMethod")
            .and_then(|vm| vm.as_array());

        // Extract Ed25519 authentication key
        // authentication can be: ["#key-1"] (reference) OR [{ "publicKeyBase58": "..." }] (embedded)
        let auth_key = did_document
            .get("authentication")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| {
                if let Some(ref_id) = first.as_str() {
                    // Reference like "#key-1" — resolve against verificationMethod
                    verification_methods.and_then(|vms| {
                        vms.iter()
                            .find(|vm| vm_id_matches(vm, ref_id))
                            .and_then(vm_public_key_base58)
                    })
                } else {
                    // Embedded key object
                    vm_public_key_base58(first)
                }
            })
            // Fallback: first verificationMethod (no/unresolvable authentication)
            .or_else(|| {
                verification_methods
                    .and_then(|vms| vms.first())
                    .and_then(vm_public_key_base58)
            })?;

        tracing::debug!(
            "  ✓ Extracted Ed25519 authentication key (for kid): {}",
            auth_key
        );

        // Extract X25519 keyAgreement key
        // keyAgreement can be: ["#key-2"] (reference) OR [{ "publicKeyBase58": "..." }] (embedded)
        let key_agreement = did_document
            .get("keyAgreement")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| {
                if let Some(ref_id) = first.as_str() {
                    verification_methods.and_then(|vms| {
                        vms.iter()
                            .find(|vm| vm_id_matches(vm, ref_id))
                            .and_then(vm_public_key_base58)
                    })
                } else {
                    vm_public_key_base58(first)
                }
            })
            // Fallback: second verificationMethod (no/unresolvable keyAgreement)
            .or_else(|| {
                verification_methods
                    .and_then(|vms| vms.get(1))
                    .and_then(vm_public_key_base58)
            });

        // Some connections/1.0 did_docs carry only the Ed25519
        // publicKey (no separate keyAgreement / second verificationMethod). Derive
        // the X25519 key from the Ed25519 auth key so the connection record always
        // has an encryption key; otherwise outbound packing would fall back to
        // (failing) did:peer:1 resolution and both keys would be dropped.
        let key_agreement = match key_agreement {
            Some(ka) => ka,
            None => derive_x25519_from_ed25519_base58(&auth_key)?,
        };

        tracing::debug!(
            "  ✓ Extracted X25519 keyAgreement key (for ECDH): {}",
            key_agreement
        );

        Some((auth_key, key_agreement))
    }

    /// Same as create_peer_did_with_service but accepts multiple service endpoints.
    /// Each endpoint becomes its own service entry (#inline-0, #inline-1, …) sharing
    /// the same recipientKeys and routingKeys. Including both HTTP and WS endpoints
    /// is required so other DIDComm agents can resolve a WebSocket service for live-mode pickup.
    fn create_peer_did_with_services(
        &self,
        ed25519_public_key: &[u8],
        service_endpoints: &[String],
        routing_keys: Vec<String>,
        signing_ed25519_public_key: Option<&[u8]>,
    ) -> std::result::Result<(String, serde_json::Value), String> {
        use sha2::Digest;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| format!("Invalid Ed25519 key: {}", e))?
                .decompress()
                .ok_or("Failed to decompress Ed25519 key")?
                .to_montgomery()
                .to_bytes();

        let ed25519_base58 = bs58::encode(ed25519_public_key).into_string();
        let x25519_base58 = bs58::encode(&x25519_public_key).into_string();

        // Transform routing keys: some receivers dereference keys using endsWith()
        // matching, so did:key:z6Mk... must be did:key:z6Mk...#z6Mk... (with fragment).
        // Otherwise the routing key can't be matched against the resolved
        // did:key document's verification method IDs (which include fragments)
        let routing_keys: Vec<String> = routing_keys
            .into_iter()
            .map(|rk| {
                if rk.starts_with("did:key:") && !rk.contains('#') {
                    let fingerprint = &rk[8..]; // Skip "did:key:"
                    format!("{}#{}", rk, fingerprint)
                } else {
                    rk
                }
            })
            .collect();

        // Optionally compute signing key base58 if a separate signing key is provided
        // (used for mediated connections where DID doc key != signing key)
        let signing_key_base58 = signing_ed25519_public_key.map(|k| bs58::encode(k).into_string());

        // Build genesis doc public keys
        let mut genesis_public_keys = vec![
            serde_json::json!({
                "id": "#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "#id",
                "publicKeyBase58": &ed25519_base58
            }),
            serde_json::json!({
                "id": "#key-2",
                "type": "X25519KeyAgreementKey2019",
                "controller": "#id",
                "publicKeyBase58": &x25519_base58
            }),
        ];
        if let Some(ref signing_base58) = signing_key_base58 {
            genesis_public_keys.push(serde_json::json!({
                "id": "#key-3",
                "type": "Ed25519VerificationKey2018",
                "controller": "#id",
                "publicKeyBase58": signing_base58
            }));
        }

        // Build one service entry per endpoint. Mobile wallets need a WS endpoint
        // in the DID doc to enable live-mode message pickup (otherwise the mediator
        // queues forwarded messages instead of pushing them).
        let endpoints_for_genesis: Vec<&String> = if service_endpoints.is_empty() {
            return Err("service_endpoints must contain at least one endpoint".to_string());
        } else {
            service_endpoints.iter().collect()
        };
        let genesis_services: Vec<serde_json::Value> = endpoints_for_genesis
            .iter()
            .enumerate()
            .map(|(idx, ep)| {
                serde_json::json!({
                    "id": format!("#inline-{}", idx),
                    "type": "did-communication",
                    "priority": idx as u32,
                    "recipientKeys": ["#key-1"],
                    "routingKeys": &routing_keys,
                    "serviceEndpoint": ep
                })
            })
            .collect();

        // Create genesis doc (for hashing to create did:peer:1)
        // Note: routing_keys are included in the genesis doc to ensure the DID is unique
        let genesis_doc = serde_json::json!({
            "publicKey": genesis_public_keys,
            "service": genesis_services
        });

        // Hash the genesis doc to create did:peer:1
        // Format: did:peer:1z<base58btc hash> where 'z' is the multibase prefix for base58btc
        let genesis_str = serde_json::to_string(&genesis_doc)
            .map_err(|e| format!("Failed to serialize genesis doc: {}", e))?;
        let genesis_hash = sha2::Sha256::digest(genesis_str.as_bytes());
        let peer_did = format!("did:peer:1z{}", bs58::encode(&genesis_hash).into_string());

        // Build full DID document verification methods
        let mut verification_methods = vec![
            serde_json::json!({
                "id": format!("{}#key-1", &peer_did),
                "type": "Ed25519VerificationKey2018",
                "controller": &peer_did,
                "publicKeyBase58": &ed25519_base58
            }),
            serde_json::json!({
                "id": format!("{}#key-2", &peer_did),
                "type": "X25519KeyAgreementKey2019",
                "controller": &peer_did,
                "publicKeyBase58": &x25519_base58
            }),
        ];
        let mut authentication = vec![format!("{}#key-1", &peer_did)];

        // If separate signing key provided, add as #key-3 in authentication
        // This ensures the receiver's JWS signer check passes: signing key ∈ DID doc auth keys
        if let Some(ref signing_base58) = signing_key_base58 {
            verification_methods.push(serde_json::json!({
                "id": format!("{}#key-3", &peer_did),
                "type": "Ed25519VerificationKey2018",
                "controller": &peer_did,
                "publicKeyBase58": signing_base58
            }));
            authentication.push(format!("{}#key-3", peer_did));
        }

        // Build full DID doc service entries (one per endpoint).
        let full_services: Vec<serde_json::Value> = endpoints_for_genesis
            .iter()
            .enumerate()
            .map(|(idx, ep)| {
                serde_json::json!({
                    "id": format!("#inline-{}", idx),
                    "serviceEndpoint": ep,
                    "type": "did-communication",
                    "priority": idx as u32,
                    "recipientKeys": ["#key-1"],
                    "routingKeys": &routing_keys
                })
            })
            .collect();

        // Create the full DID document (with resolved IDs)
        // IMPORTANT: Must include verificationMethod array for encryption code to find keys
        let did_document = serde_json::json!({
            "@context": ["https://w3id.org/did/v1"],
            "id": &peer_did,
            "verificationMethod": verification_methods,
            "authentication": authentication,
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": full_services
        });

        Ok((peer_did, did_document))
    }

    /// Create a did:peer:2 DID with embedded keys and service endpoint (for v2 connections)
    ///
    /// Format: `did:peer:2.V<auth_key>.E<agreement_key>.S<service>`
    /// Self-resolving — no did_doc~attach needed.
    fn create_peer_did_2_with_service(
        &self,
        ed25519_public_key: &[u8],
        service_endpoint: &str,
        routing_keys: Vec<String>,
    ) -> std::result::Result<(String, serde_json::Value), String> {
        use base64::Engine;

        // Convert Ed25519 to X25519 for keyAgreement
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| format!("Invalid Ed25519 key: {}", e))?
                .decompress()
                .ok_or("Failed to decompress Ed25519 key")?
                .to_montgomery()
                .to_bytes();

        // Encode keys as multibase (z-prefix base58btc with multicodec prefix)
        let mut auth_multicodec = vec![0xed, 0x01];
        auth_multicodec.extend_from_slice(ed25519_public_key);
        let auth_key_encoded = multibase::encode(multibase::Base::Base58Btc, &auth_multicodec);

        let mut agreement_multicodec = vec![0xec, 0x01];
        agreement_multicodec.extend_from_slice(&x25519_public_key);
        let agreement_key_encoded =
            multibase::encode(multibase::Base::Base58Btc, &agreement_multicodec);

        // Encode service as base64url (for did:peer:2)
        let service_json = serde_json::json!({
            "t": "dm",
            "s": service_endpoint,
            "r": routing_keys,
            "a": ["didcomm/v2"]
        });
        let service_str = serde_json::to_string(&service_json)
            .map_err(|e| format!("Failed to serialize service: {}", e))?;
        let service_encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(service_str.as_bytes());

        // Compose did:peer:2
        let peer_did = format!(
            "did:peer:2.V{}.E{}.S{}",
            auth_key_encoded, agreement_key_encoded, service_encoded
        );

        // Create DID document (for local storage)
        let did_document = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://w3id.org/security/suites/x25519-2020/v1"
            ],
            "id": &peer_did,
            "verificationMethod": [{
                "id": format!("{}#key-1", &peer_did),
                "type": "Ed25519VerificationKey2020",
                "controller": &peer_did,
                "publicKeyMultibase": auth_key_encoded
            }, {
                "id": format!("{}#key-2", &peer_did),
                "type": "X25519KeyAgreementKey2020",
                "controller": &peer_did,
                "publicKeyMultibase": agreement_key_encoded
            }],
            "authentication": [format!("{}#key-1", &peer_did)],
            "keyAgreement": [format!("{}#key-2", &peer_did)],
            "service": [{
                "id": "#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": service_endpoint,
                "accept": ["didcomm/v2"],
                "routingKeys": routing_keys
            }]
        });

        Ok((peer_did, did_document))
    }

    /// Create a did_doc~attach structure from a DID document
    ///
    /// Encodes the DID document in the DIDComm attachment format with JWS signature
    async fn create_did_doc_attach_signed(
        &self,
        did_document: serde_json::Value,
        signing_key_id: &str,
        recipient_key_fingerprint: &str,
    ) -> std::result::Result<serde_json::Value, String> {
        // Encode DID document as base64
        let did_doc_json = serde_json::to_string(&did_document)
            .map_err(|e| format!("Failed to serialize DID document: {}", e))?;
        let did_doc_base64 = general_purpose::STANDARD.encode(did_doc_json.as_bytes());

        // Get the public key for JWK
        let key = self
            .wallet_provider
            .get_key(signing_key_id)
            .await
            .map_err(|e| format!("Failed to get key: {}", e))?
            .ok_or_else(|| format!("Key not found: {}", signing_key_id))?;

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
            .map_err(|e| format!("Failed to serialize protected header: {}", e))?;
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
            .map_err(|e| format!("Failed to sign: {}", e))?;
        let signature_base64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature.bytes);

        // Create the did_doc~attach structure with JWS.
        // The JWS header `kid` MUST be a `did:key:` DID per Aries RFC 0023 receivers —
        // passing a bare multibase fingerprint causes the receiver
        // to error with "JWS header kid must be a did:key DID".
        let kid_did_key: String = if recipient_key_fingerprint.starts_with("did:key:") {
            recipient_key_fingerprint.to_string()
        } else {
            format!("did:key:{}", recipient_key_fingerprint)
        };
        let attachment = serde_json::json!({
            "@id": format!("did-doc-{}", uuid::Uuid::new_v4()),
            "mime-type": "application/json",
            "data": {
                "base64": did_doc_base64,
                "jws": {
                    "protected": protected_base64,
                    "signature": signature_base64,
                    "header": {
                        "kid": kid_did_key
                    }
                }
            }
        });

        Ok(attachment)
    }
}

// Native: Multi-threaded with Send bounds
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// WASM: Single-threaded, no Send bounds
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for DidExchangeRequestHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![DidExchangeRequestMessage::TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> Result<Option<OutboundMessage>, MessageHandlerError> {
        tracing::debug!("→ [RequestHandler] Received request");
        tracing::debug!("  Body type: {:?}", inbound.message.body.is_object());
        tracing::debug!(
            "  Body keys: {:?}",
            inbound
                .message
                .body
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
        );
        tracing::debug!(
            "  Full body: {}",
            serde_json::to_string_pretty(&inbound.message.body).unwrap_or_default()
        );

        // Parse the request message from body (where the full protocol message is stored)
        let request: DidExchangeRequestMessage =
            serde_json::from_value(inbound.message.body.clone())
                .map_err(|e| MessageHandlerError::InvalidMessage(e.to_string()))?;
        tracing::debug!("  Parsed request from: {}", request.did);

        // Get parent thread ID (invitation ID)
        let parent_thread_id = request.parent_thread_id().ok_or_else(|| {
            MessageHandlerError::InvalidMessage("Missing parent thread ID".into())
        })?;

        // Find the out-of-band invitation by invitation ID (not record ID)
        // Note: parent_thread_id is the invitation.id, not the record.id
        let oob_record = self
            .oob_repository
            .find_by_invitation_id(parent_thread_id, protocol_oob::OutOfBandRole::Sender)
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?
            .ok_or_else(|| {
                MessageHandlerError::ProcessingFailed(format!(
                    "Out-of-band invitation not found: {}",
                    parent_thread_id
                ))
            })?;

        // Detect DIDComm v2: requester sent a did:peer:2 (self-resolving, no did_doc~attach)
        let use_v2 = request.did.starts_with("did:peer:2");
        if use_v2 {
            tracing::debug!("  → DIDComm v2 detected: requester DID is did:peer:2");
        }

        // Extract both authentication and keyAgreement keys from did_doc~attach
        // For v2: Keys are embedded in the DID itself — no did_doc~attach needed
        let (their_auth_key, their_key_agreement) = if use_v2 {
            // did:peer:2 is self-resolving, but store the peer's raw base58
            // verkeys on the connection so key-based lookups (inbound
            // basic-message `get_connection` by sender key, v1 packing) resolve
            // without re-deriving — a did-communication peer (credo) is
            // otherwise unmatchable by its base58 kid.
            did::methods::peer::parse_peer2_verkeys(&request.did)
        } else {
            match self.extract_recipient_keys(&request) {
                Some((auth, ka)) => (Some(auth), Some(ka)),
                None => (None, None),
            }
        };

        // IMPORTANT: Store the requester's DID document so we can send messages to them later
        // For v2: did:peer:2 is self-resolving — store DID reference, no did_doc~attach processing
        if use_v2 {
            // Store their did:peer:2 as a received DID (self-resolving, no doc needed)
            if let Err(e) =
                self.did_repository
                    .store_received_did(request.did.clone(), None, vec![])
            {
                tracing::debug!("  ⚠ Failed to store requester's did:peer:2: {}", e);
            } else {
                tracing::debug!(
                    "  ✓ Stored requester's did:peer:2 (self-resolving): {}",
                    request.did
                );
            }
        } else if let Some(did_doc_attach) = &request.did_doc_attach {
            if let Some(did_document_json) = decode_did_doc_attachment(did_doc_attach) {
                tracing::debug!(
                    "  → Storing requester's DID document for future message sending..."
                );

                // Normalize the DID document for compatibility:
                // 1. Some did:peer:1 docs use "publicKey" (DID v0.11) instead of "verificationMethod" (v1.0)
                // 2. Some agents embed full VM objects in authentication/keyAgreement arrays instead of using references
                let mut did_document_json = did_document_json;
                if let Some(obj) = did_document_json.as_object_mut() {
                    // Step 1: Map publicKey → verificationMethod (v0.11 compat)
                    if !obj.contains_key("verificationMethod") {
                        if let Some(public_key) = obj.get("publicKey").cloned() {
                            tracing::debug!("  → Normalizing publicKey → verificationMethod (DID spec v0.11 compat)");
                            obj.insert("verificationMethod".to_string(), public_key);
                        }
                    }

                    // Step 2: Extract embedded VMs from authentication/keyAgreement into verificationMethod
                    let mut extracted_methods = Vec::new();
                    for section in &["authentication", "keyAgreement"] {
                        if let Some(arr) = obj.get_mut(*section).and_then(|a| a.as_array_mut()) {
                            for item in arr.iter_mut() {
                                if let Some(embedded) = item.as_object() {
                                    if let Some(id) = embedded.get("id").and_then(|id| id.as_str())
                                    {
                                        extracted_methods.push(item.clone());
                                        *item = serde_json::json!(id);
                                    }
                                }
                            }
                        }
                    }
                    if !extracted_methods.is_empty() {
                        if !obj.contains_key("verificationMethod") {
                            obj.insert("verificationMethod".to_string(), serde_json::json!([]));
                        }
                        if let Some(vm_arr) = obj
                            .get_mut("verificationMethod")
                            .and_then(|v| v.as_array_mut())
                        {
                            for method in &extracted_methods {
                                vm_arr.push(method.clone());
                            }
                        }
                        tracing::debug!(
                            "  → Extracted {} embedded VMs from authentication/keyAgreement",
                            extracted_methods.len()
                        );
                    }
                }

                // Parse into DidDocument struct
                if let Ok(did_doc_struct) = serde_json::from_value::<DidDocument>(did_document_json)
                {
                    // Store as "Received" DID (this is THEIR DID that they sent us)
                    if let Err(e) = self.did_repository.store_received_did(
                        request.did.clone(),
                        Some(did_doc_struct),
                        vec![], // Keys are in the document itself
                    ) {
                        tracing::debug!("  ⚠ Failed to store requester's DID document: {}", e);
                    } else {
                        tracing::debug!("  ✓ Stored requester's DID document: {}", request.did);
                    }
                }
            }
        }

        // Process the request (creates connection record in RequestReceived state)
        let connection = self
            .connection_service
            .process_request(
                &request,
                &oob_record,
                self.our_did.clone(),
                their_auth_key,
                their_key_agreement,
            )
            .await
            .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

        // If this was a duplicate request (replay via WS + queue),
        // the response has already been sent — don't re-send it.
        if connection.state != crate::domain::DidExchangeState::RequestReceived {
            tracing::debug!(
                "  ⏭  Connection state is {:?} (response already sent for thread {}), skipping auto-accept",
                connection.state, connection.thread_id
            );
            return Ok(None);
        }

        // Check auto-accept (per-connection OR global config)
        let should_auto_accept = connection
            .auto_accept_connection
            .unwrap_or(self.auto_accept_connections);

        if should_auto_accept {
            tracing::debug!("  Auto-accept enabled, generating response");

            // Extract ALL service endpoints from OOB invitation (HTTP, WS, etc.).
            // Including all transports in the response DID doc lets the mobile pick a
            // WebSocket service for live-mode pickup (otherwise forwarded messages get
            // queued at the mediator and never push-delivered).
            let service_endpoints: Vec<String> = oob_record
                .invitation
                .services
                .iter()
                .filter_map(|svc| match svc {
                    protocol_oob::OutOfBandService::Inline(inline) => {
                        Some(inline.service_endpoint.clone())
                    }
                    protocol_oob::OutOfBandService::Did(did) => {
                        extract_endpoint_from_peer_did_2(did)
                    }
                })
                .collect();
            if service_endpoints.is_empty() {
                return Err(MessageHandlerError::ProcessingFailed(
                    "No service endpoint found in OOB invitation".to_string(),
                ));
            }
            // Keep `service_endpoint` (singular) for code paths still using it (v2 builder).
            let service_endpoint = service_endpoints[0].clone();

            tracing::debug!(
                "  Extracted {} service endpoint(s) from OOB: {:?}",
                service_endpoints.len(),
                service_endpoints
            );

            // Get routing keys from mediation grant (NOT from OOB invitation!)
            // routingKeys = mediator keys only from grant message
            // The agent's registered_mediation_key should NOT be in routingKeys - it's for recipientKeys
            let routing_keys = self
                .mediation_routing_keys
                .read()
                .map(|guard| guard.clone().unwrap_or_default())
                .unwrap_or_default();

            tracing::debug!(
                "[REQUEST-HANDLER] Using mediation_routing_keys from grant (count={}): {:?}",
                routing_keys.len(),
                routing_keys
            );
            if !routing_keys.is_empty() {
                tracing::debug!(
                    "  ✓ Using {} routing key(s) from mediation grant",
                    routing_keys.len()
                );
            }

            // ═══════════════════════════════════════════════════════════════
            // DIDComm v2 path: create did:peer:2 (self-resolving, no did_doc~attach)
            // ═══════════════════════════════════════════════════════════════
            if use_v2 {
                tracing::debug!("  → Creating did:peer:2 response (DIDComm v2)...");

                // Create a new Ed25519 key for this connection
                let our_key = self
                    .wallet_provider
                    .create_key(
                        agent_core::traits::KeyType::Ed25519,
                        agent_core::traits::KeyPurpose::AgentMessaging,
                    )
                    .await
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to create key: {}",
                            e
                        ))
                    })?;

                // Create did:peer:2 with our endpoint
                let (peer_did, did_document) = self
                    .create_peer_did_2_with_service(
                        &our_key.public_key,
                        &service_endpoint,
                        routing_keys,
                    )
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to create did:peer:2: {}",
                            e
                        ))
                    })?;

                tracing::debug!("  ✓ Created did:peer:2: {}", peer_did);

                // Store our did:peer:2 in DidRepository
                let did_doc_struct: DidDocument = serde_json::from_value(did_document.clone())
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to deserialize DID document: {}",
                            e
                        ))
                    })?;

                use did::core::DidDocumentKey;
                let keys = vec![
                    DidDocumentKey::new(our_key.id.clone(), format!("{}#key-1", peer_did)),
                    DidDocumentKey::new(our_key.id.clone(), format!("{}#key-2", peer_did)),
                ];

                self.did_repository
                    .store_created_did(peer_did.clone(), Some(did_doc_struct), keys)
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!("Failed to store DID: {}", e))
                    })?;

                // Create response
                let (mut updated_connection, mut response_msg) = self
                    .connection_service
                    .create_response(&connection.id)
                    .await
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

                // Update connection with did:peer:2 and DIDComm version
                updated_connection.did = peer_did.clone();
                updated_connection.didcomm_version = Some("2".to_string());
                response_msg.did = peer_did.clone();
                // No did_doc~attach for v2 — DID is self-resolving

                self.connection_service
                    .update(&updated_connection)
                    .await
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to save connection: {}",
                            e
                        ))
                    })?;

                tracing::debug!("  ✓ Connection updated with did:peer:2 (DIDComm v2)");

                // Convert to DIDComm message and return
                let response_json = serde_json::to_value(&response_msg)
                    .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

                let didcomm_msg = DidcommMessage::new(
                    response_msg.id.clone(),
                    response_msg.msg_type.clone(),
                    response_json,
                );

                let outbound = OutboundMessage {
                    message: didcomm_msg,
                    to: request.did.clone(),
                    from: peer_did,
                    connection_id: Some(updated_connection.id),
                };

                tracing::debug!(
                    "✓ [RequestHandler] Returning v2 response for: {}",
                    outbound.to
                );
                return Ok(Some(outbound));
            }

            // ═══════════════════════════════════════════════════════════════
            // DIDComm v1 path (unchanged): create did:peer:1 with did_doc~attach
            // ═══════════════════════════════════════════════════════════════

            // Check if we have a registered mediation key - CRITICAL for mediated connections!
            // When mediation is active, we MUST use the registered key so the mediator can route
            // Forward messages to us. Using a new key would mean the mediator can't deliver.
            let registered_key = self
                .registered_mediation_key
                .read()
                .map(|guard| guard.clone())
                .unwrap_or(None);

            let (public_key_bytes, our_key_id, is_mediated, signing_key_public_bytes): (
                Vec<u8>,
                String,
                bool,
                Option<Vec<u8>>,
            ) = if let Some(ref registered_key) = registered_key {
                // MEDIATED: Use the registered mediation key
                tracing::debug!(
                    "  ✓ Using REGISTERED mediation key for did:peer:1: {}",
                    registered_key
                );

                // Extract Ed25519 public key from did:key format
                // did:key:z6Mk... where z = base58btc, 6Mk = Ed25519 multicodec prefix
                if !registered_key.starts_with("did:key:z") {
                    return Err(MessageHandlerError::ProcessingFailed(format!(
                        "Invalid registered_mediation_key format: {}. Expected did:key:z...",
                        registered_key
                    )));
                }

                let multibase_part = &registered_key[9..]; // Skip "did:key:z"
                let decoded = bs58::decode(multibase_part).into_vec().map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to decode did:key: {}",
                        e
                    ))
                })?;

                // First 2 bytes are multicodec prefix (0xed 0x01 for Ed25519)
                if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
                    return Err(MessageHandlerError::ProcessingFailed(format!(
                        "Invalid Ed25519 key in did:key: expected 0xed01 prefix, got {:02x}{:02x}",
                        decoded.first().unwrap_or(&0),
                        decoded.get(1).unwrap_or(&0)
                    )));
                }

                // Create a UNIQUE key per connection for #key-1 (authentication + encryption)
                // CRITICAL: We must NOT reuse the mediation key as #key-1 because some agents index
                // DID records by recipientKeyFingerprints. Reusing the same key across connections
                // causes "Multiple records found" errors on the mobile side.
                // The mediation key goes into routingKeys instead for message routing.
                let connection_key = self
                    .wallet_provider
                    .create_key(
                        agent_core::traits::KeyType::Ed25519,
                        agent_core::traits::KeyPurpose::AgentMessaging,
                    )
                    .await
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to create connection key: {}",
                            e
                        ))
                    })?;

                tracing::debug!(
                    "  ✓ Created unique connection key for did:peer:1: {}",
                    connection_key.id
                );

                // Convert connection key to did:key format for mediator registration
                // Format: did:key:z + base58btc(0xed01 + public_key_bytes)
                let mut multicodec_key = vec![0xed, 0x01]; // Ed25519 multicodec prefix
                multicodec_key.extend_from_slice(&connection_key.public_key);
                let connection_did_key =
                    format!("did:key:z{}", bs58::encode(&multicodec_key).into_string());

                // Queue this key for registration with the mediator via keylist-update
                // This MUST happen before we send the response, otherwise the mediator
                // won't know to queue messages for this key and the connection-complete
                // message from the peer will be lost.
                tracing::debug!(
                    "[REQUEST-HANDLER] Queueing connection key for mediator registration: {}",
                    connection_did_key
                );
                if let Ok(mut pending) = self.pending_key_registrations.write() {
                    pending.push(connection_did_key.clone());
                    tracing::debug!(
                        "[REQUEST-HANDLER] Pending key registrations count: {}",
                        pending.len()
                    );
                }

                (
                    connection_key.public_key.clone(),
                    connection_key.id.clone(),
                    true,
                    None,
                )
            } else {
                // DIRECT (no mediation): Create a new key for this connection
                // Same key is used for DID doc AND signing, so no separate signing key needed
                tracing::debug!(
                    "  Creating new Ed25519 key for did:peer:1 response (no mediation)..."
                );

                let our_new_key = self
                    .wallet_provider
                    .create_key(
                        agent_core::traits::KeyType::Ed25519,
                        agent_core::traits::KeyPurpose::AgentMessaging,
                    )
                    .await
                    .map_err(|e| {
                        MessageHandlerError::ProcessingFailed(format!(
                            "Failed to create new key: {}",
                            e
                        ))
                    })?;

                tracing::debug!(
                    "  ✓ Created new key for did:peer:1 response: {}",
                    our_new_key.id
                );

                (
                    our_new_key.public_key.clone(),
                    our_new_key.id.clone(),
                    false,
                    None,
                )
            };

            // NOTE: routingKeys contains ONLY mediator keys from grant.
            // The registered_mediation_key is NOT added to routingKeys.
            // It's used internally for mediator keylist, not for DID document routing.
            tracing::debug!(
                "[REQUEST-HANDLER] Final routing_keys for DID doc (count={}): {:?}",
                routing_keys.len(),
                routing_keys
            );

            // Create a connection-specific did:peer:1 DID with ALL service endpoints.
            // Include routing keys from mediation grant.
            let (peer_did, did_document) = self
                .create_peer_did_with_services(
                    &public_key_bytes,
                    &service_endpoints,
                    routing_keys.clone(),
                    signing_key_public_bytes.as_deref(),
                )
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to create did:peer:1: {}",
                        e
                    ))
                })?;

            tracing::debug!("[REQUEST-HANDLER] Created did:peer:1 DID: {}", peer_did);
            tracing::debug!("[REQUEST-HANDLER] Service endpoint: {}", service_endpoint);
            if is_mediated {
                tracing::debug!("[REQUEST-HANDLER] DID uses unique connection key + mediator routing keys from grant (Aries TS-compatible)");
            }

            // Store did:peer:1 document in DidRepository
            // Deserialize the JSON document into DidDocument struct
            let did_doc_struct: DidDocument = serde_json::from_value(did_document.clone())
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to deserialize DID document: {}",
                        e
                    ))
                })?;

            // Create DidDocumentKey link to KMS
            // Maps our wallet key ID to the DID document's #key-1
            use did::core::DidDocumentKey;
            let keys = if is_mediated {
                vec![DidDocumentKey::new(
                    our_key_id.clone(),
                    format!("{}#key-1", peer_did),
                )]
            } else {
                vec![DidDocumentKey::new(
                    our_key_id.clone(),
                    "#key-1".to_string(),
                )]
            };

            // Store as "Created" DID (this is OUR DID that we created)
            self.did_repository
                .store_created_did(peer_did.clone(), Some(did_doc_struct), keys)
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to store DID document: {}",
                        e
                    ))
                })?;

            tracing::debug!("  ✓ Stored did:peer:1 document in DidRepository for resolution");

            // Auto-generate response with the new did:peer:1 DID
            let (mut updated_connection, mut response_msg) = self
                .connection_service
                .create_response(&connection.id)
                .await
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            // Update the connection to use our connection-specific did:peer:1 (not agent's did:key)
            updated_connection.did = peer_did.clone();

            // Also override the DID in the response message
            response_msg.did = peer_did.clone();

            // Save the updated connection record to persist the peer DID
            // This is crucial: we must persist the connection-specific DID
            // (connection.did = didDocument.id) to the repository
            self.connection_service
                .update(&updated_connection)
                .await
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to save updated connection: {}",
                        e
                    ))
                })?;

            tracing::debug!("  ✓ Updated connection to use did:peer:1: {}", peer_did);

            // Set mesh transport preference if request arrived over mesh
            if let Some(ref ep) = inbound.context.sender_endpoint {
                if ep.starts_with("mesh://") {
                    tracing::debug!("  Setting mesh transport preference: {}", ep);
                    updated_connection.update_metadata(serde_json::json!({
                        "transport": {
                            "preferred": "mesh",
                            "selected_endpoint": ep
                        }
                    }));
                    self.connection_service
                        .update(&updated_connection)
                        .await
                        .map_err(|e| {
                            MessageHandlerError::ProcessingFailed(format!(
                                "Failed to save mesh transport metadata: {}",
                                e
                            ))
                        })?;
                }
            }

            // For did:peer:1, use did_doc~attach with the DID document (signed with JWS)
            // Sign with our_key_id (the signing key created for this connection).
            // For mediated connections, this signing key is added as #key-3 in the DID document's
            // authentication array, so the receiver's attached-DID-document check passes:
            //   signer key ∈ DID doc authentication keys ✓
            // For direct connections, the same key is used for both DID doc #key-1 and signing.
            tracing::debug!("  Creating did_doc~attach for did:peer:1 with JWS signature");

            // Compute fingerprint for the signing key (for JWS header kid field)
            let signing_pub_for_fingerprint = signing_key_public_bytes
                .as_deref()
                .unwrap_or(&public_key_bytes);
            let mut fingerprint_prefixed = vec![0xed, 0x01];
            fingerprint_prefixed.extend_from_slice(signing_pub_for_fingerprint);
            let signing_fingerprint =
                format!("z{}", bs58::encode(&fingerprint_prefixed).into_string());

            tracing::debug!("  Signing did_doc~attach with key: {}", our_key_id);
            tracing::debug!("  Signing key fingerprint: {}", signing_fingerprint);

            let did_doc_attach = self
                .create_did_doc_attach_signed(did_document, &our_key_id, &signing_fingerprint)
                .await
                .map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to create did_doc~attach: {}",
                        e
                    ))
                })?;
            response_msg = response_msg.with_did_doc_attach(did_doc_attach);
            tracing::debug!("  ✓ Response message created with signed did_doc~attach");

            // Convert response message to DIDComm Message
            // We need to store the protocol message in the body field
            let response_json = serde_json::to_value(&response_msg)
                .map_err(|e| MessageHandlerError::ProcessingFailed(e.to_string()))?;

            let didcomm_msg = DidcommMessage::new(
                response_msg.id.clone(),
                response_msg.msg_type.clone(),
                response_json, // Store the full protocol message as body
            );

            // For HTTP synchronous responses, we use the requester's DID for encryption
            // The HTTP endpoint is not needed because the response is returned in the HTTP body
            // Note: The endpoint extraction method remains for potential async sending scenarios

            // Create outbound message
            // IMPORTANT: `to` field must be the DID (for encryption), not the HTTP endpoint
            // Use did:peer:1 as the `from` field so other DIDComm agents can extract our service endpoint
            let outbound = OutboundMessage {
                message: didcomm_msg,
                to: request.did.clone(), // Use requester's DID for encryption
                from: peer_did.clone(), // Use did:peer:1 so other DIDComm agents can resolve it and extract the service endpoint
                connection_id: Some(updated_connection.id),
            };

            tracing::debug!(
                "✓ [RequestHandler] Returning encrypted response for: {}",
                outbound.to
            );
            // Return response for dispatcher to send
            return Ok(Some(outbound));
        }

        // Manual acceptance required - no automatic response
        Ok(None)
    }
}

// TODO: Update tests after refactoring
#[cfg(test)]
#[allow(dead_code)]
mod tests_disabled {
    use super::*;
    use crate::domain::{DidExchangeRole, DidExchangeState};
    use crate::repository::{ConnectionRepository, ConnectionRepositoryTrait};

    use didcomm::messaging::MessageContext;
    use protocol_oob::messages::OutOfBandInvitation;
    use protocol_oob::repository::{OutOfBandRecord, OutOfBandTags};

    async fn setup_test_handler(
        auto_accept: bool,
    ) -> (
        DidExchangeRequestHandler,
        Arc<ConnectionRepository>,
        Arc<OutOfBandRepository>,
    ) {
        let conn_repo = Arc::new(ConnectionRepository::new());
        let oob_repo = Arc::new(OutOfBandRepository::new());
        let did_repo = Arc::new(DidRepository::new());
        let service = Arc::new(ConnectionService::new(conn_repo.clone()));

        // Create a mock wallet provider for tests
        // Note: Tests are disabled, so this is a placeholder
        let handler = DidExchangeRequestHandler::new(
            service,
            oob_repo.clone(),
            did_repo,
            create_mock_wallet_provider(),
            auto_accept,
            "did:peer:responder".to_string(),
            Arc::new(RwLock::new(None)), // No registered mediation key for tests
            Arc::new(RwLock::new(None)), // No mediation routing keys for tests
            Arc::new(RwLock::new(Vec::new())), // No pending key registrations for tests
        );

        (handler, conn_repo, oob_repo)
    }

    // Mock wallet provider for tests
    fn create_mock_wallet_provider() -> WalletRef {
        // This is a placeholder - tests are disabled anyway
        unimplemented!("Tests are disabled - need mock wallet provider")
    }

    fn create_test_request(parent_thread_id: &str) -> DidExchangeRequestMessage {
        DidExchangeRequestMessage::new(
            "Requester Agent".to_string(),
            "did:peer:requester".to_string(),
            parent_thread_id.to_string(),
        )
    }

    fn create_test_oob_record(invitation_id: &str) -> OutOfBandRecord {
        let invitation = OutOfBandInvitation {
            id: invitation_id.to_string(),
            msg_type: "https://didcomm.org/out-of-band/1.1/invitation".to_string(),
            label: Some("Test Invitation".to_string()),
            goal_code: None,
            goal: None,
            accept: None,
            handshake_protocols: Some(vec!["https://didcomm.org/didexchange/1.1".to_string()]),
            requests: None,
            services: vec![],
            image_url: None,
        };

        OutOfBandRecord {
            id: invitation_id.to_string(),
            invitation,
            role: protocol_oob::OutOfBandRole::Sender,
            state: protocol_oob::OutOfBandState::AwaitResponse,
            reusable: false,
            auto_accept_connection: None,
            mediator_id: None,
            alias: None,
            reuse_connection_id: None,
            invitation_inline_service_keys: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: OutOfBandTags::default(),
        }
    }

    fn create_inbound_message(request: DidExchangeRequestMessage) -> InboundMessage {
        let didcomm_msg: DidcommMessage =
            serde_json::from_value(serde_json::to_value(&request).unwrap()).unwrap();

        InboundMessage {
            message: didcomm_msg,
            context: MessageContext {
                from: Some("did:peer:requester".to_string()),
                to: Some("did:peer:responder".to_string()),
                thread_id: Some(request.thread_id().to_string()),
                parent_thread_id: request.parent_thread_id().map(|s| s.to_string()),
                connection_id: None,
                encrypted: true,
                authenticated: true,
                sender_endpoint: Some("channel://requester".to_string()),
            },
        }
    }

    #[tokio::test]
    #[ignore = "Requires mock wallet provider implementation"]
    async fn test_request_handler_auto_accept() {
        let (handler, conn_repo, oob_repo) = setup_test_handler(true).await;

        // Create and store OOB invitation
        let oob_record = create_test_oob_record("invitation-123");
        oob_repo
            .save(&oob_record)
            .await
            .expect("Failed to save OOB record");

        // Create request message
        let request = create_test_request("invitation-123");
        let inbound = create_inbound_message(request.clone());

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_some(), "Should auto-generate response");

        let outbound = response.unwrap();
        assert_eq!(outbound.to, request.did);
        assert_eq!(outbound.from, "did:peer:responder");

        // Verify connection was created
        let connections = conn_repo
            .find_by_role_and_thread_id(DidExchangeRole::Responder, request.thread_id())
            .await
            .unwrap();
        assert!(connections.is_some());
        let connection = connections.unwrap();
        assert_eq!(connection.state, DidExchangeState::ResponseSent);
    }

    #[tokio::test]
    #[ignore = "Requires mock wallet provider implementation"]
    async fn test_request_handler_manual_accept() {
        let (handler, conn_repo, oob_repo) = setup_test_handler(false).await;

        // Create and store OOB invitation
        let oob_record = create_test_oob_record("invitation-456");
        oob_repo
            .save(&oob_record)
            .await
            .expect("Failed to save OOB record");

        // Create request message
        let request = create_test_request("invitation-456");
        let inbound = create_inbound_message(request.clone());

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.is_none(), "Should NOT auto-generate response");

        // Verify connection was created in RequestReceived state
        let connections = conn_repo
            .find_by_role_and_thread_id(DidExchangeRole::Responder, request.thread_id())
            .await
            .unwrap();
        assert!(connections.is_some());
        let connection = connections.unwrap();
        assert_eq!(connection.state, DidExchangeState::RequestReceived);
    }

    #[tokio::test]
    #[ignore = "Requires mock wallet provider implementation"]
    async fn test_request_handler_missing_invitation() {
        let (handler, _, _) = setup_test_handler(true).await;

        // Create request with non-existent invitation
        let request = create_test_request("nonexistent-invitation");
        let inbound = create_inbound_message(request);

        // Handle the message
        let result = handler.handle(inbound).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, MessageHandlerError::ProcessingFailed(_)));
    }
}
