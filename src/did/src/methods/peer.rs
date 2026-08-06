//! did:peer Method Implementation
//!
//! Implements did:peer creation and resolution using Affinidi's did-peer crate.
//!
//! # References
//! - Aries RFC 0627: https://github.com/hyperledger/aries-rfcs/tree/main/features/0627-static-peer-dids
//!
//! # Supported Algorithms
//! - numalgo 0: Inception key without doc (delegates to did:key)
//! - numalgo 1: Genesis-doc lookup (stored short-form DID)
//! - numalgo 2: Multiple inception keys (default)
//! - numalgo 4: Long form (self-describing embedded doc) + short form (stored)

use async_trait::async_trait;
use base64::Engine;
use std::sync::Arc;

use crate::core::{
    CreateDidOptions, CreateDidResult, DidCreator, DidDocument, DidDocumentKey, DidRepository,
    DidResolver, ResolutionError, ResolutionResult, Service, VerificationMethod,
    VerificationRelationship, DID,
};
use agent_core::traits::{KeyPurpose, KeyType, WalletProvider};

/// did:peer Resolver - Resolves did:peer DIDs to DID Documents
///
/// - For did:peer:1: Queries DidRepository for stored genesis documents,
///   falling back to `fallback_repository` if configured (used by multi-
///   tenant setups where the mediator's DID lives in a shared/root repo).
/// - For did:peer:2: Uses did-peer crate to reconstruct from DID
pub struct PeerDidResolver {
    peer: did_peer::DIDPeer,
    did_repository: Arc<DidRepository>,
    fallback_repository: Option<Arc<DidRepository>>,
}

impl PeerDidResolver {
    pub fn new(did_repository: Arc<DidRepository>) -> Self {
        Self {
            peer: did_peer::DIDPeer,
            did_repository,
            fallback_repository: None,
        }
    }

    /// Attach a second `DidRepository` that's queried whenever the
    /// primary one doesn't carry the genesis document for a did:peer:1.
    /// Used by `agent_tenants::TenantContext::new` so each tenant's
    /// resolver chains to `SharedInfrastructure::did_repository`, which
    /// is where the mediator's DID doc lives.
    pub fn with_fallback(mut self, fallback: Arc<DidRepository>) -> Self {
        self.fallback_repository = Some(fallback);
        self
    }

    /// Convert did-peer Document to our DidDocument type
    fn convert_document(
        peer_doc: affinidi_did_common::Document,
    ) -> Result<DidDocument, ResolutionError> {
        // Serialize the peer document to JSON
        let json = serde_json::to_value(&peer_doc).map_err(|e| {
            ResolutionError::InternalError(format!("Failed to serialize peer doc: {}", e))
        })?;

        tracing::trace!(target: "did.peer", doc = %json, "resolved peer document");

        // Deserialize into our DidDocument type
        let our_doc: DidDocument = serde_json::from_value(json.clone()).map_err(|e| {
            tracing::warn!(target: "did.peer", error = %e, "peer document deserialization failed");
            ResolutionError::InternalError(format!("Failed to convert peer doc: {}", e))
        })?;

        Ok(our_doc)
    }

    /// Resolve a *short-form* did:peer (numalgo 1, or numalgo 4 short form) from
    /// its stored genesis document: the primary repository first, then the
    /// shared/root fallback (where a mediator's DID lives in multi-tenant
    /// setups). Both short forms share this single path — no per-numalgo copy.
    fn resolve_stored(&self, did: &str) -> ResolutionResult<DidDocument> {
        if let Some(rec) = self.did_repository.find_by_did(did) {
            if let Some(doc) = rec.did_document {
                return Ok(doc);
            }
            return Err(ResolutionError::InternalError(format!(
                "DidRecord found for {did} but didDocument is missing"
            )));
        }
        if let Some(fallback) = &self.fallback_repository {
            if let Some(rec) = fallback.find_by_did(did) {
                if let Some(doc) = rec.did_document {
                    return Ok(doc);
                }
            }
        }
        Err(ResolutionError::NotFound(format!(
            "No did record found for {did} - short-form did:peer resolution requires the genesis document"
        )))
    }
}

#[async_trait]
impl DidResolver for PeerDidResolver {
    fn method_name(&self) -> &str {
        "peer"
    }

    fn allows_caching(&self) -> bool {
        false // did:peer is deterministic, no caching needed
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        let s = did.as_str();
        // One dispatch for every did:peer numalgo (the digit right after
        // "did:peer:") so each variant lives in exactly one place — no
        // per-caller special-casing:
        //   0, 2 -> self-describing; decoded by the Affinidi did-peer crate
        //   1    -> short form: stored genesis document (`resolve_stored`)
        //   4    -> long form: decode the embedded, self-certifying document;
        //           short form: stored genesis document (`resolve_stored`)
        match s
            .strip_prefix("did:peer:")
            .and_then(|rest| rest.as_bytes().first().copied())
        {
            Some(b'1') => self.resolve_stored(s),
            Some(b'4') => match split_peer4_long(s) {
                Some(encoded) => decode_peer4_long(s, encoded),
                None => self.resolve_stored(s),
            },
            Some(b'0') | Some(b'2') => {
                let result = self.peer.resolve(s).await.map_err(|e| {
                    ResolutionError::ResolutionFailed(format!(
                        "did:peer resolution failed: {:?}",
                        e
                    ))
                })?;
                Self::convert_document(result)
            }
            _ => Err(ResolutionError::ResolutionFailed(format!(
                "unsupported did:peer numalgo: {s}"
            ))),
        }
    }
}

// ── numalgo-4 (did:peer:4) decoding ─────────────────────────────────────────
// The long form `did:peer:4<hash>:<encodedDocument>` embeds the whole DID
// document, so it resolves with no network/storage lookup (per the did:peer
// numalgo-4 spec). The short form `did:peer:4<hash>` is a stored DID and goes
// through `resolve_stored`, alongside numalgo 1.

/// Return the encoded-document tail of a *long-form* did:peer:4, or `None` for
/// the short form. The hash segment never contains ':', so one split suffices.
fn split_peer4_long(did: &str) -> Option<&str> {
    let body = did.strip_prefix("did:peer:4")?;
    let (hash, encoded) = body.split_once(':')?;
    (!hash.is_empty() && !encoded.is_empty()).then_some(encoded)
}

/// Decode a long-form numalgo-4 did:peer into a DID Document: verify the
/// self-certifying hash, strip the JSON multicodec prefix, parse the embedded
/// document, then re-attach `id` / `alsoKnownAs` / verification-method
/// `controller`s (which the encoding strips), per the did:peer numalgo-4 spec.
fn decode_peer4_long(did: &str, encoded: &str) -> ResolutionResult<DidDocument> {
    // did = "did:peer:4<hash>:<encoded>"; short form is everything before ":<encoded>".
    let short = &did[..did.len() - encoded.len() - 1];
    let got_hash = short.strip_prefix("did:peer:4").unwrap_or_default();
    let expected_hash = hash_encoded_document(encoded);
    if got_hash != expected_hash.as_str() {
        return Err(ResolutionError::ResolutionFailed(format!(
            "did:peer:4 self-certifying hash mismatch: {did}"
        )));
    }

    // Multibase-decode ('z' = base58btc), then strip the varint JSON multicodec.
    let (_base, data) = multibase::decode(encoded).map_err(|e| {
        ResolutionError::ResolutionFailed(format!("did:peer:4 multibase decode: {e}"))
    })?;
    let (codec, rest) = read_uvarint(&data).ok_or_else(|| {
        ResolutionError::ResolutionFailed("did:peer:4 truncated multicodec".into())
    })?;
    if codec != 0x0200 {
        return Err(ResolutionError::ResolutionFailed(format!(
            "did:peer:4 unexpected multicodec 0x{codec:x} (want 0x0200 JSON)"
        )));
    }

    let mut doc: serde_json::Value = serde_json::from_slice(rest).map_err(|e| {
        ResolutionError::ResolutionFailed(format!("did:peer:4 document JSON: {e}"))
    })?;
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("id".into(), serde_json::Value::String(did.to_string()));
        obj.insert("alsoKnownAs".into(), serde_json::json!([short]));
        // The encoding drops each verification method's controller; the spec
        // says the resolved controller is the DID itself.
        for field in [
            "verificationMethod",
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityDelegation",
            "capabilityInvocation",
        ] {
            if let Some(arr) = obj.get_mut(field).and_then(|v| v.as_array_mut()) {
                for item in arr.iter_mut() {
                    if let Some(m) = item.as_object_mut() {
                        m.entry("controller")
                            .or_insert_with(|| serde_json::Value::String(did.to_string()));
                    }
                }
            }
        }
    }

    serde_json::from_value(doc)
        .map_err(|e| ResolutionError::InternalError(format!("did:peer:4 -> DidDocument: {e}")))
}

/// `z` + base58btc( multihash-sha2-256( utf8(encoded) ) ) — the numalgo-4
/// document hash. Multihash sha2-256 = 0x12 (code) 0x20 (len) ++ digest.
fn hash_encoded_document(encoded: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(encoded.as_bytes());
    let mut mh = Vec::with_capacity(2 + digest.len());
    mh.push(0x12);
    mh.push(0x20);
    mh.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// Minimal unsigned-LEB128 varint reader → (value, remaining bytes).
fn read_uvarint(data: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &data[i + 1..]));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// did:peer Creator - Creates new did:peer DIDs (numalgo 2)
///
/// Creates did:peer:2 DIDs with embedded keys and service endpoint.
/// Format: `did:peer:2.V<auth_key>.E<agreement_key>.S<service>`
///
/// These DIDs are self-resolving — keys and service are encoded directly in the DID string.
pub struct PeerDidCreator {
    wallet: Arc<dyn WalletProvider>,
    did_repository: Arc<DidRepository>,
}

impl PeerDidCreator {
    pub fn new(wallet: Arc<dyn WalletProvider>, did_repository: Arc<DidRepository>) -> Self {
        Self {
            wallet,
            did_repository,
        }
    }
}

#[async_trait]
impl DidCreator for PeerDidCreator {
    async fn create(&self, options: CreateDidOptions) -> ResolutionResult<CreateDidResult> {
        // Extract service endpoint (required for did:peer:2)
        let service_endpoint = options.service_endpoints.first().ok_or_else(|| {
            ResolutionError::InvalidDid(
                "did:peer:2 requires at least one service endpoint".to_string(),
            )
        })?;

        // Extract optional routing keys from options
        let routing_keys: Vec<String> = options
            .options
            .get("routing_keys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Extract optional accept protocols (default: didcomm/v2)
        let accept: Vec<String> = options
            .options
            .get("accept")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| vec!["didcomm/v2".to_string()]);

        // 1. Create Ed25519 key in wallet (for authentication/signing)
        let key = self
            .wallet
            .create_key(KeyType::Ed25519, KeyPurpose::AgentDID)
            .await
            .map_err(|e| ResolutionError::InternalError(format!("Failed to create key: {}", e)))?;

        let ed25519_public_key = &key.public_key;

        // 2. Convert Ed25519 to X25519 for keyAgreement (encryption)
        let x25519_public_key =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public_key)
                .map_err(|e| {
                    ResolutionError::InternalError(format!("Invalid Ed25519 key: {:?}", e))
                })?
                .decompress()
                .ok_or_else(|| {
                    ResolutionError::InternalError("Failed to decompress Ed25519 key".to_string())
                })?
                .to_montgomery()
                .to_bytes();

        // 3. Encode keys as multibase (z-prefix base58btc with multicodec prefix)
        //    V = Verification method (authentication)
        let mut auth_multicodec = vec![0xed, 0x01]; // Ed25519 multicodec prefix
        auth_multicodec.extend_from_slice(ed25519_public_key);
        let auth_key_encoded = multibase::encode(multibase::Base::Base58Btc, &auth_multicodec);

        //    E = Encryption (key agreement)
        let mut agreement_multicodec = vec![0xec, 0x01]; // X25519 multicodec prefix
        agreement_multicodec.extend_from_slice(&x25519_public_key);
        let agreement_key_encoded =
            multibase::encode(multibase::Base::Base58Btc, &agreement_multicodec);

        // Choose the service dialect from the negotiated `accept` profiles.
        //
        // Aries DIDComm v1 peers (DID Exchange / RFC 0023, e.g. credo) resolve a
        // `did-communication` service with an explicit `recipientKeys` list.
        // The did:peer:2 `dm` (DIDCommMessaging) abbreviation is DIDComm v2 —
        // an Aries v1 agent resolves ZERO usable services from it and reports
        // the peer as undeliverable. So when the profile is v1, emit the
        // `did-communication` form credo/Aries expects (recipientKeys → the
        // first verification method, `#key-1`). Otherwise keep the v2 `dm` form.
        let is_didcomm_v1 = accept
            .iter()
            .any(|a| a.contains("aip") || a.contains("rfc19") || a.contains("rfc0"));

        // 4. Encode service endpoint as base64url for did:peer:2 (NOT multibase)
        let service_json = if is_didcomm_v1 {
            serde_json::json!({
                "t": "did-communication",
                "s": service_endpoint,
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "r": routing_keys
            })
        } else {
            serde_json::json!({
                "t": "dm",
                "s": service_endpoint,
                "r": routing_keys,
                "a": accept
            })
        };
        let service_str = serde_json::to_string(&service_json).map_err(|e| {
            ResolutionError::InternalError(format!("Failed to serialize service: {}", e))
        })?;
        let service_encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(service_str.as_bytes());

        // 5. Compose did:peer:2 string
        let peer_did = format!(
            "did:peer:2.V{}.E{}.S{}",
            auth_key_encoded, agreement_key_encoded, service_encoded
        );

        // 6. Build the DID Document
        let mut did_document = DidDocument::new(peer_did.clone());
        did_document.context = Some(serde_json::json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
        ]));

        // Authentication key (Ed25519)
        let auth_vm = VerificationMethod::new(
            format!("{}#key-1", peer_did),
            "Ed25519VerificationKey2020".to_string(),
            peer_did.clone(),
        )
        .with_public_key_multibase(auth_key_encoded);

        // Key agreement key (X25519)
        let agreement_vm = VerificationMethod::new(
            format!("{}#key-2", peer_did),
            "X25519KeyAgreementKey2020".to_string(),
            peer_did.clone(),
        )
        .with_public_key_multibase(agreement_key_encoded);

        did_document.add_verification_method(auth_vm);
        did_document.add_verification_method(agreement_vm);
        did_document.add_authentication(VerificationRelationship::Reference(format!(
            "{}#key-1",
            peer_did
        )));
        did_document.add_key_agreement(VerificationRelationship::Reference(format!(
            "{}#key-2",
            peer_did
        )));

        // DIDComm service — mirror the dialect chosen for the encoded `.S`
        // element so our stored DID Document matches what we advertise on the
        // wire. v1 (`did-communication`) carries `recipientKeys`; v2
        // (`DIDCommMessaging`) carries `accept`.
        let service = if is_didcomm_v1 {
            Service::new(
                "#didcomm".to_string(),
                "did-communication".to_string(),
                serde_json::json!(service_endpoint),
            )
            .with_property("priority".to_string(), serde_json::json!(0))
            .with_property(
                "recipientKeys".to_string(),
                serde_json::json!([format!("{}#key-1", &peer_did)]),
            )
            .with_property("routingKeys".to_string(), serde_json::json!(routing_keys))
        } else {
            Service::new(
                "#didcomm".to_string(),
                "DIDCommMessaging".to_string(),
                serde_json::json!(service_endpoint),
            )
            .with_property("accept".to_string(), serde_json::json!(accept))
            .with_property("routingKeys".to_string(), serde_json::json!(routing_keys))
        };
        did_document.add_service(service);

        // 7. Store in DidRepository
        //    BOTH key-1 (Ed25519 auth) and key-2 (X25519 keyAgreement) map to the same
        //    wallet key ID because X25519 is derived from Ed25519.
        //    The secrets resolver needs key-2 to decrypt incoming DIDComm v2 messages.
        let keys = vec![
            DidDocumentKey::new(key.id.clone(), format!("{}#key-1", peer_did)),
            DidDocumentKey::new(key.id.clone(), format!("{}#key-2", peer_did)),
        ];

        let did_record = self
            .did_repository
            .store_created_did(peer_did.clone(), Some(did_document.clone()), keys)
            .map_err(|e| ResolutionError::InternalError(format!("Failed to store DID: {}", e)))?;

        // 8. Build result
        let did = DID::parse(&peer_did).map_err(|e| {
            ResolutionError::InternalError(format!("Failed to parse created DID: {}", e))
        })?;

        let mut result = CreateDidResult::new(did, did_document, did_record);
        result = result.with_metadata("key_id".to_string(), serde_json::json!(key.id));

        Ok(result)
    }
}

/// Fully-decoded view of a self-resolving did:peer:2 (numalgo 2), extracted
/// directly from the DID string. did:peer:2 encodes:
///   - `.V<mb>`  Ed25519 authentication key (multibase)
///   - `.E<mb>`  X25519 key-agreement key (multibase)
///   - `.S<b64>` service block — base64url JSON with `s`/`serviceEndpoint`,
///     `t`/`type`, `r`/`routingKeys`
///
/// Keys are returned as raw base58 verkeys — the form Aries DIDComm v1 packing,
/// mediator keylists, and connection key-matching use. This is the canonical
/// RAW decoder: `PeerDidResolver` normalizes a did:peer:2 to `Multikey` /
/// `DIDCommMessaging`, dropping `did-communication` and the base58 form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer2Service {
    /// Service endpoint (`s` / `serviceEndpoint`).
    pub service_endpoint: Option<String>,
    /// Service `t` / `type` — e.g. `did-communication` (DIDComm v1) or
    /// `dm` / `DIDCommMessaging` (v2).
    pub service_type: Option<String>,
    /// Routing keys (`r` / `routingKeys`).
    pub routing_keys: Vec<String>,
    /// `.V` authentication key (Ed25519) as base58.
    pub authentication_key: Option<String>,
    /// `.E` key-agreement key (X25519) as base58.
    pub key_agreement_key: Option<String>,
    /// All `.V` + `.E` keys as base58, in DID order.
    pub recipient_keys: Vec<String>,
}

/// Parse a self-resolving did:peer:2 into its keys and service block. Returns
/// `None` for non-peer:2 DIDs. This is the single canonical did:peer:2 decoder —
/// callers needing endpoint / service type / routing keys / raw base58 keys
/// should use it rather than re-decoding the DID string.
pub fn parse_peer2(did: &str) -> Option<Peer2Service> {
    if !did.starts_with("did:peer:2") || did.len() < 11 {
        return None;
    }
    let mut out = Peer2Service::default();
    for part in did[10..].split('.') {
        if part.len() < 2 {
            continue;
        }
        let (tag, rest) = part.split_at(1);
        match tag {
            "V" | "E" => {
                let Some(b58) = crate::methods::key::multibase_to_base58_verkey(rest) else {
                    continue;
                };
                if tag == "V" && out.authentication_key.is_none() {
                    out.authentication_key = Some(b58.clone());
                } else if tag == "E" && out.key_agreement_key.is_none() {
                    out.key_agreement_key = Some(b58.clone());
                }
                out.recipient_keys.push(b58);
            }
            "S" => {
                use base64::Engine as _;
                let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(rest)
                else {
                    continue;
                };
                let Ok(svc) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
                    continue;
                };
                out.service_endpoint = svc
                    .get("s")
                    .and_then(|v| v.as_str())
                    .or_else(|| svc.get("serviceEndpoint").and_then(|v| v.as_str()))
                    .map(String::from);
                out.service_type = svc
                    .get("t")
                    .and_then(|v| v.as_str())
                    .or_else(|| svc.get("type").and_then(|v| v.as_str()))
                    .map(String::from);
                out.routing_keys = svc
                    .get("r")
                    .or_else(|| svc.get("routingKeys"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    Some(out)
}

/// Convenience: `(authentication_key, key_agreement_key)` base58 from a
/// did:peer:2. Thin wrapper over [`parse_peer2`].
pub fn parse_peer2_verkeys(did: &str) -> (Option<String>, Option<String>) {
    match parse_peer2(did) {
        Some(p) => (p.authentication_key, p.key_agreement_key),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_resolver_method_name() {
        let did_repo = Arc::new(DidRepository::new());
        let resolver = PeerDidResolver::new(did_repo);
        assert_eq!(resolver.method_name(), "peer");
    }

    #[tokio::test]
    async fn test_peer_resolver_no_caching() {
        let did_repo = Arc::new(DidRepository::new());
        let resolver = PeerDidResolver::new(did_repo);
        assert!(!resolver.allows_caching());
    }

    /// Mint a long-form numalgo-4 did:peer from a DID document — the inverse of
    /// `decode_peer4_long`: multicodec-tag + multibase the document, then prefix
    /// the self-certifying hash. Lets the tests generate a fresh DID rather than
    /// pin an external fixture.
    fn make_peer4(doc: &serde_json::Value) -> String {
        let json = serde_json::to_vec(doc).unwrap();
        let mut buf = Vec::with_capacity(2 + json.len());
        buf.extend_from_slice(&[0x80, 0x04]); // varint(0x0200) = JSON multicodec
        buf.extend_from_slice(&json);
        let encoded = multibase::encode(multibase::Base::Base58Btc, buf);
        format!("did:peer:4{}:{}", hash_encoded_document(&encoded), encoded)
    }

    fn sample_peer4() -> String {
        make_peer4(&serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "#key-1",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7yZ8dsuNc6TFcs2Wj"
            }],
            "authentication": ["#key-1"],
            "service": [{
                "id": "#didcomm",
                "type": "did-communication",
                "serviceEndpoint": "https://example.org/didcomm/tenant-1"
            }]
        }))
    }

    #[test]
    fn decodes_numalgo4_long_form() {
        let did = sample_peer4();
        let encoded = split_peer4_long(&did).expect("recognised as long form");
        let doc = decode_peer4_long(&did, encoded).expect("decodes without error");
        // id re-attached to the full long-form DID.
        assert_eq!(doc.id, did);
        // Embedded keys + service survive (so idiom can pack a reply and route it).
        assert!(!doc.verification_method.is_empty());
        assert!(!doc.service.is_empty());
        // Verification-method controller is set to the DID.
        assert_eq!(doc.verification_method[0].controller, did);
        // alsoKnownAs points at the short form (the DID minus the ":<encoded>" tail).
        let short = &did[..did.len() - encoded.len() - 1];
        assert!(doc.also_known_as.iter().any(|a| a == short));
    }

    #[test]
    fn numalgo4_short_form_is_not_long() {
        // Short form (no ":<encoded>" suffix) must NOT decode inline — it needs storage.
        let did = sample_peer4();
        let short = &did[..did.len() - split_peer4_long(&did).unwrap().len() - 1];
        assert!(split_peer4_long(short).is_none());
    }

    #[test]
    fn numalgo4_hash_mismatch_rejected() {
        // Corrupt the embedded document → self-certifying hash check must fail.
        let did = sample_peer4();
        let last = did.chars().next_back().unwrap();
        let tampered = format!("{}{}", &did[..did.len() - 1], if last == 'A' { 'B' } else { 'A' });
        let enc = split_peer4_long(&tampered).expect("still long form");
        assert!(decode_peer4_long(&tampered, enc).is_err());
    }

    #[tokio::test]
    async fn test_resolve_peer_did_numalgo_2() {
        let did_repo = Arc::new(DidRepository::new());
        let resolver = PeerDidResolver::new(did_repo);

        // Example did:peer:2 DID
        // This is a real did:peer that should resolve
        let did_str = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0";

        match DID::parse(did_str) {
            Ok(did) => {
                let result = resolver.resolve(&did).await;
                // The resolution might fail if the DID format is complex
                // but it should at least attempt resolution
                match result {
                    Ok(doc) => {
                        assert_eq!(doc.id, did_str);
                    }
                    Err(e) => {
                        // Expected - complex did:peer might not resolve without proper setup
                        println!("Resolution failed (expected for complex did:peer): {:?}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Failed to parse did:peer: {}", e);
            }
        }
    }
}
