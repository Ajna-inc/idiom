//! Canonical DIDComm sender.
//!
//! One place that does the full "resolve DID → pack authcrypt → wrap in
//! Forward → POST" dance. Every protocol module (reactions, receipts,
//! presence, files, basic_messages, rooms, workspaces, ...) goes through
//! this instead of re-implementing the same 80-line function inline.
//!
//! Three call shapes, picked to cover every existing site:
//!   - `send(sender_did, recipient_did, msg)` — primary form
//!   - `send_via_connection(connection, msg)` — when caller has a
//!     `ConnectionRecord` and wants pairwise DIDs auto-resolved
//!   - The return value is `Option<String>` carrying the synchronous HTTP
//!     response body if the transport captured one (mediator handlers
//!     return packed responses inline). Fire-and-forget callers discard it.

use std::sync::Arc;

use protocol_connections::ConnectionRecord;
use protocol_coordinate_mediation::ForwardMessage;

use crate::error::{AgentError, Result};
use crate::messaging::MessageEncryption;
use crate::transport::{EncryptedMessage, TransportManager};
use did::core::DidRepository;

/// Shared DIDComm send primitive. Replaces the duplicated
/// `send_packed_message` in every module.
#[derive(Clone)]
pub struct DidCommSender {
    transport: Arc<TransportManager>,
    message_encryption: Arc<MessageEncryption>,
    did_repository: Arc<DidRepository>,
    /// Optional DCX fast-path. When set and a channel exists to the
    /// recipient, `send` bypasses the JWE + Forward wrapping and ships
    /// the plaintext DIDComm envelope inside an AEAD-sealed DCX frame.
    /// Never set on the receiver side alone — the mediator opaquely
    /// relays and the peer's inbound DCX extension decodes. Falls back
    /// to JWE on any DCX error, so wire changes are safe rollbacks.
    dcx: Option<Arc<didcomm::dcx::DcxRuntime>>,
}

impl DidCommSender {
    pub fn new(
        transport: Arc<TransportManager>,
        message_encryption: Arc<MessageEncryption>,
        did_repository: Arc<DidRepository>,
    ) -> Self {
        Self {
            transport,
            message_encryption,
            did_repository,
            dcx: None,
        }
    }

    /// Enable the DCX fast-path with a caller-supplied runtime.
    /// Chainable at construction: `DidCommSender::new(...).with_dcx(rt)`.
    pub fn with_dcx(mut self, dcx: Arc<didcomm::dcx::DcxRuntime>) -> Self {
        self.dcx = Some(dcx);
        self
    }

    /// Send `message` from `sender_did` to `recipient_did`. Resolves the
    /// recipient's DID document to extract endpoint + routing keys, packs
    /// authcrypt, wraps in Forward envelopes (one per routing key, applied
    /// right-to-left so the outer envelope is for the first hop), and
    /// POSTs to the endpoint.
    ///
    /// Returns the HTTP response body if the transport surfaces one —
    /// embedded-mediator handlers reply with a packed response in-band.
    pub async fn send<M: serde::Serialize>(
        &self,
        sender_did: &str,
        recipient_did: &str,
        message: &M,
    ) -> Result<Option<String>> {
        // DCX fast path — sender wraps the plaintext DIDComm envelope
        // in a single AEAD-sealed frame instead of JWE + Forward. The
        // mediator peeks the frame's routing_prefix and relays the
        // ciphertext body verbatim; the peer's DCX inbound extension
        // decrypts and dispatches. Falls back to the legacy JWE path
        // on ANY error so a partial DCX rollout can't break sends.
        //
        // `send_to_peer` internally checks `classical.establish` —
        // succeeds when material was pre-registered for this peer
        // (peer↔peer or root↔mediator paths in agent_tenants) and
        // errors out cheaply when it wasn't, so we can call it
        // unconditionally without a pre-existence check.
        if let Some(ref dcx) = self.dcx {
            match serde_json::to_vec(message) {
                Ok(payload) => match dcx.outbound.send_to_peer(recipient_did, payload).await {
                    Ok(()) => {
                        tracing::trace!(
                            target: "dcx.sender",
                            %sender_did,
                            %recipient_did,
                            "DCX fast-path sent"
                        );
                        return Ok(None);
                    }
                    Err(e) => {
                        tracing::debug!(
                            target: "dcx.sender",
                            %recipient_did,
                            "DCX fast-path failed ({}); falling back to JWE", e
                        );
                    }
                },
                Err(e) => {
                    tracing::debug!(
                        target: "dcx.sender",
                        "DCX fast-path serialize failed ({}); falling back to JWE", e
                    );
                }
            }
        }

        // 1./2. Resolve recipient service (endpoint + routing keys + recipient
        // key). Prefer a stored DID document; fall back to self-resolving a
        // did:peer:2 directly from the DID string. A self-resolving did:peer:2
        // (credo's connection DID) is stored only as a reference with NO
        // document, so the stored-doc path fails with "DID record has no
        // document" — decode the `.S`/`.V` elements from the DID instead.
        let stored_doc = self
            .did_repository
            .find_by_did(recipient_did)
            .and_then(|r| r.did_document.clone());

        let (endpoint, routing_keys, recipient_key) = if let Some(did_doc) = stored_doc {
            let service = did_doc.service.first().ok_or_else(|| {
                AgentError::DidResolution(format!(
                    "DID document has no services: {}",
                    recipient_did
                ))
            })?;
            let endpoint = service
                .service_endpoint
                .as_str()
                .ok_or_else(|| {
                    AgentError::DidResolution("Service endpoint is not a string".into())
                })?
                .to_string();
            let routing_keys: Vec<String> = service
                .properties
                .get("routingKeys")
                .or_else(|| service.properties.get("routing_keys"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let recipient_key: Option<String> = service
                .properties
                .get("recipientKeys")
                .or_else(|| service.properties.get("recipient_keys"))
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|k| k.as_str())
                .map(|key_ref| {
                    if key_ref.starts_with('#') {
                        did_doc
                            .verification_method
                            .iter()
                            .find(|vm| vm.id.ends_with(key_ref) || vm.id.contains(key_ref))
                            .and_then(|vm| vm.public_key_base58.clone())
                            .unwrap_or_else(|| key_ref.to_string())
                    } else {
                        key_ref.to_string()
                    }
                });
            (endpoint, routing_keys, recipient_key)
        } else if let Some(resolved) = resolve_did_peer2_service(recipient_did) {
            resolved
        } else if let Some(resolved) = resolve_did_peer4_service(recipient_did) {
            resolved
        } else {
            return Err(AgentError::DidResolution(format!(
                "Cannot resolve DID: {}",
                recipient_did
            )));
        };

        // DIAG: log resolved transport/routing details for this send
        tracing::debug!(
            target: "didcomm.diag",
            %recipient_did,
            %sender_did,
            %endpoint,
            ?routing_keys,
            ?recipient_key,
            "sender.send"
        );

        // 3. Pack authcrypt
        let packed_jwe = self
            .message_encryption
            .pack_encrypted_message(message, recipient_did, sender_did)
            .await?;

        // DIAG: extract the JWE recipients[*].header.kid actually on the
        // wire. For DIDComm v1 these live inside the base64url-encoded
        // `protected` header. Only run the parse when the diag target
        // is actually enabled — otherwise this is wasted work on every
        // outbound message.
        if tracing::enabled!(target: "didcomm.diag", tracing::Level::DEBUG) {
            if let Ok(jwe_val) = serde_json::from_str::<serde_json::Value>(&packed_jwe) {
                use base64::Engine as _;
                let kids: Vec<String> = jwe_val
                    .get("protected")
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(s)
                            .ok()
                    })
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .and_then(|hdr| {
                        hdr.get("recipients").and_then(|v| v.as_array()).map(|arr| {
                            arr.iter()
                                .filter_map(|r| {
                                    r.get("header")
                                        .and_then(|h| h.get("kid"))
                                        .and_then(|k| k.as_str())
                                        .map(String::from)
                                })
                                .collect::<Vec<_>>()
                        })
                    })
                    .unwrap_or_default();
                tracing::debug!(
                    target: "didcomm.diag",
                    %recipient_did,
                    wire_kids = ?kids,
                    "packed_jwe"
                );
            }
        }

        // 4. Wrap in Forward envelopes (right-to-left so the outer envelope
        //    is for the first hop). Mediator forwards by walking inward.
        let final_packed = if !routing_keys.is_empty() {
            let mut current_packed = packed_jwe;
            let recipient_key_raw = recipient_key.unwrap_or_else(|| recipient_did.to_string());
            let mut current_to = ensure_base58_verkey(&recipient_key_raw)?;

            for routing_key in routing_keys.iter().rev() {
                let current_packed_json: serde_json::Value = serde_json::from_str(&current_packed)
                    .map_err(|e| AgentError::Module(format!("Failed to parse JWE: {}", e)))?;
                let forward_msg = ForwardMessage::new(current_to.clone(), current_packed_json);
                current_packed = self
                    .message_encryption
                    .pack_anon_message(&forward_msg, routing_key)
                    .await
                    .map_err(|e| AgentError::Module(format!("Failed to pack Forward: {}", e)))?;
                current_to = ensure_base58_verkey(routing_key)?;
            }
            current_packed
        } else {
            packed_jwe
        };

        // 5. Send via the configured outbound transport
        let encrypted_msg = EncryptedMessage::new(
            "jwe".to_string(),
            "jwe".to_string(),
            final_packed,
            "jwe".to_string(),
        );
        self.transport
            .send_message(encrypted_msg, &endpoint)
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))
    }

    /// Send `message` via an established `ConnectionRecord`. Sender DID is
    /// the connection's pairwise `did`, recipient is `their_did`. Returns
    /// the transport response just like `send`.
    pub async fn send_via_connection<M: serde::Serialize>(
        &self,
        connection: &ConnectionRecord,
        message: &M,
    ) -> Result<Option<String>> {
        let their_did = connection
            .their_did
            .as_ref()
            .ok_or_else(|| AgentError::Connections("Connection not yet completed".to_string()))?;
        self.send(&connection.did, their_did, message).await
    }

    /// Deliver an already-packed JWE to a connection's resolved endpoint.
    ///
    /// Used to forward a nested return-route reply — e.g. the issuer receives a
    /// credential request inline (as the HTTP response to its offer POST),
    /// processes it, and produces an `issue-credential` message already packed
    /// for the holder. That reply can't ride the offer's response (which is
    /// already consumed), so it must be shipped as a fresh POST. The bytes are
    /// packed for the peer, so we only resolve the endpoint and send — no
    /// re-pack. Direct (non-mediated) delivery: if the peer advertises routing
    /// keys, the caller's normal (non-prepacked) path should be used instead.
    pub async fn send_prepacked_via_connection(
        &self,
        connection: &ConnectionRecord,
        packed: String,
    ) -> Result<Option<String>> {
        let recipient_did = connection
            .their_did
            .as_ref()
            .ok_or_else(|| AgentError::Connections("Connection not yet completed".to_string()))?;

        // Resolve the peer's service endpoint — a stored DID doc first, else a
        // self-resolving did:peer:2. Mirrors `send`'s resolution.
        let stored_doc = self
            .did_repository
            .find_by_did(recipient_did)
            .and_then(|r| r.did_document.clone());
        let (endpoint, routing_keys) = if let Some(did_doc) = stored_doc {
            let service = did_doc.service.first().ok_or_else(|| {
                AgentError::DidResolution(format!("DID document has no services: {recipient_did}"))
            })?;
            let endpoint = service
                .service_endpoint
                .as_str()
                .ok_or_else(|| {
                    AgentError::DidResolution("Service endpoint is not a string".into())
                })?
                .to_string();
            let routing_keys: Vec<String> = service
                .properties
                .get("routingKeys")
                .or_else(|| service.properties.get("routing_keys"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            (endpoint, routing_keys)
        } else if let Some((endpoint, routing_keys, _)) = resolve_did_peer2_service(recipient_did) {
            (endpoint, routing_keys)
        } else if let Some((endpoint, routing_keys, _)) = resolve_did_peer4_service(recipient_did) {
            (endpoint, routing_keys)
        } else {
            return Err(AgentError::DidResolution(format!(
                "Cannot resolve DID: {recipient_did}"
            )));
        };

        if !routing_keys.is_empty() {
            tracing::warn!(
                %recipient_did,
                "send_prepacked_via_connection: peer advertises routing keys; \
                 delivering directly without Forward wrapping"
            );
        }

        self.transport
            .send_to_endpoint(&endpoint, &packed)
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))
    }

    /// Pack `message` as authcrypt from `sender_did` to `recipient_did`
    /// and POST it directly to `endpoint`, bypassing DID-document
    /// resolution and Forward wrapping. Used for direct sends to a known
    /// mediator endpoint (room fan-out, mesh bypass) where the routing
    /// happens server-side based on the inner message envelope.
    pub async fn pack_and_send_to_endpoint<M: serde::Serialize>(
        &self,
        sender_did: &str,
        recipient_did: &str,
        message: &M,
        endpoint: &str,
    ) -> Result<Option<String>> {
        let packed = self
            .message_encryption
            .pack_encrypted_message(message, recipient_did, sender_did)
            .await?;
        self.transport
            .send_to_endpoint(endpoint, &packed)
            .await
            .map_err(|e| AgentError::Transport(e.to_string()))
    }
}

/// Convert a did:key into the base58-encoded verkey that the mediator
/// stores as the routing key's lookup index. Pure helper, used while
/// wrapping Forward envelopes.
fn ensure_base58_verkey(key: &str) -> Result<String> {
    if key.starts_with("did:key:z") {
        return did::methods::key::did_key_to_base58_verkey(key)
            .ok_or_else(|| AgentError::Module(format!("Failed to decode did:key: {}", key)));
    }
    Ok(key.to_string())
}

/// Self-resolve a did:peer:2 to `(endpoint, routing_keys, recipient_key_base58)`.
/// did:peer:2 is self-resolving and often stored only as a reference with NO DID
/// document, so `send_via_connection` decodes it via the canonical
/// [`did::methods::peer::parse_peer2`]. The recipient key is the `.V` Ed25519
/// auth key (base58), used as the v1 `kid` / mediator keylist entry.
fn resolve_did_peer2_service(did: &str) -> Option<(String, Vec<String>, Option<String>)> {
    let p = did::methods::peer::parse_peer2(did)?;
    let endpoint = p.service_endpoint?;
    Some((endpoint, p.routing_keys, p.authentication_key))
}

/// Self-resolve a long-form did:peer:4 to `(endpoint, routing_keys,
/// recipient_key_base58)`. numalgo-4 DIDs (e.g. mediated mobile/Bifold wallets)
/// are self-resolving and stored only as a reference with no document, so —
/// exactly like [`resolve_did_peer2_service`] — decode the embedded document via
/// the canonical [`did::methods::peer::parse_peer4`] rather than the repository.
fn resolve_did_peer4_service(did: &str) -> Option<(String, Vec<String>, Option<String>)> {
    let p = did::methods::peer::parse_peer4(did)?;
    let endpoint = p.service_endpoint?;
    Some((endpoint, p.routing_keys, p.authentication_key))
}
