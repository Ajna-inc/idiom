//! Mesh Outbound Transport
//!
//! Bridges the agent's DIDComm transport layer to the mesh networking layer,
//! enabling DIDComm messages to be sent via BLE mesh using `mesh://` endpoints.

use async_trait::async_trait;
use didcomm::transports::MessageReceiver;
use protocol_mesh::{MeshMessageHandler, RoutingID};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

/// Topic + name constants for mesh-relay events emitted by this module.
///
/// Producers send these via `EventBus::emit` so the iOS Dart layer (and any
/// Rust subscriber) receives a typed payload instead of a hand-built JSON
/// blob. Topic stays `mesh_relay` to preserve the wire shape for in-flight
/// Dart consumers; name encodes the variant.
pub mod relay_events {
    pub const TOPIC: &str = "mesh_relay";
    pub const COMPLETE: &str = "mesh_redeem_complete";
    pub const FAILED: &str = "mesh_redeem_failed";
}

/// Payload for `mesh_redeem_complete` — server's decrypted response landed
/// successfully and the receipt is good to record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRedeemCompletePayload {
    pub request_id: String,
    pub success: bool,
    pub transaction_ref: String,
    pub amount_credited: String,
    pub token_symbol: String,
    pub receipt_signature: Option<String>,
}

impl agent_events::TypedEvent for MeshRedeemCompletePayload {
    const TOPIC: &'static str = relay_events::TOPIC;
    const NAME: &'static str = relay_events::COMPLETE;
}

/// Payload for `mesh_redeem_failed` — relay errored or the response failed
/// to decrypt; UI surfaces this as a retry hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRedeemFailedPayload {
    pub request_id: String,
    pub error: String,
}

impl agent_events::TypedEvent for MeshRedeemFailedPayload {
    const TOPIC: &'static str = relay_events::TOPIC;
    const NAME: &'static str = relay_events::FAILED;
}

/// Mesh Outbound Transport
///
/// Implements `didcomm::transports::OutboundTransport` to allow the agent's
/// TransportManager to route messages to `mesh://<hex-routing-id>` endpoints
/// via the BLE mesh network.
pub struct MeshOutboundTransport {
    /// Reference to the mesh message handler for sending
    mesh_handler: Arc<MeshMessageHandler>,
}

impl MeshOutboundTransport {
    /// Create a new MeshOutboundTransport
    pub fn new(mesh_handler: Arc<MeshMessageHandler>) -> Self {
        Self { mesh_handler }
    }
}

#[async_trait]
impl didcomm::transports::OutboundTransport for MeshOutboundTransport {
    async fn send(
        &self,
        endpoint: &str,
        message: &str,
    ) -> didcomm::transports::Result<Option<String>> {
        let routing_id = parse_mesh_endpoint(endpoint).map_err(|e| {
            didcomm::transports::TransportError::InvalidEndpoint(format!(
                "Invalid mesh endpoint '{}': {}",
                endpoint, e
            ))
        })?;

        debug!(
            endpoint = %endpoint,
            routing_id = %routing_id.to_hex(),
            "Sending DIDComm message via mesh transport"
        );

        let packet_id = self
            .mesh_handler
            .send_message(message.to_string(), Some(&routing_id), false)
            .await
            .map_err(|e| {
                didcomm::transports::TransportError::SendFailed(format!(
                    "Mesh send failed: {}",
                    e
                ))
            })?;

        debug!(packet_id = %packet_id, "Message sent via mesh");

        // Mesh is fire-and-forget; return the packet ID as acknowledgment
        Ok(Some(packet_id))
    }

    fn supports_endpoint(&self, endpoint: &str) -> bool {
        endpoint.starts_with("mesh://")
    }
}

/// Parse a `mesh://<hex-routing-id>` endpoint into a RoutingID.
fn parse_mesh_endpoint(endpoint: &str) -> Result<RoutingID, MeshEndpointError> {
    let hex_str = endpoint
        .strip_prefix("mesh://")
        .ok_or(MeshEndpointError::MissingScheme)?;

    if hex_str.is_empty() {
        return Err(MeshEndpointError::EmptyRoutingId);
    }

    RoutingID::from_hex(hex_str).map_err(MeshEndpointError::InvalidHex)
}

/// Errors when parsing mesh endpoints
#[derive(Debug, thiserror::Error)]
enum MeshEndpointError {
    #[error("endpoint does not start with mesh://")]
    MissingScheme,
    #[error("routing ID is empty")]
    EmptyRoutingId,
    #[error("invalid hex in routing ID: {0}")]
    InvalidHex(hex::FromHexError),
}

// =============================================================================
// Inbound Loops
// =============================================================================

/// An OOB invitation received over mesh, pending user accept/decline
#[derive(Debug, Clone)]
pub struct MeshOobInvite {
    /// Routing ID of the sender (hex)
    pub sender_routing_id: String,
    /// The OOB invitation URL
    pub invitation_url: String,
}

/// Check if a payload looks like an OOB invitation URL
fn is_oob_url(payload: &str) -> bool {
    // OOB URLs contain ?oob= or &oob= with a base64url-encoded invitation
    payload.contains("?oob=") || payload.contains("&oob=")
}

/// Run the mesh packet processing loop.
///
/// Receives raw mesh packets from the BLE transport, processes them through the
/// MeshMessageHandler (dedup, relay decisions), and forwards payloads destined
/// for this agent to the payload channel.
///
/// If the payload is an OOB invitation URL (contains `?oob=`), it's sent to
/// `oob_invite_tx` instead so native can show an accept/decline prompt.
pub async fn run_mesh_inbound_loop(
    handler: Arc<MeshMessageHandler>,
    mut packet_rx: tokio::sync::mpsc::Receiver<protocol_mesh::MeshPacket>,
    payload_tx: tokio::sync::mpsc::Sender<(String, String)>,
    oob_invite_tx: Option<tokio::sync::mpsc::Sender<MeshOobInvite>>,
) {
    use protocol_mesh::handler::{MeshContext, TransportType};

    tracing::info!("[MESH-INBOUND] Mesh inbound loop started, waiting for packets...");
    tracing::debug!("[MESH-INBOUND] Mesh inbound loop started, waiting for packets...");
    debug!("Mesh inbound loop started");

    while let Some(packet) = packet_rx.recv().await {
        let sender_routing_id = packet.get_sender().to_hex();
        tracing::info!("[MESH-INBOUND] Received packet: id={}, sender={}, broadcast={}, payload_len={}",
            packet.id, sender_routing_id, packet.is_broadcast(), packet.payload.len());
        tracing::debug!("[MESH-INBOUND] Received packet: id={}, sender={}, dest={:?}, payload_len={}",
            packet.id, sender_routing_id,
            packet.get_dest().map(|d| d.to_hex()),
            packet.payload.len());

        let body = match serde_json::to_value(&packet) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("[MESH-INBOUND] Failed to serialize packet to JSON: {}", e);
                warn!("Failed to serialize mesh packet: {}", e);
                continue;
            }
        };

        let ctx = MeshContext {
            sender_did: None,
            sender_routing_id: Some(packet.get_sender()),
            message_id: packet.id.clone(),
            thread_id: None,
            transport: TransportType::Ble,
        };

        tracing::debug!("[MESH-INBOUND] Calling handler.handle(MESH_RELAY)...");
        match handler
            .handle(protocol_mesh::MESH_RELAY, body, ctx)
            .await
        {
            Ok(Some(response)) => {
                tracing::info!("[MESH-INBOUND] Handler returned Some(response), msg_type={}", response.msg_type);
                tracing::debug!("[MESH-INBOUND] Handler returned response (packet is for us!)");
                // Packet was for us - extract payload
                if let Some(payload) = response.body.get("payload").and_then(|v| v.as_str()) {
                    tracing::info!("[MESH-INBOUND] Extracted payload: len={}, is_oob={}", payload.len(), is_oob_url(payload));
                    tracing::debug!("[MESH-INBOUND] Extracted payload: len={}, is_oob={}", payload.len(), is_oob_url(payload));
                    if is_oob_url(payload) {
                        // OOB invitation URL — route to native for accept/decline prompt
                        tracing::debug!("[MESH-INBOUND] OOB invitation URL detected, routing to native");
                        debug!(
                            sender = %sender_routing_id,
                            "Received OOB invitation URL over mesh"
                        );
                        if let Some(ref oob_tx) = oob_invite_tx {
                            let invite = MeshOobInvite {
                                sender_routing_id: sender_routing_id.clone(),
                                invitation_url: payload.to_string(),
                            };
                            if oob_tx.send(invite).await.is_err() {
                                tracing::debug!("[MESH-INBOUND] OOB invite channel closed");
                                warn!("OOB invite channel closed");
                            }
                        } else {
                            // No OOB handler, fall through to normal DIDComm processing
                            if payload_tx.send((payload.to_string(), sender_routing_id.clone())).await.is_err() {
                                warn!("Payload channel closed, stopping mesh inbound loop");
                                break;
                            }
                        }
                    } else {
                        // Normal DIDComm message — forward to agent
                        tracing::debug!("[MESH-INBOUND] DIDComm message, forwarding to agent for processing");
                        if payload_tx.send((payload.to_string(), sender_routing_id.clone())).await.is_err() {
                            tracing::debug!("[MESH-INBOUND] Payload channel closed!");
                            warn!("Payload channel closed, stopping mesh inbound loop");
                            break;
                        } else {
                            tracing::debug!("[MESH-INBOUND] Payload sent to delivery channel");
                        }
                    }
                } else {
                    tracing::debug!("[MESH-INBOUND] Response has no 'payload' field! body={}", response.body);
                }
            }
            Ok(None) => {
                tracing::info!("[MESH-INBOUND] Handler returned None (relayed or not for us)");
                tracing::debug!("[MESH-INBOUND] Handler returned None (packet relayed or not for us)");
            }
            Err(e) => {
                let err_str = e.to_string();
                if !err_str.contains("already seen") {
                    tracing::info!("[MESH-INBOUND] Handler error: {}", err_str);
                    tracing::debug!("[MESH-INBOUND] Handler error: {}", err_str);
                    warn!("Mesh relay error: {}", e);
                } else {
                    // Don't println for duplicates - too noisy
                    tracing::debug!("[MESH-INBOUND] Duplicate packet (already seen)");
                }
            }
        }
    }

    tracing::debug!("[MESH-INBOUND] Mesh inbound loop stopped!");
    debug!("Mesh inbound loop stopped");
}

/// Run the mesh payload delivery loop.
///
/// Receives DIDComm payloads that have been extracted from mesh packets
/// (by `run_mesh_inbound_loop`) and delivers them to the agent for processing.
pub async fn run_mesh_payload_delivery(
    agent: Arc<crate::Agent>,
    mut payload_rx: tokio::sync::mpsc::Receiver<(String, String)>,
) {
    tracing::info!("[MESH-DELIVERY] Mesh payload delivery loop started, waiting for payloads...");
    tracing::debug!("[MESH-DELIVERY] Mesh payload delivery loop started, waiting for payloads...");
    debug!("Mesh payload delivery loop started");

    while let Some((packed_message, sender_routing_id)) = payload_rx.recv().await {
        tracing::info!("[MESH-DELIVERY] Received payload: len={}, sender={}, preview={}...",
            packed_message.len(), sender_routing_id, &packed_message[..packed_message.len().min(80)]);
        tracing::debug!("[MESH-DELIVERY] Received payload for agent delivery, len={}, sender={}",
            packed_message.len(), sender_routing_id);
        tracing::debug!("[MESH-DELIVERY] Payload preview: {}...", &packed_message[..packed_message.len().min(100)]);

        // Intercept relay-forward/relay-response messages (raw mesh payloads, not DIDComm)
        if packed_message.contains("\"type\":\"relay-forward\"") {
            tracing::info!("[MESH-DELIVERY] 📡 Intercepted relay-forward! Spawning HTTP forward task...");
            tracing::debug!("[MESH-DELIVERY] Intercepted relay-forward — handling locally");
            let agent_clone = agent.clone();
            let sender = sender_routing_id.clone();
            tokio::spawn(async move {
                handle_relay_forward(&agent_clone, &packed_message, &sender).await;
            });
            continue;
        }
        if packed_message.contains("\"type\":\"relay-response\"") {
            tracing::info!("[MESH-DELIVERY] 📡 Intercepted relay-response! Processing...");
            tracing::debug!("[MESH-DELIVERY] Intercepted relay-response — dispatching");
            handle_relay_response(&agent, &packed_message).await;
            continue;
        }

        // Unwrap {"jwe":"..."} envelope if present — mesh payloads may wrap the JWE
        let actual_message = if packed_message.starts_with("{\"jwe\":") {
            match serde_json::from_str::<serde_json::Value>(&packed_message) {
                Ok(wrapper) => {
                    if let Some(jwe_str) = wrapper.get("jwe").and_then(|v| v.as_str()) {
                        tracing::info!("[MESH-DELIVERY] Unwrapped {{\"jwe\":\"...\"}} envelope, inner len={}", jwe_str.len());
                        jwe_str.to_string()
                    } else {
                        tracing::info!("[MESH-DELIVERY] {{\"jwe\":...}} but value is not a string, using as-is");
                        packed_message
                    }
                }
                Err(_) => packed_message,
            }
        } else {
            packed_message
        };

        let metadata = didcomm::transports::TransportMetadata {
            transport_type: "mesh".to_string(),
            sender_endpoint: Some(format!("mesh://{}", sender_routing_id)),
            received_at: chrono::Utc::now(),
        };

        tracing::info!("[MESH-DELIVERY] Calling agent.receive_message (len={})...", actual_message.len());
        match agent.receive_message(actual_message, metadata).await {
            Ok(_) => {
                tracing::info!("[MESH-DELIVERY] ✅ Message delivered to agent successfully");
                tracing::debug!("[MESH-DELIVERY] Message delivered to agent successfully");
            }
            Err(e) => {
                tracing::info!("[MESH-DELIVERY] ❌ Agent rejected message: {}", e);
                tracing::debug!("[MESH-DELIVERY] Agent rejected message: {}", e);
                warn!("Mesh inbound delivery error: {}", e);
            }
        }
    }

    tracing::debug!("[MESH-DELIVERY] Mesh payload delivery loop stopped!");
    debug!("Mesh payload delivery loop stopped");
}

// =============================================================================
// Mesh Relay: Forward opaque JWE for offline peers
// =============================================================================

/// Handle an incoming relay-forward request from an offline peer.
/// Try to forward the JWE to the target URL via HTTP.
/// If successful, send relay-response back to the originator via mesh.
/// If offline, the mesh's TTL-based flooding already relays the original packet further.
async fn handle_relay_forward(agent: &crate::Agent, payload: &str, sender_routing_id: &str) {
    tracing::info!("[MESH-RELAY] handle_relay_forward called, payload_len={}, sender={}", payload.len(), sender_routing_id);

    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!("[MESH-RELAY] ❌ Failed to parse relay-forward: {}", e);
            tracing::debug!("[MESH-RELAY] Failed to parse relay-forward: {}", e);
            return;
        }
    };

    let target = parsed["target"].as_str().unwrap_or("");
    let jwe = parsed["jwe"].as_str().unwrap_or("");
    let request_id = parsed["request_id"].as_str().unwrap_or("");

    if target.is_empty() || jwe.is_empty() {
        tracing::info!("[MESH-RELAY] ❌ relay-forward missing target or jwe (target={}, jwe_len={})", target, jwe.len());
        tracing::debug!("[MESH-RELAY] relay-forward missing target or jwe");
        return;
    }

    tracing::info!("[MESH-RELAY] Forwarding JWE ({} bytes) to {} (request_id={})", jwe.len(), target, request_id);
    tracing::debug!("[MESH-RELAY] Forwarding JWE to {} (request_id={})", target, request_id);

    // Try HTTP POST to the target (CBDC server)
    let http = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("[MESH-RELAY] HTTP client error: {}", e);
            return;
        }
    };

    match http.post(target)
        .header("Content-Type", "application/didcomm-encrypted+json")
        .body(jwe.to_string())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::info!("[MESH-RELAY] ✅ Server responded HTTP {}, body_len={}", status, body.len());
            tracing::debug!("[MESH-RELAY] Server responded (HTTP {}), sending relay-response back", status);

            // Build relay-response and send back to originator via mesh
            let response_payload = serde_json::json!({
                "type": "relay-response",
                "request_id": request_id,
                "success": status.is_success(),
                "response": body,
            });

            if let Some(ref mesh) = agent.mesh {
                // Send directed to originator's routing ID (NOT a DID — use raw routing ID)
                match mesh.send_to_routing_id(sender_routing_id, response_payload.to_string()).await {
                    Ok(packet_id) => {
                        tracing::info!("[MESH-RELAY] ✅ Relay-response sent to {} (packet_id={})", sender_routing_id, packet_id);
                        tracing::debug!("[MESH-RELAY] Relay-response sent to {}", sender_routing_id);
                    }
                    Err(e) => {
                        tracing::info!("[MESH-RELAY] ❌ Failed to send relay-response to {}: {}", sender_routing_id, e);
                        tracing::debug!("[MESH-RELAY] Failed to send relay-response: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            tracing::info!("[MESH-RELAY] ❌ HTTP forward failed: {} (this device also offline?)", e);
            tracing::debug!("[MESH-RELAY] HTTP forward failed (also offline?): {}", e);
            // Don't send error back — the mesh's TTL flooding will relay the original
            // relay-forward to other peers who might be online
        }
    }
}

/// Handle an incoming relay-response from a relay peer.
/// Decrypts the server's JWE response and publishes a completion event.
async fn handle_relay_response(agent: &crate::Agent, payload: &str) {
    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("[MESH-RELAY] Failed to parse relay-response: {}", e);
            return;
        }
    };

    let request_id = parsed["request_id"].as_str().unwrap_or("").to_string();
    let relay_success = parsed["success"].as_bool().unwrap_or(false);
    let response_jwe = parsed["response"].as_str().unwrap_or("");

    tracing::debug!("[MESH-RELAY] Relay-response received: request_id={}, success={}, len={}",
        request_id, relay_success, response_jwe.len());

    if relay_success && !response_jwe.is_empty() {
        // Decrypt the server's JWE response (we have the private key)
        match agent.decrypt_only(response_jwe).await {
            Ok(decrypted) => {
                let msg: serde_json::Value = serde_json::from_str(&decrypted)
                    .unwrap_or_else(|e| {
                        tracing::warn!(
                            "[MESH-RELAY] Failed to parse decrypted server response as JSON (request_id={}): {} — treating as empty",
                            request_id,
                            e
                        );
                        serde_json::Value::Null
                    });
                let body = msg.get("body").cloned().unwrap_or(msg);

                tracing::debug!("[MESH-RELAY] Decrypted server response for request_id={}", request_id);

                // Publish mesh_redeem_complete event → Dart EventService picks it up.
                let payload = MeshRedeemCompletePayload {
                    request_id: request_id.to_string(),
                    success: body["success"].as_bool().unwrap_or(false),
                    transaction_ref: body
                        .get("transactionRef")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    amount_credited: body
                        .get("amountCredited")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    token_symbol: body
                        .get("tokenSymbol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("eINR")
                        .to_string(),
                    receipt_signature: body
                        .get("receiptSignature")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                };
                let meta = agent_events::EventMetadata::for_tenant(relay_events::TOPIC);
                let _ = agent.events.emit(&meta, payload).await;
            }
            Err(e) => {
                tracing::debug!("[MESH-RELAY] Failed to decrypt relay response: {}", e);
                let payload = MeshRedeemFailedPayload {
                    request_id: request_id.to_string(),
                    error: format!("Decrypt failed: {}", e),
                };
                let meta = agent_events::EventMetadata::for_tenant(relay_events::TOPIC);
                let _ = agent.events.emit(&meta, payload).await;
            }
        }
    } else {
        let error = parsed["error"].as_str().unwrap_or("Relay failed");
        tracing::debug!("[MESH-RELAY] Relay failed for request_id={}: {}", request_id, error);
        let payload = MeshRedeemFailedPayload {
            request_id: request_id.to_string(),
            error: error.to_string(),
        };
        let meta = agent_events::EventMetadata::for_tenant(relay_events::TOPIC);
        let _ = agent.events.emit(&meta, payload).await;
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm::transports::OutboundTransport;

    #[test]
    fn test_mesh_outbound_supports_endpoint() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let handler = Arc::new(MeshMessageHandler::new(
            "did:ajna:test".to_string(),
            signing_key,
            protocol_mesh::MeshConfig::default(),
        ));
        let transport = MeshOutboundTransport::new(handler);

        assert!(transport.supports_endpoint("mesh://0102030405060708"));
        assert!(transport.supports_endpoint("mesh://abcdef1234567890"));
        assert!(!transport.supports_endpoint("http://example.com"));
        assert!(!transport.supports_endpoint("https://example.com"));
        assert!(!transport.supports_endpoint("ws://example.com"));
        assert!(!transport.supports_endpoint("channel://test"));
    }

    #[test]
    fn test_parse_mesh_endpoint_valid() {
        let routing_id = parse_mesh_endpoint("mesh://0102030405060708").unwrap();
        assert_eq!(routing_id.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_parse_mesh_endpoint_invalid_scheme() {
        assert!(parse_mesh_endpoint("http://0102030405060708").is_err());
    }

    #[test]
    fn test_parse_mesh_endpoint_empty_routing_id() {
        assert!(parse_mesh_endpoint("mesh://").is_err());
    }

    #[test]
    fn test_parse_mesh_endpoint_invalid_hex() {
        assert!(parse_mesh_endpoint("mesh://not-valid-hex").is_err());
    }

    #[test]
    fn test_parse_mesh_endpoint_roundtrip() {
        let original = RoutingID::from_bytes(&[0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a]);
        let endpoint = format!("mesh://{}", original.to_hex());
        let parsed = parse_mesh_endpoint(&endpoint).unwrap();
        assert_eq!(original, parsed);
    }

    #[tokio::test]
    async fn test_payload_channel_carries_sender_routing_id() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(8);

        let routing_id_hex = "abcdef0123456789";
        let payload = r#"{"protected":"eyJ0eXAiOiJKV0UifQ","iv":"abc","ciphertext":"xyz","tag":"123"}"#;

        tx.send((payload.to_string(), routing_id_hex.to_string()))
            .await
            .unwrap();

        let (received_payload, received_rid) = rx.recv().await.unwrap();
        assert_eq!(received_payload, payload);
        assert_eq!(received_rid, routing_id_hex);
    }

    #[test]
    fn test_mesh_metadata_sender_endpoint_format() {
        // Verify the mesh:// endpoint format matches what MeshOutboundTransport expects
        let sender_routing_id = "abcdef0123456789";
        let endpoint = format!("mesh://{}", sender_routing_id);

        assert_eq!(endpoint, "mesh://abcdef0123456789");
        assert!(endpoint.starts_with("mesh://"));

        // The endpoint should be parseable back to a RoutingID
        let parsed = parse_mesh_endpoint(&endpoint).unwrap();
        let expected = RoutingID::from_hex(sender_routing_id).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_mesh_sender_endpoint_not_oob() {
        // mesh:// endpoints should NOT be detected as OOB URLs
        assert!(!is_oob_url("mesh://abcdef0123456789"));
    }

    #[test]
    fn test_mesh_return_route_gate() {
        // Verify the mesh:// prefix check that gates the return-route path
        let mesh_ep = Some("mesh://abcdef0123456789".to_string());
        let http_ep = Some("https://mediator.ajna.dev".to_string());
        let no_ep: Option<String> = None;

        // Only mesh:// should trigger the return-route
        assert!(mesh_ep.as_ref().map_or(false, |ep| ep.starts_with("mesh://")));
        assert!(!http_ep.as_ref().map_or(false, |ep| ep.starts_with("mesh://")));
        assert!(!no_ep.as_ref().map_or(false, |ep| ep.starts_with("mesh://")));
    }

    #[tokio::test]
    async fn test_mesh_outbound_send() {
        use ed25519_dalek::SigningKey;
        use protocol_mesh::MeshTransport;
        use rand::rngs::OsRng;
        use std::sync::Mutex;

        // Create a mock transport to capture sent packets
        struct MockTransport {
            our_id: RoutingID,
            sent: Mutex<Vec<protocol_mesh::MeshPacket>>,
        }

        #[async_trait]
        impl MeshTransport for MockTransport {
            async fn broadcast(
                &self,
                packet: &protocol_mesh::MeshPacket,
            ) -> protocol_mesh::MeshResult<()> {
                self.sent.lock().unwrap().push(packet.clone());
                Ok(())
            }
            async fn send_to(
                &self,
                _neighbor: &RoutingID,
                packet: &protocol_mesh::MeshPacket,
            ) -> protocol_mesh::MeshResult<()> {
                self.sent.lock().unwrap().push(packet.clone());
                Ok(())
            }
            async fn get_neighbors(&self) -> Vec<RoutingID> {
                vec![]
            }
            fn our_routing_id(&self) -> RoutingID {
                self.our_id
            }
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let handler = Arc::new(MeshMessageHandler::new(
            "did:ajna:test".to_string(),
            signing_key,
            protocol_mesh::MeshConfig::default(),
        ));

        let mock_transport = Arc::new(MockTransport {
            our_id: handler.our_routing_id(),
            sent: Mutex::new(vec![]),
        });
        handler.set_transport(mock_transport.clone()).await;

        let outbound = MeshOutboundTransport::new(handler);

        let dest = RoutingID::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let endpoint = format!("mesh://{}", dest.to_hex());
        let result = outbound.send(&endpoint, "test-packed-message").await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some()); // Should return packet ID

        // Verify the mock transport received the packet
        let sent = mock_transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, "test-packed-message");
    }
}
