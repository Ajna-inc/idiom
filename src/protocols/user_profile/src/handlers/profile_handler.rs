use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use didcomm::messaging::{InboundMessage, MessageHandler, MessageHandlerError, OutboundMessage};
use protocol_connections::ConnectionRepositoryTrait;

use crate::messages::{ProfileMessage, PROFILE_MESSAGE_TYPE};
use crate::services::UserProfileService;

#[cfg(feature = "events")]
use agent_events::event_bus::EventBus;

pub struct ProfileHandler {
    service: Arc<UserProfileService>,

    /// Optional connection repo used to resolve the sender's `did:key` /
    /// `did:peer` to the local connection UUID. When `inbound.context.connection_id`
    /// is `None` (the dispatcher leaves it unset; see
    /// `didcomm::messaging::services::dispatcher::process_inbound`), without this
    /// the handler falls back to `inbound.context.from` (the JWE signing key),
    /// causing the peer profile to be stored under `peer:did:key:z6Mk...`
    /// instead of `peer:<uuid>`. Callers reading by connection UUID then see
    /// an empty profile even though the picture is on disk.
    connection_repository: Option<Arc<dyn ConnectionRepositoryTrait>>,

    #[cfg(feature = "events")]
    event_bus: Arc<EventBus>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl ProfileHandler {
    #[cfg(not(feature = "events"))]
    pub fn new(
        service: Arc<UserProfileService>,
        connection_repository: Option<Arc<dyn ConnectionRepositoryTrait>>,
    ) -> Self {
        Self {
            service,
            connection_repository,
        }
    }

    #[cfg(feature = "events")]
    pub fn new(
        service: Arc<UserProfileService>,
        connection_repository: Option<Arc<dyn ConnectionRepositoryTrait>>,
        event_bus: Arc<EventBus>,
        agent_id: String,
    ) -> Self {
        Self {
            service,
            connection_repository,
            event_bus,
            agent_id,
        }
    }

    /// Resolve the sender's DID (`did:key:z6Mk...` from the JWE `kid`, or
    /// `did:peer:...` from a connection-initiated message) to a local
    /// connection UUID. Mirrors `protocol_browser_sync::BrowserSyncService::
    /// resolve_connection_id_for_did` — direct `their_did` index → did:key
    /// fallback via inline `did:peer:2.Vz6Mku...` substring or raw verkey
    /// stored on `their_authentication_key_base58`.
    async fn resolve_connection_id(&self, their_did: &str) -> Option<String> {
        let repo = self.connection_repository.as_ref()?;

        if let Ok(conns) = repo.find_by_their_did(their_did).await {
            if let Some(c) = conns.first() {
                return Some(c.id.clone());
            }
        }

        if let Some(key_suffix) = their_did.strip_prefix("did:key:") {
            let verkey_base58 = decode_did_key_to_verkey_base58(their_did);

            if let Ok(all) = repo.get_all().await {
                let matched = all.into_iter().find(|c| {
                    if let Some(td) = c.their_did.as_deref() {
                        if td.contains(key_suffix) {
                            return true;
                        }
                    }
                    if let Some(vk) = verkey_base58.as_deref() {
                        if c.their_authentication_key_base58.as_deref() == Some(vk) {
                            return true;
                        }
                    }
                    false
                });
                if let Some(c) = matched {
                    return Some(c.id);
                }
            }
        }

        None
    }

    #[cfg(feature = "events")]
    async fn emit_received(
        &self,
        connection_id: &str,
        send_back_yours: bool,
        profile: &serde_json::Value,
    ) {
        let payload = crate::events::ProfileReceivedPayload {
            connection_id: connection_id.to_string(),
            send_back_yours,
            profile: profile.clone(),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
        if let Err(e) = self.event_bus.emit(&meta, payload).await {
            tracing::debug!("Failed to publish profile.received event: {}", e);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl MessageHandler for ProfileHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![PROFILE_MESSAGE_TYPE.to_string()]
    }

    async fn handle(
        &self,
        inbound: InboundMessage,
    ) -> didcomm::messaging::Result<Option<OutboundMessage>> {
        let profile_msg: ProfileMessage = serde_json::from_value(inbound.message.body.clone())
            .map_err(|e| {
                MessageHandlerError::InvalidMessage(format!(
                    "Failed to parse ProfileMessage: {}",
                    e
                ))
            })?;

        // Prefer the UUID set by upstream resolvers. If absent, try to look
        // it up from `from` (the JWE sender's `did:key`); only fall back to
        // the raw `from` string if no connection record matches — that path
        // hides the profile under `peer:did:key:...` and breaks UUID-keyed
        // readers (e.g. the Mac side panel) even though the picture is
        // safely persisted.
        let mut connection_id = inbound.context.connection_id.clone();
        if connection_id.is_none() {
            if let Some(from) = inbound.context.from.as_deref() {
                if let Some(resolved) = self.resolve_connection_id(from).await {
                    debug!(
                        from = from,
                        resolved = %resolved,
                        "Resolved sender DID to connection UUID for profile storage"
                    );
                    connection_id = Some(resolved);
                }
            }
        }
        if connection_id.is_none() {
            connection_id = inbound.context.from.clone();
            if let Some(ref cid) = connection_id {
                warn!(
                    fallback_key = %cid,
                    "No connection matched sender DID; storing profile under raw \
                     sender DID. UUID-keyed readers will not see this record."
                );
            }
        }

        let conn_id = connection_id.as_deref().unwrap_or("unknown");

        info!(
            connection_id = conn_id,
            display_name = ?profile_msg.profile.display_name,
            send_back_yours = profile_msg.send_back_yours,
            "Received user profile"
        );

        // Save peer profile (resolves attachments, merges with existing)
        match self.service.save_peer_profile(conn_id, &profile_msg).await {
            Ok(_record) => {
                #[cfg(feature = "events")]
                {
                    let profile_value = serde_json::to_value(&profile_msg.profile)
                        .unwrap_or(serde_json::Value::Null);
                    self.emit_received(conn_id, profile_msg.send_back_yours, &profile_value)
                        .await;
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to save peer profile");
            }
        }

        // If send_back_yours, reply with our own profile
        if profile_msg.send_back_yours {
            if let Ok(Some(own_record)) = self.service.get_own_profile().await {
                let reply = UserProfileService::build_profile_message(&own_record, None);
                let didcomm_msg = profile_message_to_didcomm(&reply).map_err(|e| {
                    MessageHandlerError::ProcessingFailed(format!(
                        "Failed to build DIDComm message: {}",
                        e
                    ))
                })?;

                debug!("Sending own profile back (send_back_yours)");
                return Ok(Some(OutboundMessage {
                    message: didcomm_msg,
                    to: inbound.context.from.clone().unwrap_or_default(),
                    from: inbound.context.to.clone().unwrap_or_default(),
                    connection_id: inbound.context.connection_id.clone(),
                }));
            }
        }

        Ok(None)
    }
}

/// Convert a v1-shaped `ProfileMessage` into a `didcomm::core::Message` whose
/// `body` is the FULL v1 wire form (`{@type, @id, profile, send_back_yours, ~attach}`).
///
/// Body must contain `@type`/`@id` because the agent's response packing path
/// (`processor::pack_response`) treats `outbound.message.body` as a complete
/// v1 message during the V1 packing path — see protocol_connections's
/// `request_handler.rs:1027-1034` which uses the same convention. Without
/// `@type` in the body, Alice's unpack reveals only `{profile, send_back_yours}`
/// and the message router fails with "Message missing @type or type field".
pub(crate) fn profile_message_to_didcomm(
    msg: &ProfileMessage,
) -> Result<didcomm::core::Message, String> {
    let body = serde_json::to_value(msg)
        .map_err(|e| format!("Failed to serialize ProfileMessage: {}", e))?;
    Ok(didcomm::core::Message::new(
        msg.id.clone(),
        msg.msg_type.clone(),
        body,
    ))
}

/// Decode `did:key:z<multibase>` to the raw Ed25519 verkey in base58btc —
/// the same shape stored in `ConnectionRecord.their_authentication_key_base58`.
/// Multicodec prefix for Ed25519 public keys is `0xed 0x01`.
fn decode_did_key_to_verkey_base58(did: &str) -> Option<String> {
    let encoded = did.strip_prefix("did:key:z")?;
    let decoded = bs58::decode(encoded).into_vec().ok()?;
    if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return None;
    }
    Some(bs58::encode(&decoded[2..]).into_string())
}
