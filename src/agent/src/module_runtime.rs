//! Runtime glue between the agent and the pluggable [`agent_module`] system.
//!
//! Holds the agent-side implementation of [`agent_module::OutboundSender`],
//! backed by the canonical [`crate::messaging::DidCommSender`]. Modules receive
//! this as `ctx.sender` and push protocol messages over a connection by id,
//! without depending on the agent's concrete transport wiring.

use std::sync::Arc;

use async_trait::async_trait;
use protocol_connections::ConnectionRepositoryTrait;

use crate::messaging::DidCommSender;

// -----------------------------------------------------------------------------
// DI newtype wrappers.
//
// Several agent-internal cells collide by concrete type in the DI container:
// `agent_did`, `agent_key_id`, and `mediator_did_cell` are all
// `Arc<tokio::sync::RwLock<Option<String>>>`, and the three mediation cells are
// distinct `std::sync::RwLock` shapes. The container keys providers by
// `TypeId`, so registering more than one value of the same concrete type would
// clobber the earlier registration.
//
// Wrapping each in a distinct newtype gives every shared resource its own
// `TypeId`, so modules can `ctx.container.resolve::<AgentDidCell>()` (etc.)
// and get exactly the cell they expect. All wrappers are `Sized` so they can
// be registered and resolved directly (the container downcasts `Arc<T>`).
// -----------------------------------------------------------------------------

/// The agent's own DID cell (`agent_did`), shared with self-wiring handlers.
#[derive(Clone)]
pub struct AgentDidCell(pub Arc<tokio::sync::RwLock<Option<String>>>);

/// Registered mediation key (did:key) — the key registered with the mediator.
/// All connection DIDs must use this key as their recipient key so the mediator
/// can route Forward messages back to us.
#[derive(Clone)]
pub struct RegisteredMediationKey(pub Arc<std::sync::RwLock<Option<String>>>);

/// Mediation routing keys from the mediator grant. These are the only keys that
/// go into a DID document's `routingKeys`; the agent's registered key does not.
#[derive(Clone)]
pub struct MediationRoutingKeys(pub Arc<std::sync::RwLock<Option<Vec<String>>>>);

/// Keys created by connection handlers that need to be registered with the
/// mediator via keylist-update before the connection response is sent.
#[derive(Clone)]
pub struct PendingKeyRegistrations(pub Arc<std::sync::RwLock<Vec<String>>>);

/// The agent's connection repository (trait object). Wrapped so it can be
/// registered as a `Sized` type in the DI container and resolved by modules
/// that need to look connections up (the raw `Arc<dyn ..>` is `?Sized`).
#[derive(Clone)]
pub struct ConnectionRepositoryResource(pub Arc<dyn ConnectionRepositoryTrait>);

/// [`agent_module::OutboundSender`] backed by the agent's `DidCommSender`.
///
/// `send_via_connection(connection_id)` looks up the `ConnectionRecord` via the
/// connection repository and delegates to
/// [`DidCommSender::send_via_connection`], which resolves pairwise DIDs,
/// authcrypt-packs, wraps in Forward envelopes, and POSTs.
pub struct AgentOutboundSender {
    sender: Arc<DidCommSender>,
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,
}

impl AgentOutboundSender {
    pub fn new(
        sender: Arc<DidCommSender>,
        connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    ) -> Self {
        Self {
            sender,
            connection_repository,
        }
    }
}

#[async_trait]
impl agent_module::OutboundSender for AgentOutboundSender {
    async fn send_via_connection(
        &self,
        connection_id: &str,
        message: &serde_json::Value,
    ) -> Result<(), String> {
        let connection = self
            .connection_repository
            .find_by_id(connection_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("connection {connection_id} not found"))?;

        self.sender
            .send_via_connection(&connection, message)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
