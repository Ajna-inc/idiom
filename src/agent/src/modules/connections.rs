//! Connections Module
//!
//! High-level API for the DID Exchange protocol, providing ergonomic methods
//! to manage connections.

use crate::error::{AgentError, Result};
use protocol_connections::{
    ConnectionRecord, ConnectionRepositoryTrait, ConnectionService, DidExchangeState,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, timeout};

/// Connections Module providing high-level protocol APIs.
///
/// Holds its `ConnectionService` behind an `RwLock<Arc<..>>` so that when the
/// module is composed via the builder (config-only `default()`), its
/// [`AgentModule::register`] can swap in the agent's fully-configured service
/// (event bus + notify) resolved from the DI container. All accessors read
/// through [`ConnectionsModule::service`].
pub struct ConnectionsModule {
    service: std::sync::RwLock<Arc<ConnectionService>>,
}

impl Clone for ConnectionsModule {
    fn clone(&self) -> Self {
        Self {
            service: std::sync::RwLock::new(self.service()),
        }
    }
}

impl Default for ConnectionsModule {
    /// Config-only constructor for consumers assembling an agent through the
    /// pluggable path (`AgentBuilder::with_module(ConnectionsModule::default())`).
    ///
    /// Builds a throwaway in-memory-backed service so the module is usable
    /// stand-alone; when driven by the agent, [`AgentModule::register`] resolves
    /// the agent's fully-configured `ConnectionService` (event bus + notify)
    /// from the DI container and swaps it in for all APIs + the DIDExchange
    /// handlers.
    fn default() -> Self {
        let repository: Arc<dyn ConnectionRepositoryTrait> =
            Arc::new(protocol_connections::ConnectionRepository::new());
        Self {
            service: std::sync::RwLock::new(Arc::new(ConnectionService::new(repository))),
        }
    }
}

impl ConnectionsModule {
    /// Create a new ConnectionsModule
    pub fn new(repository: Arc<dyn ConnectionRepositoryTrait>) -> Self {
        let service = Arc::new(ConnectionService::new(repository));
        Self {
            service: std::sync::RwLock::new(service),
        }
    }

    /// Create a new ConnectionsModule with a pre-configured service
    ///
    /// This is useful when you want to configure the service with additional
    /// dependencies like an event bus before creating the module.
    pub fn new_with_service(service: Arc<ConnectionService>) -> Self {
        Self {
            service: std::sync::RwLock::new(service),
        }
    }

    /// Get a connection record by ID
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    pub async fn get_by_id(&self, connection_id: &str) -> Result<Option<ConnectionRecord>> {
        Ok(self.service().get_by_id(connection_id).await?)
    }

    /// Alias for get_by_id (for API compatibility)
    pub async fn find_by_id(&self, connection_id: &str) -> Result<Option<ConnectionRecord>> {
        self.get_by_id(connection_id).await
    }

    /// Get all connections
    pub async fn get_all(&self) -> Result<Vec<ConnectionRecord>> {
        Ok(self.service().get_all().await?)
    }

    /// Get a connection record by thread ID
    ///
    /// # Arguments
    /// * `thread_id` - The protocol thread ID
    pub async fn get_by_thread_id(&self, thread_id: &str) -> Result<Option<ConnectionRecord>> {
        Ok(self.service().get_by_thread_id(thread_id).await?)
    }

    /// Get all completed connections
    pub async fn get_all_completed(&self) -> Result<Vec<ConnectionRecord>> {
        Ok(self.service().get_all_completed().await?)
    }

    /// Persist an updated connection record (labels, metadata, …). Fetch with
    /// `get_by_id`, mutate the record, then call this to save.
    pub async fn update(&self, record: &ConnectionRecord) -> Result<()> {
        Ok(self.service().update(record).await?)
    }

    /// Wait for a connection to reach the Completed state
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    /// * `timeout_ms` - Optional timeout in milliseconds (default: 15000ms)
    ///
    /// # Returns
    /// The connection record in Completed state
    ///
    /// # Errors
    /// Returns AgentError::Connections if timeout is reached or connection not found
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    ///
    /// # async fn example(agent: Agent, connection_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    /// let connection = agent.connections()
    ///     .return_when_is_connected(connection_id, None)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn return_when_is_connected(
        &self,
        connection_id: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ConnectionRecord> {
        let timeout_duration = Duration::from_millis(timeout_ms.unwrap_or(15000));

        // Use timeout to limit the wait time
        timeout(timeout_duration, async {
            let mut check_interval = interval(Duration::from_millis(100));

            loop {
                check_interval.tick().await;

                match self.service().get_by_id(connection_id).await {
                    Ok(Some(record)) => {
                        if record.state == DidExchangeState::Completed {
                            return Ok(record);
                        }
                    }
                    Ok(None) => {
                        return Err(AgentError::Connections(format!(
                            "Connection not found: {}",
                            connection_id
                        )))
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await
        .map_err(|_| {
            AgentError::Connections(format!(
                "Timeout waiting for connection {} to complete",
                connection_id
            ))
        })?
    }

    /// Wait for a connection with the given thread ID to reach the Completed state
    ///
    /// # Arguments
    /// * `thread_id` - The protocol thread ID
    /// * `timeout_ms` - Optional timeout in milliseconds (default: 15000ms)
    ///
    /// # Returns
    /// The connection record in Completed state
    pub async fn return_when_is_connected_by_thread_id(
        &self,
        thread_id: &str,
        timeout_ms: Option<u64>,
    ) -> Result<ConnectionRecord> {
        let timeout_duration = Duration::from_millis(timeout_ms.unwrap_or(15000));

        timeout(timeout_duration, async {
            let mut check_interval = interval(Duration::from_millis(100));

            loop {
                check_interval.tick().await;

                match self.service().get_by_thread_id(thread_id).await {
                    Ok(Some(record)) => {
                        if record.state == DidExchangeState::Completed {
                            return Ok(record);
                        }
                    }
                    Ok(None) => {
                        // Connection might not exist yet, keep waiting
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await
        .map_err(|_| {
            AgentError::Connections(format!(
                "Timeout waiting for connection with thread_id {} to complete",
                thread_id
            ))
        })?
    }

    /// Delete a connection record
    pub async fn delete(&self, connection_id: &str) -> Result<()> {
        Ok(self.service().delete(connection_id).await?)
    }

    /// Check if a connection exists and is in Completed state
    pub async fn is_connected(&self, connection_id: &str) -> Result<bool> {
        match self.service().get_by_id(connection_id).await? {
            Some(record) => Ok(record.state == DidExchangeState::Completed),
            None => Ok(false),
        }
    }

    /// Accept an out-of-band invitation and create a connection
    ///
    /// # Arguments
    /// * `oob_record` - The out-of-band invitation record
    /// * `our_did` - Our DID to use for this connection
    /// * `our_label` - Optional label to identify ourselves
    ///
    /// # Returns
    /// A tuple of (ConnectionRecord, DidExchangeRequestMessage) that needs to be sent
    ///
    /// # Note
    /// This method creates the connection record and request message, but does NOT send the message.
    /// The caller must send the request message via the transport layer.
    pub async fn accept_out_of_band_invitation(
        &self,
        oob_record: &protocol_oob::OutOfBandRecord,
        our_did: String,
        our_label: Option<String>,
    ) -> Result<(
        ConnectionRecord,
        protocol_connections::DidExchangeRequestMessage,
    )> {
        // Use the connection service to create the request
        let (connection_record, request_message) = self
            .service()
            .create_request(oob_record, our_did, our_label)
            .await?;

        Ok((connection_record, request_message))
    }

    /// Set metadata for a connection
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    /// * `metadata` - JSON metadata to store
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    /// use serde_json::json;
    ///
    /// # async fn example(agent: Agent, connection_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    /// agent.connections().set_connection_metadata(
    ///     connection_id,
    ///     json!({
    ///         "last_plc_height": 12345,
    ///         "peer_capabilities": ["plc", "mesh", "validator"]
    ///     })
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_connection_metadata(
        &self,
        connection_id: &str,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let mut connection = self
            .service()
            .get_by_id(connection_id)
            .await?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        connection.set_metadata(metadata);

        self.service().update(&connection).await?;

        Ok(())
    }

    /// Update metadata for a connection (merges with existing)
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    /// * `metadata` - JSON metadata to merge
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    /// use serde_json::json;
    ///
    /// # async fn example(agent: Agent, connection_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    /// // Update just the PLC height, keeping other metadata
    /// agent.connections().update_connection_metadata(
    ///     connection_id,
    ///     json!({"last_plc_height": 12350})
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update_connection_metadata(
        &self,
        connection_id: &str,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let mut connection = self
            .service()
            .get_by_id(connection_id)
            .await?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        connection.update_metadata(metadata);

        self.service().update(&connection).await?;

        Ok(())
    }

    /// Get metadata for a connection
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    ///
    /// # Returns
    /// Optional JSON metadata
    pub async fn get_connection_metadata(
        &self,
        connection_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let connection = self
            .service()
            .get_by_id(connection_id)
            .await?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        Ok(connection.get_metadata().cloned())
    }

    /// Clear metadata for a connection
    ///
    /// # Arguments
    /// * `connection_id` - The connection record ID
    pub async fn clear_connection_metadata(&self, connection_id: &str) -> Result<()> {
        let mut connection = self
            .service()
            .get_by_id(connection_id)
            .await?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        connection.clear_metadata();

        self.service().update(&connection).await?;

        Ok(())
    }

    /// Query connections by metadata predicate
    ///
    /// # Arguments
    /// * `predicate` - Function to filter connections by metadata
    ///
    /// # Example
    /// ```rust,no_run
    /// use agent::Agent;
    ///
    /// # async fn example(agent: Agent) -> Result<(), Box<dyn std::error::Error>> {
    /// // Find all validator connections
    /// let validators = agent.connections().query_by_metadata(|metadata| {
    ///     metadata.get("peer_capabilities")
    ///         .and_then(|v| v.as_array())
    ///         .map(|caps| caps.iter().any(|c| c == "validator"))
    ///         .unwrap_or(false)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_by_metadata<F>(&self, predicate: F) -> Result<Vec<ConnectionRecord>>
    where
        F: Fn(&serde_json::Value) -> bool,
    {
        let all_connections = self.service().get_all().await?;

        Ok(all_connections
            .into_iter()
            .filter(|conn| conn.get_metadata().map(&predicate).unwrap_or(false))
            .collect())
    }

    /// Get internal service (for advanced use cases). Reads through the
    /// `RwLock`, returning the currently-active service (the agent's
    /// fully-configured one once `register` has swapped it in).
    pub fn service(&self) -> Arc<ConnectionService> {
        self.service.read().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for ConnectionsModule {
    fn name(&self) -> &str {
        "connections"
    }

    /// Higher priority so the DIDExchange handlers register ahead of protocol
    /// modules that build on connections.
    fn priority(&self) -> i32 {
        100
    }

    /// Self-wire the DIDExchange request/response/complete handlers.
    ///
    /// The request handler needs several agent-private inputs. Instead of
    /// widening the shared [`agent_module::ModuleContext`] with agent internals,
    /// the agent registers those resources into the DI container (behind newtype
    /// wrappers in [`crate::module_runtime`]) and this module resolves them here:
    /// `oob_repository`, `did_repository`, `wallet` (`ctx.wallet`),
    /// `auto_accept_connections` (`ctx.context.config()`), the agent DID cell,
    /// and the shared mediation-key / routing-key / pending-registration cells.
    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        use crate::module_runtime::{
            AgentDidCell, MediationRoutingKeys, PendingKeyRegistrations, RegisteredMediationKey,
        };

        let oob_repository = ctx
            .container
            .resolve::<protocol_oob::OutOfBandRepository>()
            .map_err(|e| format!("connections: resolve oob_repository: {e}"))?;
        let did_repository = ctx
            .container
            .resolve::<did::core::DidRepository>()
            .map_err(|e| format!("connections: resolve did_repository: {e}"))?;
        let agent_did_cell = ctx
            .container
            .resolve::<AgentDidCell>()
            .map_err(|e| format!("connections: resolve agent_did_cell: {e}"))?;
        let registered_mediation_key = ctx
            .container
            .resolve::<RegisteredMediationKey>()
            .map_err(|e| format!("connections: resolve registered_mediation_key: {e}"))?;
        let mediation_routing_keys = ctx
            .container
            .resolve::<MediationRoutingKeys>()
            .map_err(|e| format!("connections: resolve mediation_routing_keys: {e}"))?;
        let pending_key_registrations = ctx
            .container
            .resolve::<PendingKeyRegistrations>()
            .map_err(|e| format!("connections: resolve pending_key_registrations: {e}"))?;

        let auto_accept_connections = ctx.context.config().auto_accept_connections;

        // Prefer the agent's fully-configured ConnectionService (event bus +
        // notify) from the container; fall back to the module's own service for
        // stand-alone use. Swap it in so ALL module APIs (`find_by_id`, …) and
        // the DIDExchange handlers use the same event-bus-wired service.
        let service = ctx
            .container
            .try_resolve::<ConnectionService>()
            .unwrap_or_else(|| self.service());
        *self.service.write().unwrap() = service.clone();

        // Agent DID is created before the module loop runs, so the cell is
        // populated by now; fall back to empty string (mirrors prior behavior
        // when auto_create_did=false).
        let our_did = agent_did_cell.0.read().await.clone().unwrap_or_default();

        let request_handler = Arc::new(protocol_connections::DidExchangeRequestHandler::new(
            service.clone(),
            oob_repository,
            did_repository.clone(),
            ctx.wallet.clone(),
            auto_accept_connections,
            our_did,
            registered_mediation_key.0.clone(),
            mediation_routing_keys.0.clone(),
            pending_key_registrations.0.clone(),
        ));

        let response_handler = Arc::new(protocol_connections::DidExchangeResponseHandler::new(
            service.clone(),
            did_repository,
            auto_accept_connections,
        ));

        let complete_handler = Arc::new(protocol_connections::DidExchangeCompleteHandler::new(
            service.clone(),
        ));

        let mut registry = ctx.handler_registry.write().await;
        registry.register(request_handler);
        registry.register(response_handler);
        registry.register(complete_handler);
        tracing::debug!("✓ [ConnectionsModule] DIDExchange handlers registered");
        Ok(())
    }
}

/// Typed, decoupled access to the [`ConnectionsModule`] from an [`crate::Agent`],
/// backed by the pluggable module system (`Agent::module::<ConnectionsModule>()`).
pub trait ConnectionsExt {
    fn connections_module(&self) -> Option<std::sync::Arc<ConnectionsModule>>;
}

impl ConnectionsExt for crate::Agent {
    fn connections_module(&self) -> Option<std::sync::Arc<ConnectionsModule>> {
        self.module::<ConnectionsModule>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_connections::ConnectionRepository;
    use protocol_oob::domain::OutOfBandRole;
    use protocol_oob::messages::{InlineService, OutOfBandInvitation, OutOfBandService};
    use protocol_oob::repository::OutOfBandRecord;

    fn create_test_oob_record() -> OutOfBandRecord {
        let invitation = OutOfBandInvitation::new(vec![OutOfBandService::Inline(InlineService {
            id: "#service-1".to_string(),
            service_type: "did-communication".to_string(),
            service_endpoint: "http://example.com".to_string(),
            recipient_keys: vec!["key1".to_string()],
            routing_keys: vec![],
        })])
        .with_handshake_protocols(vec!["https://didcomm.org/didexchange/1.1".to_string()]);

        OutOfBandRecord::new(invitation, OutOfBandRole::Sender)
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let repo = Arc::new(ConnectionRepository::new());
        let module = ConnectionsModule::new(repo.clone());
        let service = ConnectionService::new(repo);

        let oob_record = create_test_oob_record();

        let (record, _) = service
            .create_request(
                &oob_record,
                "did:peer:test".to_string(),
                Some("Test".to_string()),
            )
            .await
            .unwrap();

        let found = module.get_by_id(&record.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, record.id);
    }

    #[tokio::test]
    async fn test_get_by_thread_id() {
        let repo = Arc::new(ConnectionRepository::new());
        let module = ConnectionsModule::new(repo.clone());
        let service = ConnectionService::new(repo);

        let oob_record = create_test_oob_record();

        let (record, _) = service
            .create_request(
                &oob_record,
                "did:peer:test".to_string(),
                Some("Test".to_string()),
            )
            .await
            .unwrap();

        let found = module.get_by_thread_id(&record.thread_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().thread_id, record.thread_id);
    }

    #[tokio::test]
    async fn test_is_connected() {
        let repo = Arc::new(ConnectionRepository::new());
        let module = ConnectionsModule::new(repo.clone());
        let service = ConnectionService::new(repo);

        let oob_record = create_test_oob_record();

        let (record, _) = service
            .create_request(
                &oob_record,
                "did:peer:test".to_string(),
                Some("Test".to_string()),
            )
            .await
            .unwrap();

        // Not completed yet
        let is_connected = module.is_connected(&record.id).await.unwrap();
        assert!(!is_connected);
    }

    #[tokio::test]
    async fn test_return_when_is_connected_timeout() {
        let repo = Arc::new(ConnectionRepository::new());
        let module = ConnectionsModule::new(repo.clone());
        let service = ConnectionService::new(repo);

        let oob_record = create_test_oob_record();

        let (record, _) = service
            .create_request(
                &oob_record,
                "did:peer:test".to_string(),
                Some("Test".to_string()),
            )
            .await
            .unwrap();

        // Should timeout because connection never reaches Completed
        let result = module.return_when_is_connected(&record.id, Some(500)).await;

        assert!(result.is_err());
        match result {
            Err(AgentError::Connections(msg)) => {
                assert!(msg.contains("Timeout"));
            }
            _ => panic!("Expected timeout error"),
        }
    }
}
