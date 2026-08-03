//! Basic Messages Module
//!
//! High-level API for sending and receiving basic text messages.
//! HTTP delivery is delegated to the canonical
//! [`crate::messaging::DidCommSender`]; only the mesh-transport bypass
//! (override endpoint, no Forward wrapping) is handled inline.

use crate::error::{AgentError, Result};
use crate::messaging::{DidCommSender, MessageEncryption};
use crate::transport::{EncryptedMessage, TransportManager};
use protocol_basic_messages::{
    BasicMessageQuery, BasicMessageRecord, BasicMessageRepositoryTrait, BasicMessageRole,
    BasicMessageService,
};
use protocol_connections::ConnectionRepositoryTrait;
use std::sync::Arc;

/// Lazily-built basic-message service + orchestration deps, resolved from the
/// DI container in [`AgentModule::register`].
struct BasicMessagesInner {
    service: Arc<BasicMessageService>,
    repository: Arc<dyn BasicMessageRepositoryTrait>,
    connection_repository: Arc<dyn ConnectionRepositoryTrait>,
    sender: Arc<DidCommSender>,
    /// Mesh-transport bypass needs the raw transport + encryption since it
    /// skips the DID-doc endpoint and Forward wrapping that the canonical
    /// sender provides. Falls back to `sender` on mesh failure.
    transport: Arc<TransportManager>,
    message_encryption: Arc<MessageEncryption>,
}

/// Basic Messages Module
///
/// Provides high-level API for basic messaging between agents.
///
/// Config-only: holds no agent dependencies at construction. Its service +
/// orchestration dependencies are built lazily in [`AgentModule::register`]
/// (storage-backed repository from `ctx.storage`; sender / transport /
/// encryption / connection repository resolved from the DI container).
#[derive(Default)]
pub struct BasicMessagesModule {
    inner: once_cell::sync::OnceCell<BasicMessagesInner>,
}

impl BasicMessagesModule {
    /// Config-only constructor (no agent deps).
    pub fn new() -> Self {
        Self {
            inner: once_cell::sync::OnceCell::new(),
        }
    }

    /// Inner accessor. Panics if used before [`AgentModule::register`] has run.
    fn inner(&self) -> &BasicMessagesInner {
        self.inner
            .get()
            .expect("BasicMessagesModule used before register")
    }

    /// Send a basic message to a connection.
    ///
    /// If the connection has a mesh transport override, attempts mesh
    /// delivery first; on failure, falls back to the canonical DIDComm
    /// send through the mediator. Otherwise, sends straight through the
    /// canonical sender (which handles DID resolution, authcrypt, and
    /// Forward wrapping).
    pub async fn send_message(
        &self,
        connection_id: &str,
        content: String,
        parent_thread_id: Option<String>,
    ) -> Result<BasicMessageRecord> {
        let inner = self.inner();
        let conn_repo = &inner.connection_repository;
        let sender = &inner.sender;

        tracing::debug!(
            "[BASIC-SEND] Sending message to connection {}",
            connection_id
        );

        let connection = conn_repo
            .find_by_id(connection_id)
            .await
            .map_err(|e| AgentError::Connections(e.to_string()))?
            .ok_or_else(|| {
                AgentError::Connections(format!("Connection not found: {}", connection_id))
            })?;

        // Check connection metadata for mesh transport preference
        let mesh_endpoint_override = connection
            .get_metadata()
            .and_then(|m| m.get("transport"))
            .and_then(|t| {
                let preferred = t.get("preferred")?.as_str()?;
                if preferred == "mesh" {
                    t.get("selected_endpoint")?.as_str().map(|s| s.to_string())
                } else {
                    None
                }
            });

        // Create the basic message record up front
        let (message, record) = inner
            .service
            .create_message(content, &connection, parent_thread_id)
            .await
            .map_err(|e| AgentError::Module(format!("Basic message service error: {}", e)))?;

        tracing::debug!("[BASIC-SEND] Message created: {}", message.id);

        // Mesh fast path: pack JWE for the recipient, send to the override
        // endpoint directly, no Forward wrapping. Fall back to sender if mesh
        // fails.
        if let Some(mesh_ep) = mesh_endpoint_override {
            tracing::debug!("[BASIC-SEND] Trying mesh transport: {}", mesh_ep);
            let transport = &inner.transport;
            let message_encryption = &inner.message_encryption;

            let their_did = connection.their_did.as_ref().ok_or_else(|| {
                AgentError::Connections("Connection not yet completed".to_string())
            })?;

            let packed = message_encryption
                .pack_encrypted_message(&message, their_did, &connection.did)
                .await?;
            let encrypted_msg = EncryptedMessage::new(
                "jwe".to_string(),
                "jwe".to_string(),
                packed,
                "jwe".to_string(),
            );

            match transport.send_message(encrypted_msg, &mesh_ep).await {
                Ok(_) => {
                    tracing::debug!("[BASIC-SEND] Mesh send succeeded");
                    return Ok(record);
                }
                Err(e) => {
                    tracing::debug!(
                        "[BASIC-SEND] Mesh send failed ({}), falling back to mediator",
                        e
                    );
                    // Fall through to canonical sender below
                }
            }
        }

        // Canonical path: full DID resolution + Forward wrapping + transport
        sender
            .send_via_connection(&connection, &message)
            .await
            .map_err(|e| {
                tracing::debug!("[BASIC-SEND] ERROR: {}", e);
                e
            })?;

        tracing::debug!("[BASIC-SEND] Message sent successfully");
        Ok(record)
    }

    /// Get all messages for a connection
    pub async fn find_by_connection_id(
        &self,
        connection_id: &str,
    ) -> Result<Vec<BasicMessageRecord>> {
        self.inner()
            .repository
            .find_by_connection_id(connection_id)
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))
    }

    /// Get all messages across all connections (useful for testing/debugging).
    pub async fn get_all(&self) -> Result<Vec<BasicMessageRecord>> {
        self.inner()
            .repository
            .get_all()
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))
    }

    /// Get message by ID
    pub async fn get_by_id(&self, id: &str) -> Result<Option<BasicMessageRecord>> {
        self.inner()
            .repository
            .find_by_id(id)
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))
    }

    /// Find messages by query
    pub async fn find_by_query(&self, query: BasicMessageQuery) -> Result<Vec<BasicMessageRecord>> {
        self.inner()
            .repository
            .find_by_query(query)
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))
    }

    /// Get sent messages for a connection
    pub async fn find_sent_messages(&self, connection_id: &str) -> Result<Vec<BasicMessageRecord>> {
        let query = BasicMessageQuery {
            connection_id: Some(connection_id.to_string()),
            role: Some(BasicMessageRole::Sender),
            ..Default::default()
        };
        self.find_by_query(query).await
    }

    /// Get received messages for a connection
    pub async fn find_received_messages(
        &self,
        connection_id: &str,
    ) -> Result<Vec<BasicMessageRecord>> {
        let query = BasicMessageQuery {
            connection_id: Some(connection_id.to_string()),
            role: Some(BasicMessageRole::Receiver),
            ..Default::default()
        };
        self.find_by_query(query).await
    }

    /// Delete message by ID
    pub async fn delete_by_id(&self, id: &str) -> Result<()> {
        self.inner()
            .repository
            .delete_by_id(id)
            .await
            .map_err(|e| AgentError::Storage(e.to_string()))
    }

    /// Send a message to multiple connections.
    ///
    /// Useful for broadcasting messages (e.g. PLC updates to all validator
    /// nodes). Sends individually for now; could be optimized later with
    /// true multi-recipient JWE.
    pub async fn send_message_to_multiple(
        &self,
        connection_ids: Vec<String>,
        content: String,
        parent_thread_id: Option<String>,
    ) -> Result<Vec<BasicMessageRecord>> {
        let inner = self.inner();
        let conn_repo = &inner.connection_repository;
        let sender = &inner.sender;

        tracing::debug!(
            "→ [BasicMessages] Sending message to {} connections",
            connection_ids.len()
        );

        let mut records = Vec::new();

        for connection_id in connection_ids {
            let connection = conn_repo
                .find_by_id(&connection_id)
                .await
                .map_err(|e| AgentError::Connections(e.to_string()))?
                .ok_or_else(|| {
                    AgentError::Connections(format!("Connection not found: {}", connection_id))
                })?;

            let (message, record) = inner
                .service
                .create_message(content.clone(), &connection, parent_thread_id.clone())
                .await
                .map_err(|e| AgentError::Module(format!("Basic message service error: {}", e)))?;

            sender.send_via_connection(&connection, &message).await?;

            records.push(record);
        }

        tracing::debug!("[BasicMessages] Sent to {} connections", records.len());
        Ok(records)
    }

    /// Broadcast message to all completed connections
    pub async fn broadcast_message(
        &self,
        content: String,
        parent_thread_id: Option<String>,
    ) -> Result<Vec<BasicMessageRecord>> {
        let conn_repo = &self.inner().connection_repository;

        let connections = conn_repo
            .find_all_completed()
            .await
            .map_err(|e| AgentError::Connections(e.to_string()))?;

        let connection_ids: Vec<String> = connections.iter().map(|c| c.id.clone()).collect();

        tracing::debug!(
            "→ [BasicMessages] Broadcasting to {} completed connections",
            connection_ids.len()
        );

        self.send_message_to_multiple(connection_ids, content, parent_thread_id)
            .await
    }

    /// Get internal service (for advanced use cases like handler registration).
    /// Available after [`AgentModule::register`] has run.
    pub fn service(&self) -> Arc<BasicMessageService> {
        Arc::clone(&self.inner().service)
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for BasicMessagesModule {
    fn name(&self) -> &str {
        "basic_messages"
    }

    /// Build the storage-backed service + orchestration deps from the DI
    /// container / `ctx`, then register the inbound basic-message handler.
    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        use protocol_basic_messages::StorageBackedBasicMessageRepository;

        let connection_repository = ctx
            .container
            .resolve::<crate::module_runtime::ConnectionRepositoryResource>()
            .map_err(|e| format!("basic_messages: resolve connection_repository: {e}"))?
            .0
            .clone();
        let sender = ctx
            .container
            .resolve::<DidCommSender>()
            .map_err(|e| format!("basic_messages: resolve DidCommSender: {e}"))?;
        let transport = ctx
            .container
            .resolve::<TransportManager>()
            .map_err(|e| format!("basic_messages: resolve TransportManager: {e}"))?;
        let message_encryption = ctx
            .container
            .resolve::<MessageEncryption>()
            .map_err(|e| format!("basic_messages: resolve MessageEncryption: {e}"))?;

        let repository: Arc<dyn BasicMessageRepositoryTrait> = Arc::new(
            StorageBackedBasicMessageRepository::new(ctx.storage.clone()),
        );
        let service = Arc::new(BasicMessageService::new(
            repository.clone(),
            ctx.events.clone(),
            ctx.label.clone(),
        ));

        let _ = self.inner.set(BasicMessagesInner {
            service: service.clone(),
            repository,
            connection_repository: connection_repository.clone(),
            sender,
            transport,
            message_encryption,
        });

        let handler = Arc::new(protocol_basic_messages::BasicMessageHandler::new(
            service,
            connection_repository,
        ));
        ctx.handler_registry.write().await.register(handler);
        tracing::debug!("✓ [BasicMessagesModule] Basic message handler registered");
        Ok(())
    }
}

/// Typed, decoupled access to the [`BasicMessagesModule`] from an [`crate::Agent`].
pub trait BasicMessagesExt {
    fn basic_messages_module(&self) -> Option<std::sync::Arc<BasicMessagesModule>>;
}

impl BasicMessagesExt for crate::Agent {
    fn basic_messages_module(&self) -> Option<std::sync::Arc<BasicMessagesModule>> {
        self.module::<BasicMessagesModule>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_basic_messages::BasicMessageRepository;
    use protocol_connections::domain::{DidExchangeRole, DidExchangeState};
    use protocol_connections::ConnectionRecord;
    use uuid::Uuid;

    fn create_test_connection() -> ConnectionRecord {
        use protocol_connections::repository::ConnectionTags;

        ConnectionRecord {
            id: Uuid::new_v4().to_string(),
            state: DidExchangeState::Completed,
            role: DidExchangeRole::Requester,
            thread_id: "thread-1".to_string(),
            out_of_band_id: "oob-1".to_string(),
            did: "did:peer:test".to_string(),
            their_did: Some("did:peer:their".to_string()),
            their_authentication_key_base58: None,
            their_key_agreement_key_base58: None,
            our_label: None,
            their_label: None,
            previous_dids: vec![],
            previous_their_dids: vec![],
            auto_accept_connection: None,
            image_url: None,
            error_message: None,
            metadata: None,
            protocol: "connections/1.0".to_string(),
            didcomm_version: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            tags: ConnectionTags {
                role: DidExchangeRole::Requester,
                state: DidExchangeState::Completed,
                thread_id: "thread-1".to_string(),
                out_of_band_id: "oob-1".to_string(),
                did: "did:peer:test".to_string(),
                their_did: Some("did:peer:their".to_string()),
            },
        }
    }

    // The module is now config-only; its repository is built lazily during
    // `register`. These tests exercise the same query semantics directly against
    // the repository trait (what the module's `find_*` methods delegate to).
    #[tokio::test]
    async fn test_query_sent_messages() {
        let repo: Arc<dyn BasicMessageRepositoryTrait> = Arc::new(BasicMessageRepository::new());
        let connection = create_test_connection();

        let record = BasicMessageRecord::new(
            "msg-1",
            &connection.id,
            BasicMessageRole::Sender,
            "Test",
            chrono::Utc::now().to_rfc3339(),
        );
        repo.save(&record).await.unwrap();

        let sent = repo
            .find_by_query(BasicMessageQuery {
                connection_id: Some(connection.id.clone()),
                role: Some(BasicMessageRole::Sender),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].id, "msg-1");
    }

    #[tokio::test]
    async fn test_query_received_messages() {
        let repo: Arc<dyn BasicMessageRepositoryTrait> = Arc::new(BasicMessageRepository::new());
        let connection = create_test_connection();

        let record = BasicMessageRecord::new(
            "msg-1",
            &connection.id,
            BasicMessageRole::Receiver,
            "Incoming",
            chrono::Utc::now().to_rfc3339(),
        );
        repo.save(&record).await.unwrap();

        let received = repo
            .find_by_query(BasicMessageQuery {
                connection_id: Some(connection.id.clone()),
                role: Some(BasicMessageRole::Receiver),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].content, "Incoming");
    }
}
