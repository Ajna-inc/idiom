//! Mediator Service
//!
//! This service handles the mediator (server) side of the mediation protocol.
//! It allows an agent acting as a mediator to grant/deny mediation requests
//! and manage keylists for recipients.

use crate::{
    domain::{KeylistAction, KeylistResult},
    events::MediationStateChangedPayload,
    KeylistRecord, KeylistRepository, KeylistRepositoryTrait, KeylistUpdate, KeylistUpdated,
    MediationDenyMessage, MediationError, MediationGrantMessage, MediationRecord,
    MediationRecordBuilder, MediationRepository, MediationRepositoryTrait, MediationRole,
    MediationState, Result,
};
use std::sync::Arc;

/// Service for mediator operations
pub struct MediatorService {
    pub(crate) mediation_repository: Arc<dyn MediationRepositoryTrait>,
    pub(crate) keylist_repository: Arc<dyn KeylistRepositoryTrait>,
    /// Our mediator endpoint
    endpoint: String,
    /// Our routing keys
    routing_keys: Vec<String>,
    /// Event bus for emitting mediation events (optional)
    event_bus: Option<Arc<agent_events::EventBus>>,
    /// Agent ID for event attribution
    agent_id: String,
}

impl MediatorService {
    /// Create a new mediator service
    pub fn new(
        mediation_repository: Arc<dyn MediationRepositoryTrait>,
        keylist_repository: Arc<dyn KeylistRepositoryTrait>,
        endpoint: String,
        routing_keys: Vec<String>,
    ) -> Self {
        Self {
            mediation_repository,
            keylist_repository,
            endpoint,
            routing_keys,
            event_bus: None,
            agent_id: "unknown".to_string(),
        }
    }

    /// Create a mediator service with default repositories
    pub fn with_defaults(endpoint: String, routing_keys: Vec<String>) -> Self {
        Self::new(
            Arc::new(MediationRepository::new()),
            Arc::new(KeylistRepository::new()),
            endpoint,
            routing_keys,
        )
    }

    /// Set the event bus for emitting events
    pub fn with_event_bus(
        mut self,
        event_bus: Arc<agent_events::EventBus>,
        agent_id: String,
    ) -> Self {
        self.event_bus = Some(event_bus);
        self.agent_id = agent_id;
        self
    }

    /// Emit a mediation state changed event via the typed bus.
    async fn emit_state_changed(
        &self,
        record: &MediationRecord,
        previous_state: Option<MediationState>,
    ) {
        if let Some(event_bus) = &self.event_bus {
            let payload = MediationStateChangedPayload {
                mediation_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = event_bus.emit(&meta, payload).await;
        }
    }

    /// Process a mediation request from a recipient
    ///
    /// Creates a mediation record in Requested state
    pub async fn process_request(&self, connection_id: String) -> Result<MediationRecord> {
        // Create mediation record
        let record = MediationRecordBuilder::new(connection_id, MediationRole::Mediator).build();

        // Save record
        self.mediation_repository.save(&record).await?;

        // Emit state changed event (no previous state for new record)
        self.emit_state_changed(&record, None).await;

        Ok(record)
    }

    /// Grant mediation for a request
    ///
    /// Updates the mediation record to Granted and returns the grant message
    pub async fn grant_mediation(
        &self,
        mediation_id: &str,
        thread_id: String,
    ) -> Result<(MediationRecord, MediationGrantMessage)> {
        // Find mediation record
        let mut record = self
            .mediation_repository
            .find_by_id(mediation_id)
            .await?
            .ok_or_else(|| MediationError::NotFound(mediation_id.to_string()))?;

        // Validate state transition
        if !MediationState::Granted.is_valid_transition_from(&record.state) {
            return Err(MediationError::InvalidStateTransition {
                from: record.state,
                to: MediationState::Granted,
            });
        }

        // Store previous state for event
        let previous_state = record.state;

        // Update record
        record.state = MediationState::Granted;
        record.endpoint = Some(self.endpoint.clone());
        record.routing_keys = self.routing_keys.clone();

        // Save updated record
        self.mediation_repository.update(&record).await?;

        // Emit state changed event
        self.emit_state_changed(&record, Some(previous_state)).await;

        // Create grant message
        let message =
            MediationGrantMessage::new(thread_id, self.endpoint.clone(), self.routing_keys.clone());

        Ok((record, message))
    }

    /// Deny mediation for a request
    ///
    /// Updates the mediation record to Denied and returns the deny message
    pub async fn deny_mediation(
        &self,
        mediation_id: &str,
        thread_id: String,
    ) -> Result<(MediationRecord, MediationDenyMessage)> {
        // Find mediation record
        let mut record = self
            .mediation_repository
            .find_by_id(mediation_id)
            .await?
            .ok_or_else(|| MediationError::NotFound(mediation_id.to_string()))?;

        // Validate state transition
        if !MediationState::Denied.is_valid_transition_from(&record.state) {
            return Err(MediationError::InvalidStateTransition {
                from: record.state,
                to: MediationState::Denied,
            });
        }

        // Store previous state for event
        let previous_state = record.state;

        // Update record
        record.state = MediationState::Denied;

        // Save updated record
        self.mediation_repository.update(&record).await?;

        // Emit state changed event
        self.emit_state_changed(&record, Some(previous_state)).await;

        // Create deny message
        let message = MediationDenyMessage::new(thread_id);

        Ok((record, message))
    }

    /// Process keylist updates from a recipient
    ///
    /// Updates the keylist and returns the results
    pub async fn process_keylist_updates(
        &self,
        mediation_id: &str,
        updates: &[KeylistUpdate],
    ) -> Result<Vec<KeylistUpdated>> {
        use crate::domain::KeylistAction;
        let mut results = Vec::new();
        #[cfg(feature = "events")]
        let mut keys_added: Vec<String> = Vec::new();
        #[cfg(feature = "events")]
        let mut keys_removed: Vec<String> = Vec::new();

        for update in updates {
            let result = self
                .process_single_keylist_update(mediation_id, update)
                .await;

            let updated = match result {
                Ok(()) => {
                    #[cfg(feature = "events")]
                    {
                        match update.action {
                            KeylistAction::Add => {
                                keys_added.push(update.recipient_key.clone());
                            }
                            KeylistAction::Remove => {
                                keys_removed.push(update.recipient_key.clone());
                            }
                        }
                    }
                    KeylistUpdated::success(update.recipient_key.clone(), update.action)
                }
                Err(e) => {
                    tracing::warn!("Keylist update failed: {}", e);
                    KeylistUpdated::server_error(update.recipient_key.clone(), update.action)
                }
            };

            results.push(updated);
        }

        // Emit one aggregate `(keylist, keylist_updated)` per batch — one
        // event per recipient-issued update message rather than one per key.
        // `keys_added` / `keys_removed` are the keys that succeeded; failed
        // updates are visible only via the returned `KeylistUpdated` results.
        #[cfg(feature = "events")]
        if !keys_added.is_empty() || !keys_removed.is_empty() {
            if let Some(bus) = &self.event_bus {
                let payload = crate::events::KeylistUpdatedPayload {
                    mediation_id: mediation_id.to_string(),
                    keys_added,
                    keys_removed,
                };
                let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
                let _ = bus.emit(&meta, payload).await;
            }
        }

        Ok(results)
    }

    /// Process a single keylist update
    async fn process_single_keylist_update(
        &self,
        mediation_id: &str,
        update: &KeylistUpdate,
    ) -> Result<()> {
        // Canonicalize to raw base58 Ed25519 verkey before storing.
        //
        // The keylist-update body may carry the recipient_key in either
        // `did:key:z6Mk…` form (RFC 0211 / current recipients) or raw
        // base58 verkey (older / direct callers). The JWE recipient `kid` we
        // need to look up later is ALWAYS raw base58 verkey (the kid is the
        // base58-encoded public key), so we collapse the format here on
        // store. Lookup then becomes a single exact match: canonicalize the
        // recipient key to raw base58 before storing.
        let key = canonicalize_recipient_key(&update.recipient_key);

        match update.action {
            KeylistAction::Add => {
                // Registering a key MOVES it: a recipient key routes to
                // exactly one mediation — the most recent registration.
                // Without this, every root-agent restart (fresh
                // mediation connection) left stale rows binding the key
                // to a dead connection, and
                // `find_mediation_for_recipient_key` (arbitrary match)
                // could route deliveries there → "no live session" →
                // messages queued until the recipient's next activity.
                //
                // P-H2 (routing-key hijack): the move is only safe between
                // mediations that belong to the SAME authenticated identity.
                // A mediation's `connection_id` is the authcrypt-verified
                // sender (resolve_connection_id, keyed by the sender's own
                // auth key — stable across restarts), so a legit restart
                // re-registers under the same connection_id (new mediation
                // id). A move that would cross to a DIFFERENT connection_id
                // is a granted tenant trying to steal a victim's recipient
                // key and rebind its routing — reject it. (We only block on
                // a POSITIVE mismatch; a missing old record is a genuinely
                // dead binding and stays reclaimable, preserving the
                // restart/self-heal path.)
                let new_conn = self
                    .mediation_repository
                    .find_by_id(mediation_id)
                    .await?
                    .map(|m| m.connection_id);
                let stale: Vec<KeylistRecord> = self
                    .keylist_repository
                    .get_all()
                    .await?
                    .into_iter()
                    .filter(|r| r.recipient_key == key && r.mediation_id != mediation_id)
                    .collect();
                for r in stale {
                    let old_conn = self
                        .mediation_repository
                        .find_by_id(&r.mediation_id)
                        .await?
                        .map(|m| m.connection_id);
                    if let (Some(oc), Some(nc)) = (&old_conn, &new_conn) {
                        if oc != nc {
                            tracing::warn!(
                                key = %key,
                                old_mediation = %r.mediation_id,
                                new_mediation = %mediation_id,
                                "keylist add: REJECTED cross-identity recipient-key move (routing hijack attempt)"
                            );
                            return Err(MediationError::KeylistUpdateFailed(
                                "recipient key is registered to a different connection".into(),
                            ));
                        }
                    }
                    tracing::info!(
                        key = %key,
                        old_mediation = %r.mediation_id,
                        new_mediation = %mediation_id,
                        "keylist add: moving recipient key to new mediation"
                    );
                    self.keylist_repository
                        .delete_by_recipient_key(&r.mediation_id, &key)
                        .await?;
                }

                // Check if key already exists
                if let Some(_existing) = self
                    .keylist_repository
                    .find_by_recipient_key(mediation_id, &key)
                    .await?
                {
                    // Key already exists, no change needed
                    return Ok(());
                }

                // Add new key
                let record = KeylistRecord::new(
                    mediation_id.to_string(),
                    key,
                    KeylistAction::Add,
                    KeylistResult::Success,
                );
                self.keylist_repository.save(&record).await?;
            }
            KeylistAction::Remove => {
                // Remove the key
                self.keylist_repository
                    .delete_by_recipient_key(mediation_id, &key)
                    .await?;
            }
        }

        Ok(())
    }

    /// Get all keylist entries for a mediation
    pub async fn get_keylist(&self, mediation_id: &str) -> Result<Vec<KeylistRecord>> {
        self.keylist_repository
            .find_by_mediation_id(mediation_id)
            .await
    }

    /// Check if a recipient key is in the keylist
    pub async fn is_key_in_keylist(&self, mediation_id: &str, recipient_key: &str) -> Result<bool> {
        Ok(self
            .keylist_repository
            .find_by_recipient_key(mediation_id, recipient_key)
            .await?
            .is_some())
    }

    /// Get all granted mediations
    pub async fn get_all_granted(&self) -> Result<Vec<MediationRecord>> {
        self.mediation_repository.find_all_granted().await
    }
}

/// Convert a `did:key:z6Mk…` to its raw base58 Ed25519 verkey, or pass through
/// if already in raw form. The JWE recipient `kid` produced by DIDComm v1 packing
/// is the raw 32-byte Ed25519 public key base58-encoded. By canonicalising on
/// store, lookup becomes a trivial exact match — provided callers canonicalise
/// on lookup too.
pub fn canonicalize_recipient_key(recipient_key: &str) -> String {
    if let Some(stripped) = recipient_key.strip_prefix("did:key:z") {
        if let Ok(decoded) = bs58::decode(stripped).into_vec() {
            // ed25519-pub multicodec is `0xed 0x01` (varint), followed by 32-byte pubkey
            if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
                return bs58::encode(&decoded[2..]).into_string();
            }
        }
    }
    recipient_key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grant_mediation() {
        let service = MediatorService::with_defaults(
            "https://mediator.example.com".to_string(),
            vec!["did:key:z6Mkk...".to_string()],
        );

        // Process request
        let record = service
            .process_request("conn-123".to_string())
            .await
            .unwrap();

        // Grant mediation
        let (updated_record, grant_msg) = service
            .grant_mediation(&record.id, "thread-123".to_string())
            .await
            .unwrap();

        assert_eq!(updated_record.state, MediationState::Granted);
        assert_eq!(grant_msg.endpoint, "https://mediator.example.com");
    }

    #[tokio::test]
    async fn test_deny_mediation() {
        let service =
            MediatorService::with_defaults("https://mediator.example.com".to_string(), vec![]);

        // Process request
        let record = service
            .process_request("conn-123".to_string())
            .await
            .unwrap();

        // Deny mediation
        let (updated_record, _deny_msg) = service
            .deny_mediation(&record.id, "thread-123".to_string())
            .await
            .unwrap();

        assert_eq!(updated_record.state, MediationState::Denied);
    }

    #[tokio::test]
    async fn test_process_keylist_updates() {
        let service =
            MediatorService::with_defaults("https://mediator.example.com".to_string(), vec![]);

        // Process request and grant
        let record = service
            .process_request("conn-123".to_string())
            .await
            .unwrap();

        service
            .grant_mediation(&record.id, "thread-123".to_string())
            .await
            .unwrap();

        // Add keys
        let updates = vec![
            KeylistUpdate::add("did:key:z6Mkk1...".to_string()),
            KeylistUpdate::add("did:key:z6Mkk2...".to_string()),
        ];

        let results = service
            .process_keylist_updates(&record.id, &updates)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.result == KeylistResult::Success));

        // Verify keys were added
        let keylist = service.get_keylist(&record.id).await.unwrap();
        assert_eq!(keylist.len(), 2);
    }

    #[tokio::test]
    async fn test_keylist_add_rejects_cross_identity_hijack() {
        // P-H2: a granted tenant must not be able to Add() another tenant's
        // recipient key and hijack its routing. A move is allowed only within
        // the SAME connection identity (e.g. the same tenant re-registering
        // after a restart).
        let service =
            MediatorService::with_defaults("https://mediator.example.com".to_string(), vec![]);
        let victim_key = "did:key:z6MkVictimRecipientKey".to_string();

        // Victim registers their key under their own mediation (conn-victim).
        let victim = service
            .process_request("conn-victim".to_string())
            .await
            .unwrap();
        service
            .grant_mediation(&victim.id, "t1".to_string())
            .await
            .unwrap();
        let r = service
            .process_keylist_updates(&victim.id, &[KeylistUpdate::add(victim_key.clone())])
            .await
            .unwrap();
        assert_eq!(r[0].result, KeylistResult::Success);
        assert_eq!(service.get_keylist(&victim.id).await.unwrap().len(), 1);

        // Attacker on a DIFFERENT connection tries to steal the key → rejected.
        let attacker = service
            .process_request("conn-attacker".to_string())
            .await
            .unwrap();
        service
            .grant_mediation(&attacker.id, "t2".to_string())
            .await
            .unwrap();
        let r = service
            .process_keylist_updates(&attacker.id, &[KeylistUpdate::add(victim_key.clone())])
            .await
            .unwrap();
        assert_ne!(
            r[0].result,
            KeylistResult::Success,
            "cross-identity move must be rejected"
        );
        assert_eq!(
            service.get_keylist(&attacker.id).await.unwrap().len(),
            0,
            "attacker must not hold the key"
        );
        assert_eq!(
            service.get_keylist(&victim.id).await.unwrap().len(),
            1,
            "victim must keep the key"
        );

        // Legit restart: SAME identity (conn-victim), fresh mediation id → allowed.
        let victim2 = service
            .process_request("conn-victim".to_string())
            .await
            .unwrap();
        service
            .grant_mediation(&victim2.id, "t3".to_string())
            .await
            .unwrap();
        assert_ne!(victim2.id, victim.id);
        let r = service
            .process_keylist_updates(&victim2.id, &[KeylistUpdate::add(victim_key.clone())])
            .await
            .unwrap();
        assert_eq!(
            r[0].result,
            KeylistResult::Success,
            "same-identity restart move must succeed"
        );
        assert_eq!(service.get_keylist(&victim2.id).await.unwrap().len(), 1);
        assert_eq!(
            service.get_keylist(&victim.id).await.unwrap().len(),
            0,
            "key moved off the old mediation"
        );
    }
}
