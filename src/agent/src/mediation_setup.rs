//! Auto-mediation orchestrator — connect via OOB → request mediation →
//! wait for grant → register root key → set mediation routing.
//!
//! Lifted verbatim from `agent_ffi/src/lifecycle.rs::setup_mediation_automatic`
//! (the production-grade FFI version). The FFI helper now delegates here
//! and only retains its own `RwLock<Option<…>>` state-bag bookkeeping for
//! the C callbacks. All protocol logic lives canonically on `Agent`.
//!
//! Behavioral guarantees preserved from the FFI version:
//! - **Idempotent restore**: on second call we restore any granted
//!   MediationRecord from storage instead of re-connecting. Mediator's
//!   recipient key is parsed from the OOB invitation URL each time (NOT
//!   from `grant.registered_recipient_key`) — the stored value can go
//!   stale across app restarts where the mediator key changed.
//! - **did:peer:1 self-heal**: if the mediator's DID is `did:peer:1z…`
//!   but its DID document isn't in our repository (e.g. some mediators
//!   skip `did_doc~attach` in the connection response), we synthesize a
//!   minimal DID document from the invitation's recipient key so future
//!   resolution succeeds.
//! - **Persisted recipient_key on grant**: after registering the
//!   recipient key with the mediator's keylist, we persist it onto the
//!   `MediationRecord.registered_recipient_key` field so the same key is
//!   used on every restart. (Restoration prefers the persisted value but
//!   falls back to creating a fresh key.)

use crate::error::AgentError;
use crate::Agent;
use protocol_coordinate_mediation::{
    KeylistAction, KeylistUpdate, KeylistUpdateMessage, KeylistUpdateResponseMessage,
    MediationGrantMessage, MediationRecord,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;

type Result<T> = std::result::Result<T, AgentError>;

/// Process-wide serialization for `setup_mediation`, keyed on the mediator's
/// recipient key (extracted from the OOB invitation URL — globally unique to
/// the mediator's identity, so two callers targeting the same mediator
/// collide here regardless of which agent/bridge initiated them).
///
/// Without this lock, two concurrent agents sharing Askar storage both pass
/// the `get_all_granted()` empty check at the top of `setup_mediation` before
/// either persists a `MediationRecord`, then both run fresh OOB connect →
/// the mediator ends up with N connections. The lock serializes them so the
/// second caller re-enters `get_all_granted()` after the first commits and
/// takes the restore path instead.
///
/// Keys are never removed; the value is a tiny `Arc<TokioMutex<()>>` so the
/// memory footprint is bounded by the number of distinct mediators the
/// process has ever talked to (in practice: 1).
///
/// Public so the FFI-level manual mediator-connect entry point
/// (`agent_connect_to_mediator`) can use the same lock and serialize against
/// auto-mediation in `agent_initialize`. Without that, a manual call racing
/// with the auto loop would still produce duplicate connections.
pub fn mediator_setup_lock_for(mediator_recipient_key: &str) -> Arc<TokioMutex<()>> {
    static LOCKS: OnceLock<StdMutex<HashMap<String, Arc<TokioMutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = map.lock().expect("setup_mediation lock map poisoned");
    guard
        .entry(mediator_recipient_key.to_string())
        .or_insert_with(|| Arc::new(TokioMutex::new(())))
        .clone()
}

impl Agent {
    /// Auto-mediation orchestrator. Idempotent: if a granted MediationRecord
    /// already exists in storage, restore it (with the recipient_key from
    /// the invitation URL — not the stored key, which can be stale across
    /// app restarts). Otherwise: connect via OOB → request mediation →
    /// wait for grant → register root key → set mediation routing.
    /// Returns the granted record (containing the connection_id, endpoint,
    /// and routing_keys callers need).
    pub async fn setup_mediation(
        self: &Arc<Self>,
        invitation_url: &str,
    ) -> Result<MediationRecord> {
        tracing::info!("[setup_mediation] Starting…");

        let mediation = self
            .mediation
            .as_ref()
            .ok_or_else(|| AgentError::Mediation("Mediation module not enabled".to_string()))?;
        let recipient = mediation.recipient().ok_or_else(|| {
            AgentError::Mediation("Mediation recipient mode disabled".to_string())
        })?;

        // Parse the invitation up-front: the mediator's recipient key is the
        // dedup grain across every code path below (restore-from-grant,
        // restore-from-connection, fresh setup) AND it's the key we lock on
        // so concurrent agents in the same process serialize here.
        let (mediator_endpoint, mediator_recipient_key) = extract_mediator_info(invitation_url)?;
        let invitation_id = extract_invitation_id(invitation_url).ok();

        // Process-wide lock keyed on mediator identity. Two concurrent agents
        // (e.g. WalletBridgeManager + MessagesBridgeManager on macOS, both
        // configured with mediation enabled and sharing Askar storage) would
        // otherwise both race past the empty `get_all_granted()` check below
        // and both run fresh OOB connect → the mediator ends up with N
        // duplicate connections. With the lock, the second caller waits, then
        // re-enters get_all_granted/find_by_out_of_band_id and takes the
        // restore path against the connection the first caller just persisted.
        let setup_lock = mediator_setup_lock_for(&mediator_recipient_key);
        let _setup_guard = setup_lock.lock().await;
        tracing::debug!(
            "[setup_mediation] Acquired setup lock for mediator key {}",
            mediator_recipient_key
        );

        // ------------------------------------------------------------------
        // Restore path 1: a granted MediationRecord from a previous session
        // ------------------------------------------------------------------
        let existing = recipient
            .get_all_granted()
            .await
            .map_err(|e| AgentError::Mediation(format!("Check existing grants: {}", e)))?;

        if let Some(grant) = existing.first().cloned() {
            tracing::info!(
                "[setup_mediation] Restoring grant id={} conn={}",
                grant.id,
                grant.connection_id
            );

            // Orphan cleanup: any grant beyond the first is a leftover from a
            // pre-lock race (two agents on shared Askar both ran fresh OOB
            // setup and both persisted MediationRecords pointing at distinct
            // mediator-side ConnectionRecords). We can only keep one active
            // here — pick `existing.first()` as canonical and drop the rest
            // from local storage so subsequent restarts don't keep choosing a
            // different "first" via Askar row ordering. Mediator-side phantom
            // connections will be ignored by this agent from here on; they'll
            // age out on the mediator's own TTL.
            for orphan in existing.iter().skip(1) {
                tracing::warn!(
                    "[setup_mediation] Pruning orphan grant id={} conn={} (pre-lock race leftover)",
                    orphan.id,
                    orphan.connection_id
                );
                if let Err(e) = recipient.delete(&orphan.id).await {
                    tracing::warn!(
                        "[setup_mediation] Delete orphan grant {} failed: {}",
                        orphan.id,
                        e
                    );
                }
                if let Err(e) = self.connections().delete(&orphan.connection_id).await {
                    tracing::warn!(
                        "[setup_mediation] Delete orphan conn {} failed: {}",
                        orphan.connection_id,
                        e
                    );
                }
            }

            let connection = self
                .connections()
                .find_by_id(&grant.connection_id)
                .await
                .map_err(|e| AgentError::Mediation(format!("Find mediation conn: {}", e)))?
                .ok_or_else(|| AgentError::Mediation("Mediation connection missing".to_string()))?;
            let mediator_did = connection.their_did.clone().ok_or_else(|| {
                AgentError::Mediation("Mediation conn has no their_did".to_string())
            })?;
            let routing_endpoint = grant
                .endpoint
                .clone()
                .ok_or_else(|| AgentError::Mediation("Grant has no endpoint".to_string()))?;
            // Restore routing keys exactly as granted (empty for the direct-routing
            // Ajna mediator) — see the fresh-setup path above for why we never
            // synthesize the mediator key here.
            let routing_keys = grant.routing_keys.clone();

            // Self-heal mediator's did:peer:1 if not in repository.
            self.ensure_mediator_did_document(
                &mediator_did,
                &mediator_recipient_key,
                &mediator_endpoint,
            );

            // Restore the registered recipient key. Prefer the persisted one
            // (so peer-side invitations keep working). If persistence was
            // missed in a previous setup run (logged warning, swallowed
            // error), we'd otherwise create a fresh key here that the
            // mediator's keylist has never seen → every subsequent message
            // gets HTTP 400 from the mediator. Safety net: when persisted
            // is None, register the fresh key with the mediator's keylist
            // AND re-persist before returning.
            let agent_did_key = if let Some(ref persisted) = grant.registered_recipient_key {
                self.set_agent_did(persisted.clone()).await;
                persisted.clone()
            } else {
                tracing::warn!(
                    "[setup_mediation] Restored grant has no registered_recipient_key — registering fresh key with mediator"
                );
                let fresh_key = self.create_or_get_agent_did_key().await?;
                if let Err(e) = self
                    .register_recipient_key_with_mediator(
                        &grant.connection_id,
                        &mediator_did,
                        &mediator_endpoint,
                        &fresh_key,
                    )
                    .await
                {
                    tracing::error!(
                        "[setup_mediation] Re-register on restore failed: {} — peer messages may fail",
                        e
                    );
                    // Fall through anyway — caller might want to use the
                    // restored grant for other things, and the next pickup
                    // poll will surface PollingExitReason::KeyRejected which
                    // triggers a full re-mediation.
                } else if let Ok(Some(mut rec)) =
                    recipient.find_by_connection_id(&grant.connection_id).await
                {
                    rec.registered_recipient_key = Some(fresh_key.clone());
                    if let Err(e) = recipient.update(&rec).await {
                        tracing::warn!(
                            "[setup_mediation] Persist registered_recipient_key on restore: {}",
                            e
                        );
                    }
                }
                fresh_key
            };

            self.set_mediation_routing(routing_endpoint, routing_keys, Some(agent_did_key.clone()));

            tracing::info!("[setup_mediation] Restored existing mediation (no new connection)");
            return Ok(grant);
        }

        // ------------------------------------------------------------------
        // Restore path 2: a connection already exists for this OOB invitation
        // but the mediation grant was never persisted (typically because the
        // previous process crashed mid-bootstrap, between OOB completion and
        // process_grant). Re-issue the mediation request on the existing
        // connection rather than minting another one.
        // ------------------------------------------------------------------
        let connection_id_opt = if let Some(ref inv_id) = invitation_id {
            self.connections().get_all().await.ok().and_then(|conns| {
                conns
                    .into_iter()
                    .find(|c| c.out_of_band_id == *inv_id && c.their_did.is_some())
                    .map(|c| c.id)
            })
        } else {
            None
        };

        let connection_id = if let Some(existing_id) = connection_id_opt {
            tracing::info!(
                "[setup_mediation] Reusing existing connection {} for mediator (no grant yet)",
                existing_id
            );
            existing_id
        } else {
            // --------------------------------------------------------------
            // Fresh-setup path
            // --------------------------------------------------------------
            tracing::info!("[setup_mediation] No existing grant or connection, fresh setup…");

            // 1. Receive the OOB invitation. The connection completes either
            //    inline (idiom mediator returns the didexchange response in
            //    the HTTP body) or asynchronously (some mediators deliver it via
            //    pickup, which only starts working once we register a key).
            let result = self
                .oob()
                .receive_invitation_from_url(invitation_url, Some(true))
                .await
                .map_err(|e| AgentError::Mediation(format!("Receive invitation: {}", e)))?;
            let new_id = result
                .connection_record_id
                .ok_or_else(|| AgentError::Mediation("OOB returned no connection".to_string()))?;
            tracing::info!("[setup_mediation] Connection {} created", new_id);
            new_id
        };

        // 2. Wait for the DID Exchange handshake to complete. 10s is plenty
        //    for a healthy mediator + inline response; a typical handshake
        //    timeout is around 15s. The previous 30s was a debug-era
        //    fudge.
        let conn_notify = self.connection_ready_notify();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut mediator_did_opt: Option<String> = None;
        loop {
            if let Ok(Some(c)) = self.connections().find_by_id(&connection_id).await {
                if c.their_did.is_some() {
                    mediator_did_opt = c.their_did.clone();
                    break;
                }
            }
            match tokio::time::timeout_at(deadline, conn_notify.notified()).await {
                Ok(()) => continue,
                Err(_) => break,
            }
        }
        let mediator_did = mediator_did_opt
            .ok_or_else(|| AgentError::Mediation("Connection handshake timeout".to_string()))?;

        // 3. Build & send mediation request.
        let (_record, request_msg) = recipient
            .request_mediation(connection_id.clone())
            .await
            .map_err(|e| AgentError::Mediation(format!("Create mediation request: {}", e)))?;
        let connection = self
            .connections()
            .find_by_id(&connection_id)
            .await
            .map_err(|e| AgentError::Mediation(format!("Find conn after create: {}", e)))?
            .ok_or_else(|| AgentError::Mediation("Connection missing post-create".to_string()))?;
        let our_did = connection.did.clone();

        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "~transport".to_string(),
            serde_json::json!({"return_route": "all"}),
        );
        let request_message = didcomm::core::Message {
            id: request_msg.id.clone(),
            msg_type: request_msg.msg_type.clone(),
            body: serde_json::json!({}),
            from: Some(our_did.clone()),
            to: Some(vec![mediator_did.clone()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra,
        };
        // mediator_endpoint / mediator_recipient_key were extracted up-front.
        self.ensure_mediator_did_document(
            &mediator_did,
            &mediator_recipient_key,
            &mediator_endpoint,
        );

        let packed = self
            .pack_message_with_sender(&request_message, &mediator_did, &our_did, true)
            .await
            .map_err(|e| AgentError::Mediation(format!("Pack mediation request: {}", e)))?;

        // Reuse the agent's shared HTTP client (one TLS pool across the
        // entire mediation bootstrap — see `agent/src/http.rs` for the
        // tuning rationale). Cloning is cheap; the underlying connection
        // pool is shared by ref.
        let client = self.http_client.clone();
        let resp = client
            .post(&mediator_endpoint)
            .header("Content-Type", "application/didcomm-envelope-enc")
            .body(packed)
            .send()
            .await
            .map_err(|e| AgentError::Transport(format!("Send mediation request: {}", e)))?;
        let body = resp
            .text()
            .await
            .map_err(|e| AgentError::Transport(format!("Read mediation response: {}", e)))?;
        let decrypted = self
            .decrypt_only(&body)
            .await
            .map_err(|e| AgentError::Mediation(format!("Decrypt mediation grant: {}", e)))?;
        let grant_json: serde_json::Value = serde_json::from_str(&decrypted)
            .map_err(|e| AgentError::Mediation(format!("Parse mediation grant: {}", e)))?;

        // 4. Persist the grant + extract routing keys exactly as the mediator
        //    granted them (credo-parity: credo stores `mediationRecord.routingKeys`
        //    verbatim). The Ajna mediator runs in direct-routing mode and grants
        //    an EMPTY list — it routes inbound authcrypt by recipient-key lookup
        //    on the JWE. So we advertise NO routing keys and send direct (no
        //    Forward wrapping), exactly like credo. Synthesizing the mediator key
        //    here breaks credo interop: credo tries to dereference it as one of
        //    our DID's verification methods and fails ("Unable to locate
        //    verification method"), so it can never address us back.
        let routing_endpoint = grant_json
            .get("endpoint")
            .and_then(|e| e.as_str())
            .map(String::from)
            .unwrap_or_else(|| mediator_endpoint.clone());
        let routing_keys: Vec<String> = grant_json
            .get("routing_keys")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let thread_id = grant_json
            .get("~thread")
            .and_then(|t| t.get("thid"))
            .and_then(|t| t.as_str())
            .unwrap_or(&request_msg.id)
            .to_string();
        let grant_message =
            MediationGrantMessage::new(thread_id, routing_endpoint.clone(), routing_keys.clone());
        let granted_record = recipient
            .process_grant(&connection_id, &grant_message)
            .await
            .map_err(|e| AgentError::Mediation(format!("Process grant: {}", e)))?;

        // 5. Register our key with the mediator's keylist + process the
        //    return-routed response (persists KeylistRecord rows + emits
        //    KeylistUpdatedPayload on the recipient side).
        let agent_did_key = self.create_or_get_agent_did_key().await?;
        self.register_recipient_key_with_mediator(
            &connection_id,
            &mediator_did,
            &mediator_endpoint,
            &agent_did_key,
        )
        .await?;

        // 6. Persist registered_recipient_key onto the mediation record so
        //    restarts use the same key (without this we'd create a fresh
        //    key every restart, breaking peer invitations).
        if let Ok(Some(mut rec)) = recipient.find_by_connection_id(&connection_id).await {
            rec.registered_recipient_key = Some(agent_did_key.clone());
            if let Err(e) = recipient.update(&rec).await {
                tracing::warn!("[setup_mediation] Persist registered_recipient_key: {}", e);
            }
        }

        // 7. Wire mediation routing onto the agent.
        self.set_mediation_routing(routing_endpoint, routing_keys, Some(agent_did_key.clone()));

        // 8. Install the per-invitation recipient-key minter on the OOB
        //    module. Without this every OOB accept would reuse the singleton
        //    `agent_did_key` → identical `did:peer:1z…` → collision on the
        //    second invitation. The minter mints a fresh Ed25519 key,
        //    registers it with the mediator's keylist, and returns the
        //    did:key.
        let agent_ref = Arc::clone(self);
        self.oob().set_mint_recipient_key(Arc::new(move || {
            let agent = Arc::clone(&agent_ref);
            Box::pin(async move { agent.mint_recipient_key_via_mediator().await })
        }));

        tracing::info!(
            "[setup_mediation] Auto-mediation complete: key={}",
            agent_did_key
        );
        Ok(granted_record)
    }

    /// Get the agent's DID in did:key form, creating one if needed.
    /// Public so FFI consumers can use the same logic when they want
    /// just the key (without the full mediation flow).
    pub async fn create_or_get_agent_did_key(self: &Arc<Self>) -> Result<String> {
        if let Some(did) = self.agent_did().await {
            if did.starts_with("did:key:") {
                return Ok(did);
            }
            // Resolve did:peer or did:ajna to the underlying did:key
            if let Some(record) = self.did_repository().find_by_did(&did) {
                if let Some(ref doc) = record.did_document {
                    if let Some(vm) = doc.verification_method.first() {
                        if let Some(ref pk) = vm.public_key_base58 {
                            if let Ok(bytes) = bs58::decode(pk).into_vec() {
                                let mut mc = vec![0xed_u8, 0x01];
                                mc.extend_from_slice(&bytes);
                                return Ok(format!("did:key:z{}", bs58::encode(&mc).into_string()));
                            }
                        }
                    }
                }
            }
        }
        // No agent DID yet — create a fresh Ed25519 key.
        let wallet = self
            .wallet()
            .map_err(|e| AgentError::Mediation(format!("wallet provider: {}", e)))?;
        let key = wallet
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentMessaging,
            )
            .await
            .map_err(|e| AgentError::Mediation(format!("create_key: {}", e)))?;
        let mut mc = vec![0xed_u8, 0x01];
        mc.extend_from_slice(&key.public_key);
        let did_key = format!("did:key:z{}", bs58::encode(&mc).into_string());
        self.set_agent_did(did_key.clone()).await;
        Ok(did_key)
    }

    /// Mint a fresh Ed25519 key in the wallet, convert it to did:key form,
    /// register it with the active mediator via RFC 0211 keylist-update,
    /// and return the did:key. Each call yields a brand-new key — designed
    /// to be wired as the OOB module's per-invitation recipient-key minter.
    ///
    /// Mints a fresh recipient key, then performs the keylist-update
    /// before returning the routing. Without this, every OOB accept reuses
    /// the singleton mediator key → identical `did:peer:1z…` →
    /// `our_did` collision on the second invitation.
    pub async fn mint_recipient_key_via_mediator(self: &Arc<Self>) -> Result<(String, String)> {
        let mediation = self
            .mediation
            .as_ref()
            .ok_or_else(|| AgentError::Mediation("Mediation module not enabled".to_string()))?;
        let recipient = mediation.recipient().ok_or_else(|| {
            AgentError::Mediation("Mediation recipient mode disabled".to_string())
        })?;

        // Find the active granted mediation (we only expect one — see the
        // process-wide `mediator_setup_lock_for` at the top of this file).
        let granted = recipient
            .get_all_granted()
            .await
            .map_err(|e| AgentError::Mediation(format!("get_all_granted: {}", e)))?;
        let mediation_record = granted
            .into_iter()
            .next()
            .ok_or_else(|| AgentError::Mediation("No granted mediation".to_string()))?;
        let connection_id = mediation_record.connection_id.clone();
        let mediator_endpoint = mediation_record
            .endpoint
            .clone()
            .ok_or_else(|| AgentError::Mediation("Mediation record has no endpoint".to_string()))?;

        // Resolve the mediator's DID from the connection record (their_did).
        let conn = self
            .connections()
            .find_by_id(&connection_id)
            .await
            .map_err(|e| AgentError::Mediation(format!("find_by_id: {}", e)))?
            .ok_or_else(|| AgentError::Mediation("Mediator connection missing".to_string()))?;
        let mediator_did = conn.their_did.clone().ok_or_else(|| {
            AgentError::Mediation("Mediator connection has no their_did".to_string())
        })?;

        // Mint a brand-new Ed25519 key in the wallet and encode as did:key.
        let wallet = self
            .wallet()
            .map_err(|e| AgentError::Mediation(format!("wallet provider: {}", e)))?;
        let key = wallet
            .create_key(
                agent_core::traits::KeyType::Ed25519,
                agent_core::traits::KeyPurpose::AgentMessaging,
            )
            .await
            .map_err(|e| AgentError::Mediation(format!("create_key: {}", e)))?;
        let mut mc = vec![0xed_u8, 0x01];
        mc.extend_from_slice(&key.public_key);
        let fresh_did_key = format!("did:key:z{}", bs58::encode(&mc).into_string());

        // Register the new key with the mediator (RFC 0211 keylist-update).
        self.register_recipient_key_with_mediator(
            &connection_id,
            &mediator_did,
            &mediator_endpoint,
            &fresh_did_key,
        )
        .await?;

        tracing::info!(
            "[mint_recipient_key_via_mediator] Registered fresh recipient key {} (wallet key {})",
            fresh_did_key,
            key.id
        );
        Ok((fresh_did_key, key.id))
    }

    /// Send a single `keylist-update {action: add, recipient_key}` to the
    /// mediator and process the return-routed `keylist-update-response`.
    ///
    /// On success: the mediator's keylist now contains `recipient_key`, our
    /// local `KeylistRepository` has the matching `KeylistRecord`, and
    /// `KeylistUpdatedPayload` has been emitted on the event bus.
    ///
    /// Called from two paths:
    /// - fresh setup, after `process_grant` lands a `MediationRecord`;
    /// - restore-path safety net, when `registered_recipient_key` is missing
    ///   from a restored grant (we generated a fresh key and need to tell
    ///   the mediator).
    ///
    /// Returns `Err` only if the HTTP POST fails or the mediator returns
    /// non-2xx. Decrypt / parse failures on the response are best-effort
    /// (logged + swallowed) — the 2xx is authoritative for "accepted".
    pub(crate) async fn register_recipient_key_with_mediator(
        self: &Arc<Self>,
        connection_id: &str,
        mediator_did: &str,
        mediator_endpoint: &str,
        recipient_key: &str,
    ) -> Result<()> {
        let mediation = self
            .mediation
            .as_ref()
            .ok_or_else(|| AgentError::Mediation("Mediation module not enabled".to_string()))?;
        let recipient = mediation.recipient().ok_or_else(|| {
            AgentError::Mediation("Mediation recipient mode disabled".to_string())
        })?;
        let connection = self
            .connections()
            .find_by_id(connection_id)
            .await
            .map_err(|e| AgentError::Mediation(format!("Find conn: {}", e)))?
            .ok_or_else(|| AgentError::Mediation("Connection missing".to_string()))?;
        let our_did = connection.did.clone();

        let keylist_msg = KeylistUpdateMessage::new(vec![KeylistUpdate {
            recipient_key: recipient_key.to_string(),
            action: KeylistAction::Add,
        }]);
        let mut kl_extra = std::collections::HashMap::new();
        kl_extra.insert(
            "~transport".to_string(),
            serde_json::json!({"return_route": "all"}),
        );
        let keylist_message = didcomm::core::Message {
            id: keylist_msg.id.clone(),
            msg_type: KeylistUpdateMessage::TYPE.to_string(),
            body: serde_json::to_value(&keylist_msg)
                .map_err(|e| AgentError::Mediation(format!("Serialize keylist update: {}", e)))?,
            from: Some(our_did.clone()),
            to: Some(vec![mediator_did.to_string()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: kl_extra,
        };
        let packed_kl = self
            .pack_message_with_sender(&keylist_message, mediator_did, &our_did, true)
            .await
            .map_err(|e| AgentError::Mediation(format!("Pack keylist-update: {}", e)))?;

        // Reuse the agent's shared HTTP client (see `agent/src/http.rs`).
        // Keylist-update is a tiny round-trip; sharing the pool means we
        // don't pay another TLS handshake on top of the mediation-request
        // one that just happened.
        let client = self.http_client.clone();
        let resp = client
            .post(mediator_endpoint)
            .header("Content-Type", "application/didcomm-envelope-enc")
            .body(packed_kl)
            .send()
            .await
            .map_err(|e| AgentError::Transport(format!("Send keylist-update: {}", e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(AgentError::Mediation(format!(
                "Keylist update HTTP {}",
                status
            )));
        }

        // Process the return-routed keylist-update-response. Best-effort.
        let body = resp.text().await.unwrap_or_default();
        if !body.is_empty() {
            // Find the mediation record id for this connection so the
            // process_keylist_update_response can save KeylistRecord rows
            // scoped to the right mediation.
            let mediation_id = recipient
                .find_by_connection_id(connection_id)
                .await
                .ok()
                .flatten()
                .map(|r| r.id);
            match self.decrypt_only(&body).await {
                Ok(decrypted) => {
                    match serde_json::from_str::<KeylistUpdateResponseMessage>(&decrypted) {
                        Ok(response) => {
                            if let Some(mid) = mediation_id {
                                if let Err(e) = recipient
                                    .process_keylist_update_response(&mid, &response.updated)
                                    .await
                                {
                                    tracing::warn!(
                                        "[register_recipient_key] process_keylist_update_response: {}",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => tracing::debug!(
                            "[register_recipient_key] response not parsable as keylist-update-response: {}",
                            e
                        ),
                    }
                }
                Err(e) => tracing::debug!("[register_recipient_key] decrypt response: {}", e),
            }
        }
        Ok(())
    }

    /// Self-heal: if the mediator's DID is `did:peer:1z…` and its document
    /// isn't in our repository (some mediators sometimes skip
    /// `did_doc~attach` in the connection response), synthesize a minimal
    /// document from the invitation's recipient key. Idempotent.
    fn ensure_mediator_did_document(
        &self,
        mediator_did: &str,
        mediator_recipient_key: &str,
        endpoint: &str,
    ) {
        if !mediator_did.starts_with("did:peer:1") {
            return;
        }
        let did_repo = self.did_repository();
        if did_repo.find_by_did(mediator_did).is_some() {
            return;
        }
        let Some(key_part) = mediator_recipient_key.strip_prefix("did:key:z") else {
            return;
        };
        let Ok(decoded) = bs58::decode(key_part).into_vec() else {
            return;
        };
        if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
            return;
        }
        let public_key_base58 = bs58::encode(&decoded[2..]).into_string();
        let mut did_document = did::core::DidDocument::new(mediator_did.to_string());
        let vm = did::core::VerificationMethod::new(
            format!("{}#key-1", mediator_did),
            "Ed25519VerificationKey2020".to_string(),
            mediator_did.to_string(),
        )
        .with_public_key_base58(public_key_base58);
        did_document.add_verification_method(vm);
        did_document.add_authentication(did::core::VerificationRelationship::Reference(format!(
            "{}#key-1",
            mediator_did
        )));
        did_document.add_key_agreement(did::core::VerificationRelationship::Reference(format!(
            "{}#key-1",
            mediator_did
        )));
        let service = did::core::Service::new(
            format!("{}#didcomm", mediator_did),
            "DIDCommMessaging".to_string(),
            serde_json::json!(endpoint),
        )
        .with_property(
            "recipientKeys".to_string(),
            serde_json::json!([mediator_recipient_key]),
        );
        did_document.add_service(service);
        if let Err(e) =
            did_repo.store_received_did(mediator_did.to_string(), Some(did_document), vec![])
        {
            tracing::warn!(
                "[setup_mediation] store mediator DID document failed: {}",
                e
            );
        }
    }
}

/// Parse an OOB invitation URL and return `(http_endpoint, mediator_recipient_key)`.
/// The recipient key is the mediator's static public key — peers must
/// encrypt their outer envelope to this key for the mediator to route it.
pub fn extract_mediator_info(url: &str) -> Result<(String, String)> {
    let oob_param = url
        .split("oob=")
        .nth(1)
        .ok_or_else(|| AgentError::Mediation("No oob parameter".to_string()))?;
    let decoded_url = urlencoding::decode(oob_param)
        .map_err(|e| AgentError::Mediation(format!("URL decode oob: {}", e)))?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let json_bytes = URL_SAFE_NO_PAD
        .decode(decoded_url.as_bytes())
        .map_err(|e| AgentError::Mediation(format!("base64 decode oob: {}", e)))?;
    let invitation: serde_json::Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| AgentError::Mediation(format!("parse invitation: {}", e)))?;

    let services = invitation
        .get("services")
        .or_else(|| invitation.get("service"))
        .and_then(|s| s.as_array())
        .ok_or_else(|| AgentError::Mediation("no services in invitation".to_string()))?;
    let first = services
        .first()
        .ok_or_else(|| AgentError::Mediation("empty services".to_string()))?;
    let endpoint = first
        .get("serviceEndpoint")
        .and_then(|e| e.as_str())
        .ok_or_else(|| AgentError::Mediation("no serviceEndpoint".to_string()))?
        .to_string();
    let recipient_key = first
        .get("recipientKeys")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|k| k.as_str())
        .ok_or_else(|| AgentError::Mediation("no recipientKeys".to_string()))?
        .to_string();
    Ok((endpoint, recipient_key))
}

/// Parse an OOB invitation URL and return its `@id`. The @id is the OOB
/// invitation's globally-unique identifier (same value the mediator embeds
/// in every issued invitation URL). We use it to look up whether this agent
/// has already received this invitation in a prior run — see Restore Path 2
/// in `setup_mediation`.
pub fn extract_invitation_id(url: &str) -> Result<String> {
    let oob_param = url
        .split("oob=")
        .nth(1)
        .ok_or_else(|| AgentError::Mediation("No oob parameter".to_string()))?;
    let decoded_url = urlencoding::decode(oob_param)
        .map_err(|e| AgentError::Mediation(format!("URL decode oob: {}", e)))?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let json_bytes = URL_SAFE_NO_PAD
        .decode(decoded_url.as_bytes())
        .map_err(|e| AgentError::Mediation(format!("base64 decode oob: {}", e)))?;
    let invitation: serde_json::Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| AgentError::Mediation(format!("parse invitation: {}", e)))?;
    invitation
        .get("@id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AgentError::Mediation("invitation has no @id".to_string()))
}
