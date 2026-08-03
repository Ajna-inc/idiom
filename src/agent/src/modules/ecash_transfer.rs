//! eCash Transfer Handler
//!
//! Processes incoming connectionless eCash transfer-note messages.
//! When a transfer-note arrives (e.g. from a QR-code payment), the handler
//! deserializes the OfflineTransfer, verifies the note, and adds it to the
//! local eCash wallet.
//!
//! This module is kept minimal — it receives a wallet Arc at construction
//! and only depends on `didcomm_messaging` for the handler trait. The wallet
//! type is generic to avoid pulling in `ajna_client` as a dependency.

use std::sync::Arc;
use tokio::sync::Notify;

/// Current time in milliseconds (avoid dependency on ajna_offline)
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Trait for adding received notes to a wallet.
/// Implemented by the FFI layer to bridge to the concrete wallet type.
#[async_trait::async_trait]
pub trait NoteReceiver: Send + Sync {
    /// Add notes from a batch transfer JSON envelope.
    /// JSON is `{"batch": true, "commit": {...}, "reveal": {...}, "rx_se_label": ..., "rx_se_pk": ...}`
    async fn receive_batch_json(&self, batch_json: &str) -> Result<(), String>;
}

// ============================================================================
// Batch Transfer Protocol — 4-message state machine
// ============================================================================

use std::collections::HashMap;
use tokio::sync::RwLock;

/// PIURI for batch-commit (Message 1: sender → receiver)
pub const PIURI_BATCH_COMMIT: &str = "https://ajna.network/ecash/1.0/batch-commit";

/// PIURI for batch-ack (Message 2: receiver → sender)
pub const PIURI_BATCH_ACK: &str = "https://ajna.network/ecash/1.0/batch-ack";

/// PIURI for batch-reveal (Message 3: sender → receiver)
pub const PIURI_BATCH_REVEAL: &str = "https://ajna.network/ecash/1.0/batch-reveal";

/// PIURI for batch-done (Message 4: receiver → sender, confirmation/rejection)
pub const PIURI_BATCH_DONE: &str = "https://ajna.network/ecash/1.0/batch-done";

/// Timeout for pending transfers (30 seconds)
const TRANSFER_TIMEOUT_MS: u64 = 30_000;

/// Trait for generating Secure Enclave keys (callback from native layer).
#[async_trait::async_trait]
pub trait SecureKeyProvider: Send + Sync {
    /// Generate a new P-256 key and return the compressed public key (33 bytes).
    async fn generate_key(&self, label: &str) -> Result<[u8; 33], String>;
}

/// Trait for signing ACK data with the agent's DID Ed25519 key.
///
/// Provides non-repudiation: the receiver signs the ACK with their DID key,
/// proving they acknowledged a specific batch. The sender can verify
/// using the receiver's DID public key (from the OOB invitation).
#[async_trait::async_trait]
pub trait DidSigner: Send + Sync {
    /// Sign data with the agent's DID Ed25519 key.
    /// Returns (64-byte Ed25519 signature, DID string).
    async fn sign_with_did(&self, data: &[u8]) -> Result<(Vec<u8>, String), String>;
}

/// Data returned when sender receives an ACK.
pub struct BatchAckData {
    pub preimages: Vec<[u8; 32]>,
    pub note_serials: Vec<[u8; 32]>,
    pub receiver_spend_pk: [u8; 33],
    pub sender_se_labels: Vec<String>,
    pub sender_se_pks: Vec<[u8; 33]>,
    pub ack_sig: Vec<u8>,
    pub receiver_did: String,
}

/// Result of a transfer from the receiver's perspective (4th message).
pub enum TransferDoneResult {
    /// Receiver successfully processed the batch
    Done,
    /// Receiver rejected the transfer
    Nack(String),
}

/// Internal state for pending batch transfers.
enum PendingBatchTransfer {
    /// Receiver has received a batch-commit, waiting for batch-reveal.
    CommitReceived {
        commit_json: String,
        ts: u64,
        /// ONE SE key label for the batch
        rx_se_label: String,
        /// ONE compressed P-256 public key for the batch
        rx_se_pk: [u8; 33],
    },
    /// Sender has sent a batch-commit, waiting for batch-ack.
    Committed {
        preimages: Vec<[u8; 32]>,
        note_serials: Vec<[u8; 32]>,
        sender_se_labels: Vec<String>,
        sender_se_pks: Vec<[u8; 33]>,
        ts: u64,
    },
    /// Sender has received a batch-ack, ready to reveal.
    AckReceived {
        preimages: Vec<[u8; 32]>,
        note_serials: Vec<[u8; 32]>,
        receiver_spend_pk: [u8; 33],
        sender_se_labels: Vec<String>,
        sender_se_pks: Vec<[u8; 33]>,
        ack_sig: Vec<u8>,
        receiver_did: String,
        ts: u64,
    },
}

/// Handler for the 4-message batch eCash transfer protocol.
///
/// Processes:
/// - `batch-commit` (Message 1): Receiver stores pending, sends ACK
/// - `batch-ack` (Message 2): Sender stores ACK, triggers reveal
/// - `batch-reveal` (Message 3): Receiver decrypts notes, verifies chain, adds to wallet
/// - `batch-done` (Message 4): Sender learns result (done/nack)
pub struct BatchTransferHandler {
    receiver: Arc<dyn NoteReceiver>,
    pending: Arc<RwLock<HashMap<[u8; 32], PendingBatchTransfer>>>,
    done_confirmations: Arc<RwLock<HashMap<[u8; 32], TransferDoneResult>>>,
    se_provider: Option<Arc<dyn SecureKeyProvider>>,
    did_signer: Option<Arc<dyn DidSigner>>,
    ack_notify: Arc<Notify>,
    done_notify: Arc<Notify>,
}

impl BatchTransferHandler {
    pub fn new(
        receiver: Arc<dyn NoteReceiver>,
        se_provider: Option<Arc<dyn SecureKeyProvider>>,
        did_signer: Option<Arc<dyn DidSigner>>,
    ) -> Self {
        Self {
            receiver,
            pending: Arc::new(RwLock::new(HashMap::new())),
            done_confirmations: Arc::new(RwLock::new(HashMap::new())),
            se_provider,
            did_signer,
            ack_notify: Arc::new(Notify::new()),
            done_notify: Arc::new(Notify::new()),
        }
    }

    /// Store a sender-side pending batch transfer (called by FFI pay flow).
    pub async fn register_pending_batch(
        &self,
        batch_id: [u8; 32],
        preimages: Vec<[u8; 32]>,
        note_serials: Vec<[u8; 32]>,
        sender_se_labels: Vec<String>,
        sender_se_pks: Vec<[u8; 33]>,
    ) {
        tracing::debug!(
            "[eCash-PENDING] register_pending_batch: batch_id={}, notes={}, self={:p}",
            hex::encode(&batch_id[..8]),
            preimages.len(),
            self as *const Self
        );
        let mut pending = self.pending.write().await;
        pending.insert(
            batch_id,
            PendingBatchTransfer::Committed {
                preimages,
                note_serials,
                sender_se_labels,
                sender_se_pks,
                ts: now_ms(),
            },
        );
        tracing::debug!(
            "[eCash-PENDING] Pending map now has {} entries: [{}]",
            pending.len(),
            pending
                .keys()
                .map(|k| hex::encode(&k[..8]))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// Check if we have a received ACK for a given batch_id.
    pub async fn take_ack(&self, batch_id: &[u8; 32]) -> Option<BatchAckData> {
        let mut pending = self.pending.write().await;
        if matches!(
            pending.get(batch_id),
            Some(PendingBatchTransfer::AckReceived { .. })
        ) {
            if let Some(PendingBatchTransfer::AckReceived {
                preimages,
                note_serials,
                receiver_spend_pk,
                sender_se_labels,
                sender_se_pks,
                ack_sig,
                receiver_did,
                ..
            }) = pending.remove(batch_id)
            {
                return Some(BatchAckData {
                    preimages,
                    note_serials,
                    receiver_spend_pk,
                    sender_se_labels,
                    sender_se_pks,
                    ack_sig,
                    receiver_did,
                });
            }
        }
        None
    }

    /// Check if the receiver sent a DONE/NACK for a given batch_id.
    pub async fn take_done(&self, batch_id: &[u8; 32]) -> Option<TransferDoneResult> {
        self.done_confirmations.write().await.remove(batch_id)
    }

    /// Wait for ACK with timeout. Returns instantly when ACK arrives.
    pub async fn wait_for_ack(
        &self,
        batch_id: &[u8; 32],
        timeout_secs: u64,
    ) -> Option<BatchAckData> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            if let Some(data) = self.take_ack(batch_id).await {
                return Some(data);
            }
            match tokio::time::timeout_at(deadline, self.ack_notify.notified()).await {
                Ok(()) => continue,
                Err(_) => return self.take_ack(batch_id).await,
            }
        }
    }

    /// Wait for DONE/NACK with timeout. Returns instantly when DONE arrives.
    pub async fn wait_for_done(
        &self,
        batch_id: &[u8; 32],
        timeout_secs: u64,
    ) -> Option<TransferDoneResult> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        loop {
            if let Some(result) = self.take_done(batch_id).await {
                return Some(result);
            }
            match tokio::time::timeout_at(deadline, self.done_notify.notified()).await {
                Ok(()) => continue,
                Err(_) => return self.take_done(batch_id).await,
            }
        }
    }

    /// Number of pending transfers (for testing)
    #[cfg(test)]
    pub(crate) async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Prune timed-out pending transfers
    pub async fn prune_expired(&self) {
        let now = now_ms();
        let mut pending = self.pending.write().await;
        pending.retain(|_, v| {
            let ts = match v {
                PendingBatchTransfer::CommitReceived { ts, .. } => *ts,
                PendingBatchTransfer::Committed { ts, .. } => *ts,
                PendingBatchTransfer::AckReceived { ts, .. } => *ts,
            };
            now - ts < TRANSFER_TIMEOUT_MS
        });
    }
}

/// Helper: parse a [u8; 32] from a JSON byte array
fn parse_32_from_json(
    val: &serde_json::Value,
    field: &str,
) -> Result<[u8; 32], didcomm::messaging::MessageHandlerError> {
    let arr = val.get(field).and_then(|v| v.as_array()).ok_or_else(|| {
        didcomm::messaging::MessageHandlerError::InvalidMessage(format!("Missing {} field", field))
    })?;
    let mut buf = [0u8; 32];
    if arr.len() != 32 {
        return Err(didcomm::messaging::MessageHandlerError::InvalidMessage(
            format!("{} must be 32 bytes", field),
        ));
    }
    for (i, v) in arr.iter().enumerate() {
        buf[i] = v.as_u64().unwrap_or(0) as u8;
    }
    Ok(buf)
}

#[async_trait::async_trait]
impl didcomm::messaging::MessageHandler for BatchTransferHandler {
    fn supported_types(&self) -> Vec<String> {
        vec![
            PIURI_BATCH_COMMIT.to_string(),
            PIURI_BATCH_ACK.to_string(),
            PIURI_BATCH_REVEAL.to_string(),
            PIURI_BATCH_DONE.to_string(),
        ]
    }

    async fn handle(
        &self,
        inbound: didcomm::messaging::InboundMessage,
    ) -> std::result::Result<
        Option<didcomm::messaging::OutboundMessage>,
        didcomm::messaging::MessageHandlerError,
    > {
        tracing::debug!(
            "[eCash-HANDLER] handle() called, msg_type={}, from={:?}, to={:?}",
            inbound.message.msg_type,
            inbound.context.from,
            inbound.context.to
        );

        match inbound.message.msg_type.as_str() {
            // Message 1: Batch Commit (receiver side)
            PIURI_BATCH_COMMIT => {
                tracing::debug!("[eCash-RX] Batch-commit received — processing...");
                let body = &inbound.message.body;
                let commit_json_str =
                    body.get("commit").and_then(|v| v.as_str()).ok_or_else(|| {
                        didcomm::messaging::MessageHandlerError::InvalidMessage(
                            "Missing commit in batch-commit".to_string(),
                        )
                    })?;

                let commit: serde_json::Value =
                    serde_json::from_str(commit_json_str).map_err(|e| {
                        didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                            "Invalid commit JSON: {}",
                            e
                        ))
                    })?;

                // Extract batch_id
                let batch_id = parse_32_from_json(&commit, "batch_id")?;

                // Extract total_amount
                let total_amount = commit
                    .get("total_amount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u128;

                // Extract note count
                let note_count = commit
                    .get("notes")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);

                // Validate total_amount == sum of notes[].amount
                if let Some(notes_arr) = commit.get("notes").and_then(|v| v.as_array()) {
                    let sum: u128 = notes_arr
                        .iter()
                        .map(|n| n.get("amount").and_then(|a| a.as_u64()).unwrap_or(0) as u128)
                        .sum();
                    if sum != total_amount {
                        return Err(didcomm::messaging::MessageHandlerError::InvalidMessage(
                            format!("total_amount {} != sum of notes {}", total_amount, sum),
                        ));
                    }
                }

                // Generate ONE SE key for the entire batch
                let se = self.se_provider.as_ref().ok_or_else(|| {
                    didcomm::messaging::MessageHandlerError::ProcessingFailed(
                        "Secure Key Store not available — cannot receive eCash without hardware security".to_string(),
                    )
                })?;
                let label = format!("ecash-rx-batch-{}", hex::encode(&batch_id[..8]));
                let receiver_spend_pk = se.generate_key(&label).await.map_err(|e| {
                    didcomm::messaging::MessageHandlerError::ProcessingFailed(format!(
                        "SE key generation failed: {}",
                        e
                    ))
                })?;

                // Store pending state
                {
                    let mut pending = self.pending.write().await;
                    pending.insert(
                        batch_id,
                        PendingBatchTransfer::CommitReceived {
                            commit_json: commit_json_str.to_string(),
                            ts: now_ms(),
                            rx_se_label: label.clone(),
                            rx_se_pk: receiver_spend_pk,
                        },
                    );
                }

                // Sign ACK with DID Ed25519 key for non-repudiation
                let timestamp_ms = now_ms();
                let mut ack_body = serde_json::json!({
                    "batch_id": hex::encode(batch_id),
                    "receiver_spend_pk": hex::encode(receiver_spend_pk),
                    "timestamp_ms": timestamp_ms,
                });

                if let Some(ref signer) = self.did_signer {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"AJNA/ECASH/BATCH-ACK/V1");
                    hasher.update(&batch_id);
                    hasher.update(&receiver_spend_pk);
                    hasher.update(&timestamp_ms.to_le_bytes());
                    let msg_hash = hasher.finalize();

                    match signer.sign_with_did(msg_hash.as_bytes()).await {
                        Ok((sig, did)) => {
                            ack_body["ack_sig"] = serde_json::Value::String(hex::encode(&sig));
                            ack_body["receiver_did"] = serde_json::Value::String(did);
                            tracing::debug!("[eCash-RX] ACK signed with DID Ed25519 key");
                        }
                        Err(e) => {
                            tracing::debug!(
                                "[eCash-RX] WARNING: DID signing failed: {}, sending unsigned ACK",
                                e
                            );
                        }
                    }
                }

                tracing::debug!(
                    "[eCash-RX] Batch commit stored, ACK sent (total_amount={}, note_count={})",
                    total_amount,
                    note_count
                );

                let sender_did = inbound.context.from.clone().unwrap_or_default();
                let our_did = inbound.context.to.clone().unwrap_or_default();
                let response_message = didcomm::core::Message::new(
                    uuid::Uuid::new_v4().to_string(),
                    PIURI_BATCH_ACK.to_string(),
                    ack_body,
                );

                let response = didcomm::messaging::OutboundMessage {
                    message: response_message,
                    to: sender_did,
                    from: our_did,
                    connection_id: inbound.context.connection_id.clone(),
                };

                Ok(Some(response))
            }

            // Message 2: Batch ACK (sender side)
            PIURI_BATCH_ACK => {
                tracing::debug!(
                    "[eCash-RX] Batch-ack received, handler self={:p}",
                    self as *const Self
                );
                let body = &inbound.message.body;
                tracing::debug!(
                    "[eCash-RX] ACK body: {}",
                    serde_json::to_string(body).unwrap_or_default()
                );

                // Extract batch_id (hex-encoded 32 bytes)
                let batch_id_hex =
                    body.get("batch_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            didcomm::messaging::MessageHandlerError::InvalidMessage(
                                "Missing batch_id in ACK body".to_string(),
                            )
                        })?;
                let batch_id_bytes = hex::decode(batch_id_hex).map_err(|e| {
                    didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                        "Invalid batch_id hex: {}",
                        e
                    ))
                })?;
                let mut batch_id = [0u8; 32];
                if batch_id_bytes.len() != 32 {
                    return Err(didcomm::messaging::MessageHandlerError::InvalidMessage(
                        "batch_id must be 32 bytes".to_string(),
                    ));
                }
                batch_id.copy_from_slice(&batch_id_bytes);

                // Extract receiver_spend_pk (hex-encoded 33 bytes)
                let spend_pk_hex = body
                    .get("receiver_spend_pk")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        didcomm::messaging::MessageHandlerError::InvalidMessage(
                            "Missing receiver_spend_pk in ACK body".to_string(),
                        )
                    })?;
                let spend_pk_bytes = hex::decode(spend_pk_hex).map_err(|e| {
                    didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                        "Invalid receiver_spend_pk hex: {}",
                        e
                    ))
                })?;
                let mut receiver_spend_pk = [0u8; 33];
                if spend_pk_bytes.len() != 33 {
                    return Err(didcomm::messaging::MessageHandlerError::InvalidMessage(
                        "receiver_spend_pk must be 33 bytes".to_string(),
                    ));
                }
                receiver_spend_pk.copy_from_slice(&spend_pk_bytes);

                // Extract optional DID signature
                let ack_sig = body
                    .get("ack_sig")
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .unwrap_or_default();
                let receiver_did = body
                    .get("receiver_did")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if !ack_sig.is_empty() {
                    tracing::debug!(
                        "[eCash-RX] ACK includes DID signature from {}",
                        receiver_did
                    );
                }

                // Transition: Committed → AckReceived
                {
                    let mut pending = self.pending.write().await;
                    tracing::debug!(
                        "[eCash-RX] ACK lookup: batch_id={}, pending_count={}, pending_keys=[{}]",
                        hex::encode(batch_id),
                        pending.len(),
                        pending
                            .keys()
                            .map(|k| hex::encode(&k[..8]))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    if let Some(PendingBatchTransfer::Committed {
                        preimages,
                        note_serials,
                        sender_se_labels,
                        sender_se_pks,
                        ts,
                    }) = pending.remove(&batch_id)
                    {
                        pending.insert(
                            batch_id,
                            PendingBatchTransfer::AckReceived {
                                preimages,
                                note_serials,
                                receiver_spend_pk,
                                sender_se_labels,
                                sender_se_pks,
                                ack_sig,
                                receiver_did,
                                ts,
                            },
                        );
                    } else {
                        return Err(didcomm::messaging::MessageHandlerError::ProcessingFailed(
                            "No pending batch commit for this ACK".to_string(),
                        ));
                    }
                }

                self.ack_notify.notify_one();
                tracing::debug!("[eCash-RX] ACK processed, ready for reveal");
                Ok(None)
            }

            // Message 3: Batch Reveal (receiver side)
            PIURI_BATCH_REVEAL => {
                tracing::debug!("[eCash-RX] Batch-reveal received");
                let body = &inbound.message.body;
                let reveal_json_str =
                    body.get("reveal").and_then(|v| v.as_str()).ok_or_else(|| {
                        didcomm::messaging::MessageHandlerError::InvalidMessage(
                            "Missing reveal in batch-reveal".to_string(),
                        )
                    })?;

                let reveal: serde_json::Value =
                    serde_json::from_str(reveal_json_str).map_err(|e| {
                        didcomm::messaging::MessageHandlerError::InvalidMessage(format!(
                            "Invalid reveal JSON: {}",
                            e
                        ))
                    })?;

                // Extract batch_id to look up pending state
                let batch_id = parse_32_from_json(&reveal, "batch_id")?;

                // Look up the pending commit (peek, don't remove yet)
                let (commit_json, rx_se_label, rx_se_pk) = {
                    let pending = self.pending.read().await;
                    match pending.get(&batch_id) {
                        Some(PendingBatchTransfer::CommitReceived {
                            commit_json,
                            rx_se_label,
                            rx_se_pk,
                            ..
                        }) => (commit_json.clone(), rx_se_label.clone(), *rx_se_pk),
                        _ => {
                            return Err(didcomm::messaging::MessageHandlerError::ProcessingFailed(
                                "No pending batch commit for this reveal".to_string(),
                            ));
                        }
                    }
                };

                // Build combined envelope for the NoteReceiver (FFI layer)
                let transfer_json = serde_json::json!({
                    "batch": true,
                    "commit": serde_json::from_str::<serde_json::Value>(&commit_json)
                        .unwrap_or(serde_json::Value::Null),
                    "reveal": reveal,
                    "rx_se_label": rx_se_label,
                    "rx_se_pk": hex::encode(rx_se_pk),
                });

                let sender_did = inbound.context.from.clone().unwrap_or_default();
                let our_did = inbound.context.to.clone().unwrap_or_default();

                match self
                    .receiver
                    .receive_batch_json(&transfer_json.to_string())
                    .await
                {
                    Ok(()) => {
                        // Success — NOW remove pending state
                        self.pending.write().await.remove(&batch_id);
                        tracing::debug!("[eCash-RX] Batch reveal processed, notes added to wallet — sending DONE");

                        let done_body = serde_json::json!({
                            "batch_id": batch_id.to_vec(),
                            "status": "done",
                        });
                        let done_message = didcomm::core::Message::new(
                            uuid::Uuid::new_v4().to_string(),
                            PIURI_BATCH_DONE.to_string(),
                            done_body,
                        );
                        Ok(Some(didcomm::messaging::OutboundMessage {
                            message: done_message,
                            to: sender_did,
                            from: our_did,
                            connection_id: inbound.context.connection_id.clone(),
                        }))
                    }
                    Err(e) => {
                        tracing::debug!(
                            "[eCash-RX] Batch reveal processing FAILED: {} — sending NACK",
                            e
                        );

                        let nack_body = serde_json::json!({
                            "batch_id": batch_id.to_vec(),
                            "status": "nack",
                            "reason": e,
                        });
                        let nack_message = didcomm::core::Message::new(
                            uuid::Uuid::new_v4().to_string(),
                            PIURI_BATCH_DONE.to_string(),
                            nack_body,
                        );
                        Ok(Some(didcomm::messaging::OutboundMessage {
                            message: nack_message,
                            to: sender_did,
                            from: our_did,
                            connection_id: inbound.context.connection_id.clone(),
                        }))
                    }
                }
            }

            // Message 4: Done/Nack (sender side)
            PIURI_BATCH_DONE => {
                let body = &inbound.message.body;
                let status = body
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("done");

                let batch_id = parse_32_from_json(body, "batch_id")?;

                let result = if status == "nack" {
                    let reason = body
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    tracing::debug!("[eCash-RX] Batch NACK received: {}", reason);
                    TransferDoneResult::Nack(reason)
                } else {
                    tracing::debug!("[eCash-RX] Batch DONE received — receiver confirmed");
                    TransferDoneResult::Done
                };

                self.done_confirmations
                    .write()
                    .await
                    .insert(batch_id, result);
                self.done_notify.notify_one();
                Ok(None)
            }

            other => {
                tracing::debug!("[eCash-RX] Unknown message type: {}", other);
                Err(didcomm::messaging::MessageHandlerError::InvalidMessage(
                    format!("Unknown message type: {}", other),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm::messaging::MessageHandler;
    use std::sync::Mutex;

    /// Mock NoteReceiver that records calls
    struct MockReceiver {
        received: Mutex<Vec<String>>,
        should_fail: bool,
    }

    impl MockReceiver {
        fn new() -> Self {
            Self {
                received: Mutex::new(vec![]),
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                received: Mutex::new(vec![]),
                should_fail: true,
            }
        }
    }

    #[async_trait::async_trait]
    impl NoteReceiver for MockReceiver {
        async fn receive_batch_json(&self, batch_json: &str) -> Result<(), String> {
            if self.should_fail {
                return Err("Mock failure".to_string());
            }
            self.received.lock().unwrap().push(batch_json.to_string());
            Ok(())
        }
    }

    // =========================================================================
    // BatchTransferHandler Tests
    // =========================================================================

    struct MockSEProvider {
        pk: [u8; 33],
    }

    impl MockSEProvider {
        fn new() -> Self {
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1] = 0x42;
            Self { pk }
        }
    }

    #[async_trait::async_trait]
    impl SecureKeyProvider for MockSEProvider {
        async fn generate_key(&self, _label: &str) -> Result<[u8; 33], String> {
            Ok(self.pk)
        }
    }

    struct MockDidSigner {
        did: String,
    }

    impl MockDidSigner {
        fn new(did: &str) -> Self {
            Self {
                did: did.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl DidSigner for MockDidSigner {
        async fn sign_with_did(&self, data: &[u8]) -> Result<(Vec<u8>, String), String> {
            Ok((blake3::hash(data).as_bytes().to_vec(), self.did.clone()))
        }
    }

    // ── Test helpers ──────────────────────────────────────────────────

    fn make_inbound(
        msg_type: &str,
        body: serde_json::Value,
        from: &str,
        to: &str,
    ) -> didcomm::messaging::InboundMessage {
        let message = didcomm::core::Message {
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: msg_type.to_string(),
            body,
            from: Some(from.to_string()),
            to: Some(vec![to.to_string()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        };
        let context = didcomm::messaging::MessageContext {
            from: Some(from.to_string()),
            to: Some(to.to_string()),
            thread_id: None,
            parent_thread_id: None,
            connection_id: None,
            encrypted: false,
            authenticated: false,
            sender_endpoint: None,
        };
        didcomm::messaging::InboundMessage { message, context }
    }

    /// Build a BATCH_COMMIT message body
    fn mock_batch_commit_body(batch_id: [u8; 32], amount: u128) -> serde_json::Value {
        let batch_id_vec: Vec<u8> = batch_id.to_vec();
        let mock_commitment: Vec<u8> = vec![0xCCu8; 32];
        let mock_encrypted: Vec<u8> = vec![0xEEu8; 48];
        let commit_obj = serde_json::json!({
            "batch_id": batch_id_vec,
            "total_amount": amount,
            "notes": [{
                "commitment": mock_commitment,
                "encrypted_note": mock_encrypted,
                "amount": amount,
            }],
            "timestamp_ms": now_ms(),
            "payer_did": "did:ajna:alice",
            "payee_did": "did:ajna:bob",
        });
        serde_json::json!({"commit": serde_json::to_string(&commit_obj).unwrap()})
    }

    /// Build a BATCH_REVEAL message body
    fn mock_batch_reveal_body(batch_id: [u8; 32], preimage: [u8; 32]) -> serde_json::Value {
        let batch_id_vec: Vec<u8> = batch_id.to_vec();
        let mock_commitment: Vec<u8> = vec![0xCCu8; 32];
        let preimage_vec: Vec<u8> = preimage.to_vec();
        let zero_sig: Vec<u8> = vec![0u8; 64];
        let zero_pk: Vec<u8> = vec![0u8; 33];
        let zero_commitment: Vec<u8> = vec![0u8; 32];
        let reveal_obj = serde_json::json!({
            "batch_id": batch_id_vec,
            "notes": [{
                "commitment": mock_commitment,
                "preimage": preimage_vec,
                "spend_transfer": {
                    "transfer_sig": zero_sig,
                    "sender_pk": zero_pk,
                    "new_commitment": zero_commitment,
                },
            }],
        });
        serde_json::json!({"reveal": serde_json::to_string(&reveal_obj).unwrap()})
    }

    // ── Unit tests ──────────────────────────────────────────────────

    #[test]
    fn test_batch_handler_supported_types() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);
        let types = handler.supported_types();

        assert_eq!(types.len(), 4);
        assert!(types.contains(&PIURI_BATCH_COMMIT.to_string()));
        assert!(types.contains(&PIURI_BATCH_ACK.to_string()));
        assert!(types.contains(&PIURI_BATCH_REVEAL.to_string()));
        assert!(types.contains(&PIURI_BATCH_DONE.to_string()));
    }

    #[tokio::test]
    async fn test_batch_register_pending() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let batch_id = [1u8; 32];
        handler
            .register_pending_batch(
                batch_id,
                vec![[2u8; 32]],
                vec![[3u8; 32]],
                vec!["ecash-mint-test".to_string()],
                vec![[0x02; 33]],
            )
            .await;

        let result = handler.take_ack(&batch_id).await;
        assert!(
            result.is_none(),
            "Committed state should not match take_ack"
        );
    }

    #[tokio::test]
    async fn test_batch_take_ack_empty() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let result = handler.take_ack(&[99u8; 32]).await;
        assert!(result.is_none(), "No pending = None");
    }

    #[tokio::test]
    async fn test_batch_prune_expired() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        handler
            .register_pending_batch(
                [1u8; 32],
                vec![[2u8; 32]],
                vec![[3u8; 32]],
                vec!["test".to_string()],
                vec![[0x02; 33]],
            )
            .await;

        {
            let pending = handler.pending.read().await;
            assert_eq!(pending.len(), 1);
        }

        handler.prune_expired().await;
        {
            let pending = handler.pending.read().await;
            assert_eq!(pending.len(), 1, "Fresh entry should not be pruned");
        }
    }

    #[tokio::test]
    async fn test_batch_handler_commit_missing_field() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let message = didcomm::core::Message {
            id: "bad-commit".to_string(),
            msg_type: PIURI_BATCH_COMMIT.to_string(),
            body: serde_json::json!({}),
            from: Some("did:ajna:sender".to_string()),
            to: Some(vec!["did:ajna:receiver".to_string()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: std::collections::HashMap::new(),
        };

        let context = didcomm::messaging::MessageContext {
            from: Some("did:ajna:sender".to_string()),
            to: Some("did:ajna:receiver".to_string()),
            thread_id: None,
            parent_thread_id: None,
            connection_id: None,
            encrypted: false,
            authenticated: false,
            sender_endpoint: None,
        };

        let inbound = didcomm::messaging::InboundMessage { message, context };
        let result = handler.handle(inbound).await;

        assert!(result.is_err(), "Missing commit field must error");
    }

    #[tokio::test]
    async fn test_batch_handler_unknown_type() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let inbound = make_inbound(
            "https://ajna.network/ecash/1.0/bogus",
            serde_json::json!({}),
            "did:ajna:sender",
            "did:ajna:receiver",
        );
        let result = handler.handle(inbound).await;

        assert!(result.is_err(), "Unknown message type must error");
    }

    #[tokio::test]
    async fn test_batch_handler_ack_without_commit() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let inbound = make_inbound(
            PIURI_BATCH_ACK,
            serde_json::json!({
                "batch_id": hex::encode([0u8; 32]),
                "receiver_spend_pk": hex::encode([0u8; 33]),
                "timestamp_ms": 0u64,
            }),
            "did:ajna:receiver",
            "did:ajna:sender",
        );
        let result = handler.handle(inbound).await;

        assert!(result.is_err(), "ACK without prior commit must fail");
    }

    #[tokio::test]
    async fn test_batch_handler_reveal_without_commit() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let inbound = make_inbound(
            PIURI_BATCH_REVEAL,
            mock_batch_reveal_body([0u8; 32], [0u8; 32]),
            "did:ajna:sender",
            "did:ajna:receiver",
        );
        let result = handler.handle(inbound).await;

        assert!(result.is_err(), "Reveal without prior commit must fail");
    }

    // ── E2E Protocol Flow Tests ───────────────────────────────────────

    /// Full 4-message batch flow: COMMIT → ACK → REVEAL → DONE
    #[tokio::test]
    async fn test_batch_full_flow_two_handlers() {
        let batch_id = [7u8; 32];
        let preimage = [42u8; 32];

        // Alice = sender, Bob = receiver
        let alice_receiver = Arc::new(MockReceiver::new());
        let alice_handler = BatchTransferHandler::new(alice_receiver.clone(), None, None);

        let bob_receiver = Arc::new(MockReceiver::new());
        let bob_se = Arc::new(MockSEProvider::new());
        let bob_handler = BatchTransferHandler::new(
            bob_receiver.clone(),
            Some(bob_se.clone() as Arc<dyn SecureKeyProvider>),
            None,
        );

        // Step 1: Alice registers pending batch (sender side)
        alice_handler
            .register_pending_batch(
                batch_id,
                vec![preimage],
                vec![[1u8; 32]],
                vec!["ecash-test".to_string()],
                vec![[0x02; 33]],
            )
            .await;
        assert_eq!(alice_handler.pending_count().await, 1);

        // Step 2: Bob receives BATCH_COMMIT → returns BATCH_ACK
        let commit_body = mock_batch_commit_body(batch_id, 1_000_000_000_000_000_000);
        let commit_inbound = make_inbound(
            PIURI_BATCH_COMMIT,
            commit_body,
            "did:ajna:alice",
            "did:ajna:bob",
        );
        let ack_result = bob_handler.handle(commit_inbound).await;
        let ack_outbound = ack_result
            .expect("COMMIT must succeed")
            .expect("COMMIT must return ACK");
        assert_eq!(ack_outbound.message.msg_type, PIURI_BATCH_ACK);
        assert_eq!(ack_outbound.to, "did:ajna:alice");
        assert_eq!(ack_outbound.from, "did:ajna:bob");
        assert_eq!(bob_handler.pending_count().await, 1);

        // Step 3: Alice receives ACK → state transitions to AckReceived
        let ack_inbound = make_inbound(
            PIURI_BATCH_ACK,
            ack_outbound.message.body.clone(),
            "did:ajna:bob",
            "did:ajna:alice",
        );
        let ack_handle = alice_handler.handle(ack_inbound).await;
        assert!(
            ack_handle.expect("ACK must succeed").is_none(),
            "ACK returns no response"
        );

        // Step 4: Alice takes ACK data
        let ack_data = alice_handler.take_ack(&batch_id).await;
        assert!(ack_data.is_some(), "ACK data must be available");
        let ack = ack_data.unwrap();
        assert_eq!(ack.preimages, vec![preimage]);
        assert_eq!(ack.receiver_spend_pk, bob_se.pk);
        assert_eq!(alice_handler.pending_count().await, 0);

        // Step 5: Bob receives REVEAL → NoteReceiver called, returns DONE
        let reveal_body = mock_batch_reveal_body(batch_id, preimage);
        let reveal_inbound = make_inbound(
            PIURI_BATCH_REVEAL,
            reveal_body,
            "did:ajna:alice",
            "did:ajna:bob",
        );
        let reveal_result = bob_handler.handle(reveal_inbound).await;
        let done_outbound = reveal_result.expect("REVEAL must succeed");
        assert!(done_outbound.is_some(), "REVEAL must return DONE message");
        let done_msg = done_outbound.unwrap();
        assert_eq!(done_msg.message.msg_type, PIURI_BATCH_DONE);
        assert_eq!(done_msg.message.body["status"], "done");
        assert_eq!(bob_handler.pending_count().await, 0);

        // Verify: MockReceiver got exactly one call with batch envelope
        let received = bob_receiver.received.lock().unwrap();
        assert_eq!(
            received.len(),
            1,
            "Bob must receive exactly 1 batch transfer"
        );
        let envelope: serde_json::Value = serde_json::from_str(&received[0]).unwrap();
        assert_eq!(envelope["batch"], true);
        assert!(envelope["commit"].is_object(), "commit must be an object");
        assert!(envelope["reveal"].is_object(), "reveal must be an object");

        // Verify: Alice's receiver was never called
        assert_eq!(alice_receiver.received.lock().unwrap().len(), 0);
    }

    /// Full flow with DID signer — verifies ACK includes signature
    #[tokio::test]
    async fn test_batch_full_flow_with_did_signer() {
        let batch_id = [11u8; 32];
        let preimage = [22u8; 32];

        let alice_handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);
        let bob_receiver = Arc::new(MockReceiver::new());
        let bob_handler = BatchTransferHandler::new(
            bob_receiver.clone(),
            Some(Arc::new(MockSEProvider::new()) as Arc<dyn SecureKeyProvider>),
            Some(Arc::new(MockDidSigner::new("did:ajna:bob")) as Arc<dyn DidSigner>),
        );

        alice_handler
            .register_pending_batch(
                batch_id,
                vec![preimage],
                vec![[1u8; 32]],
                vec!["test".to_string()],
                vec![[0x02; 33]],
            )
            .await;

        // Bob handles COMMIT → ACK with DID signature
        let ack_outbound = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id, 100),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap()
            .unwrap();

        let ack_body = &ack_outbound.message.body;
        let ack_sig_hex = ack_body["ack_sig"]
            .as_str()
            .expect("ack_sig must be present");
        assert!(!ack_sig_hex.is_empty());
        assert_eq!(ack_body["receiver_did"].as_str().unwrap(), "did:ajna:bob");

        // Alice handles ACK
        alice_handler
            .handle(make_inbound(
                PIURI_BATCH_ACK,
                ack_body.clone(),
                "did:ajna:bob",
                "did:ajna:alice",
            ))
            .await
            .unwrap();

        let ack_data = alice_handler.take_ack(&batch_id).await.unwrap();
        assert!(!ack_data.ack_sig.is_empty());
        assert_eq!(ack_data.receiver_did, "did:ajna:bob");

        // Complete with REVEAL
        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                mock_batch_reveal_body(batch_id, preimage),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();
        assert_eq!(bob_receiver.received.lock().unwrap().len(), 1);
    }

    /// No SE provider → COMMIT handling must fail
    #[tokio::test]
    async fn test_batch_commit_fails_without_se() {
        let batch_id = [33u8; 32];

        let bob_handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);

        let result = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id, 100),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await;

        assert!(result.is_err(), "COMMIT must fail without SE provider");
        let err = result.unwrap_err();
        assert!(format!("{:?}", err).contains("Secure Key Store not available"));
    }

    /// REVEAL with failing NoteReceiver returns NACK
    #[tokio::test]
    async fn test_batch_reveal_receiver_failure() {
        let batch_id = [55u8; 32];
        let preimage = [66u8; 32];

        let bob_handler = BatchTransferHandler::new(
            Arc::new(MockReceiver::failing()),
            Some(Arc::new(MockSEProvider::new()) as Arc<dyn SecureKeyProvider>),
            None,
        );

        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id, 100),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();

        let result = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                mock_batch_reveal_body(batch_id, preimage),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await;

        let nack_outbound = result.expect("REVEAL must return NACK, not error");
        assert!(nack_outbound.is_some());
        let nack_msg = nack_outbound.unwrap();
        assert_eq!(nack_msg.message.msg_type, PIURI_BATCH_DONE);
        assert_eq!(nack_msg.message.body["status"], "nack");
        let reason = nack_msg.message.body["reason"].as_str().unwrap_or("");
        assert!(reason.contains("Mock failure"));

        // Pending still exists (kept for retry)
        assert_eq!(bob_handler.pending_count().await, 1);
    }

    /// Duplicate REVEAL is rejected (replay protection)
    #[tokio::test]
    async fn test_batch_duplicate_reveal_rejected() {
        let batch_id = [77u8; 32];
        let preimage = [88u8; 32];

        let bob_receiver = Arc::new(MockReceiver::new());
        let bob_handler = BatchTransferHandler::new(
            bob_receiver.clone(),
            Some(Arc::new(MockSEProvider::new()) as Arc<dyn SecureKeyProvider>),
            None,
        );

        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id, 100),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();

        // First REVEAL succeeds
        let reveal_body = mock_batch_reveal_body(batch_id, preimage);
        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                reveal_body.clone(),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();
        assert_eq!(bob_receiver.received.lock().unwrap().len(), 1);

        // Second REVEAL rejected
        let dup_result = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                reveal_body,
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await;
        assert!(dup_result.is_err(), "Duplicate REVEAL must be rejected");
        assert_eq!(bob_receiver.received.lock().unwrap().len(), 1);
    }

    /// Two concurrent batch transfers
    #[tokio::test]
    async fn test_batch_concurrent_transfers() {
        let batch_id_a = [10u8; 32];
        let preimage_a = [20u8; 32];
        let batch_id_b = [30u8; 32];
        let preimage_b = [40u8; 32];

        let alice_handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);
        let bob_receiver = Arc::new(MockReceiver::new());
        let bob_handler = BatchTransferHandler::new(
            bob_receiver.clone(),
            Some(Arc::new(MockSEProvider::new()) as Arc<dyn SecureKeyProvider>),
            None,
        );

        alice_handler
            .register_pending_batch(
                batch_id_a,
                vec![preimage_a],
                vec![[1u8; 32]],
                vec!["a".to_string()],
                vec![[0x02; 33]],
            )
            .await;
        alice_handler
            .register_pending_batch(
                batch_id_b,
                vec![preimage_b],
                vec![[2u8; 32]],
                vec!["b".to_string()],
                vec![[0x02; 33]],
            )
            .await;
        assert_eq!(alice_handler.pending_count().await, 2);

        let ack_a = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id_a, 100),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap()
            .unwrap();
        let ack_b = bob_handler
            .handle(make_inbound(
                PIURI_BATCH_COMMIT,
                mock_batch_commit_body(batch_id_b, 200),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bob_handler.pending_count().await, 2);

        alice_handler
            .handle(make_inbound(
                PIURI_BATCH_ACK,
                ack_a.message.body,
                "did:ajna:bob",
                "did:ajna:alice",
            ))
            .await
            .unwrap();
        alice_handler
            .handle(make_inbound(
                PIURI_BATCH_ACK,
                ack_b.message.body,
                "did:ajna:bob",
                "did:ajna:alice",
            ))
            .await
            .unwrap();

        assert!(alice_handler.take_ack(&batch_id_a).await.is_some());
        assert!(alice_handler.take_ack(&batch_id_b).await.is_some());
        assert_eq!(alice_handler.pending_count().await, 0);

        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                mock_batch_reveal_body(batch_id_a, preimage_a),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();
        bob_handler
            .handle(make_inbound(
                PIURI_BATCH_REVEAL,
                mock_batch_reveal_body(batch_id_b, preimage_b),
                "did:ajna:alice",
                "did:ajna:bob",
            ))
            .await
            .unwrap();

        let received_len = bob_receiver.received.lock().unwrap().len();
        assert_eq!(received_len, 2);
        assert_eq!(bob_handler.pending_count().await, 0);
    }

    /// wait_for_ack returns instantly when ACK arrives
    #[tokio::test]
    async fn test_wait_for_ack_instant() {
        let batch_id = [77u8; 32];
        let preimage = [88u8; 32];

        let handler = Arc::new(BatchTransferHandler::new(
            Arc::new(MockReceiver::new()),
            Some(Arc::new(MockSEProvider::new()) as Arc<dyn SecureKeyProvider>),
            None,
        ));

        handler
            .register_pending_batch(
                batch_id,
                vec![preimage],
                vec![[1u8; 32]],
                vec!["se-key".to_string()],
                vec![[0x02; 33]],
            )
            .await;

        let h = handler.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let ack_body = serde_json::json!({
                "batch_id": hex::encode(batch_id),
                "receiver_spend_pk": hex::encode([0x03u8; 33]),
                "timestamp_ms": 12345u64,
            });
            h.handle(make_inbound(
                PIURI_BATCH_ACK,
                ack_body,
                "did:ajna:bob",
                "did:ajna:alice",
            ))
            .await
            .unwrap();
        });

        let start = std::time::Instant::now();
        let ack = handler.wait_for_ack(&batch_id, 5).await;
        let elapsed = start.elapsed();

        assert!(ack.is_some(), "ACK must be received");
        assert!(
            elapsed.as_millis() < 500,
            "Should return in <500ms, got {}ms",
            elapsed.as_millis()
        );
    }

    /// wait_for_ack returns None on timeout
    #[tokio::test]
    async fn test_wait_for_ack_timeout() {
        let handler = BatchTransferHandler::new(Arc::new(MockReceiver::new()), None, None);
        let batch_id = [99u8; 32];
        handler
            .register_pending_batch(
                batch_id,
                vec![[0u8; 32]],
                vec![[0u8; 32]],
                vec![String::new()],
                vec![[0u8; 33]],
            )
            .await;

        let start = std::time::Instant::now();
        let ack = handler.wait_for_ack(&batch_id, 1).await;
        let elapsed = start.elapsed();

        assert!(ack.is_none(), "Must timeout with None");
        assert!(elapsed.as_secs() >= 1, "Must wait at least 1s");
        assert!(
            elapsed.as_secs() < 3,
            "Must not wait much longer than timeout"
        );
    }

    /// wait_for_done returns instantly when DONE arrives
    #[tokio::test]
    async fn test_wait_for_done_instant() {
        let batch_id = [55u8; 32];

        let handler = Arc::new(BatchTransferHandler::new(
            Arc::new(MockReceiver::new()),
            None,
            None,
        ));

        let h = handler.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let done_body = serde_json::json!({
                "batch_id": batch_id.to_vec(),
                "status": "done",
            });
            h.handle(make_inbound(
                PIURI_BATCH_DONE,
                done_body,
                "did:ajna:bob",
                "did:ajna:alice",
            ))
            .await
            .unwrap();
        });

        let start = std::time::Instant::now();
        let result = handler.wait_for_done(&batch_id, 5).await;
        let elapsed = start.elapsed();

        assert!(matches!(result, Some(TransferDoneResult::Done)));
        assert!(
            elapsed.as_millis() < 500,
            "Should return in <500ms, got {}ms",
            elapsed.as_millis()
        );
    }
}
