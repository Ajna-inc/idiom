//! Message Encryption and Decryption
//!
//! Handles DIDComm message packing (v1 and v2) and unpacking.
//!
//! `pack_encrypted_message` is the canonical entry point used by every
//! protocol-level outbound sender (basic_messages, workflow, presence,
//! files, rooms, …). It auto-selects DIDComm v1 vs v2 based on the
//! recipient's DID method, so individual protocol packages never need
//! to know which wire version they're speaking.

use crate::crypto::KeyExtractor;
use crate::error::{AgentError, Result};
use crate::messaging::pack_message_v1;
use agent_core::traits::WalletProvider;
use did::core::DidRepository;
use didcomm::core::version::{DIDCommVersion, PackOptions};
use didcomm::core::{capability_detector::CapabilityDetector, EnvelopeService, Message};
use didcomm::messaging::DidCommDocumentService;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Message encryption service
///
/// Handles DIDComm message packing (v1 and v2 — selected automatically per
/// recipient via `CapabilityDetector`) and unpacking.
pub struct MessageEncryption {
    wallet_provider: Arc<dyn WalletProvider>,
    did_document_service: Arc<DidCommDocumentService>,
    did_repository: Arc<DidRepository>,
    agent_did: Arc<RwLock<Option<String>>>,
    agent_key_id: Arc<RwLock<Option<String>>>,
    /// Optional version-aware envelope service. When wired (after
    /// `Agent::initialize()`), `pack_encrypted_message` will route
    /// v2-capable peers through `pack_encrypted_with_version` instead
    /// of the hardcoded v1 path. None during early bring-up keeps
    /// behaviour identical to the pre-refactor v1-only world.
    envelope_service: RwLock<Option<Arc<EnvelopeService>>>,
}

impl MessageEncryption {
    /// Create a new message encryption service
    pub fn new(
        wallet_provider: Arc<dyn WalletProvider>,
        did_document_service: Arc<DidCommDocumentService>,
        did_repository: Arc<DidRepository>,
        agent_did: Arc<RwLock<Option<String>>>,
        agent_key_id: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            wallet_provider,
            did_document_service,
            did_repository,
            agent_did,
            agent_key_id,
            envelope_service: RwLock::new(None),
        }
    }

    /// Wire the version-aware envelope service after `Agent::initialize()`.
    ///
    /// Mirrors the same setter pattern used by `OobModule` and
    /// `MessageProcessor` so the bring-up order can stay the same.
    /// Until this is called, `pack_encrypted_message` falls back to
    /// the legacy v1-only path — that's the pre-refactor behaviour.
    pub async fn set_envelope_service(&self, envelope_service: Arc<EnvelopeService>) {
        let mut guard = self.envelope_service.write().await;
        *guard = Some(envelope_service);
    }

    /// Pack a message with DIDComm v1 encryption
    ///
    /// This uses didcomm::v1::pack_message to create a DIDComm v1 envelope
    /// with "Authcrypt" algorithm identifier.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (must be JSON serializable)
    /// * `recipient_did` - The recipient's DID (from OOB invitation recipient_keys)
    /// * `sender_did` - Our DID (for authcrypt)
    ///
    /// # Returns
    /// JWE-encrypted message as a JSON string
    pub async fn pack_encrypted_message(
        &self,
        message: &impl serde::Serialize,
        recipient_did: &str,
        sender_did: &str,
    ) -> Result<String> {
        // ── Version selection ─────────────────────────────────────────
        // Detect the recipient's DIDComm capabilities. did:peer:1, did:sov,
        // did:indy → v1-only (legacy). did:peer:2 / did:key → v2-capable.
        //
        // If the envelope service is wired (set by `Agent::initialize()`)
        // AND the peer's DID method advertises v2 support, route through
        // the version-aware path. Otherwise stay on the hardcoded v1 path
        // — this is the behaviour the codebase has had since day one and
        // keeps the did:peer:1 interop flows working identically.
        let env_svc_guard = self.envelope_service.read().await;
        let recipient_caps = CapabilityDetector::detect_from_did_string(recipient_did);
        if recipient_caps.supports_v2 {
            if let Some(env_svc) = env_svc_guard.clone() {
                drop(env_svc_guard);
                return self
                    .pack_via_envelope_service(env_svc, message, recipient_did, sender_did)
                    .await;
            }
        }
        drop(env_svc_guard);

        tracing::debug!("[DIDComm v1] Packing authcrypt");

        // Serialize the protocol message to Value
        let message_value = serde_json::to_value(message)
            .map_err(|e| AgentError::Transport(format!("Failed to serialize message: {}", e)))?;

        tracing::debug!(
            "[DIDComm v1] type={}",
            message_value
                .get("@type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );

        // Convert Value to HashMap<String, Value> for didcomm::v1::pack_message
        let message_map: HashMap<String, serde_json::Value> =
            serde_json::from_value(message_value.clone()).map_err(|e| {
                AgentError::Transport(format!("Failed to convert message to HashMap: {}", e))
            })?;

        // Extract BOTH recipient keys from DID
        let key_extractor = KeyExtractor::with_did_repository(
            self.did_document_service.clone(),
            self.wallet_provider.clone(),
            self.did_repository.clone(),
        );

        // 1. Ed25519 authentication key - used as `kid` in JWE (for wallet lookup)
        // 2. X25519 keyAgreement key - used for ECDH encryption
        let recipient_auth_key = key_extractor
            .extract_public_key_from_did(recipient_did)
            .await?;
        let recipient_encryption_key = key_extractor
            .extract_key_agreement_from_did(recipient_did)
            .await?;

        // DIAG: surface what the wallet decided to pack FOR. Lines up
        // with the mediator's `to=…` log so we can spot mismatches.
        // Gated behind tracing::debug! so production stderr stays clean
        // while still being available via `RUST_LOG=agent=debug`.
        tracing::debug!(
            target: "didcomm.diag",
            %recipient_did,
            %sender_did,
            %recipient_auth_key,
            %recipient_encryption_key,
            "pack_for"
        );

        tracing::trace!("[DIDComm v1] recipient auth_key and agreement_key resolved");

        // Find sender key in wallet
        let sender_key_id = self.find_sender_key(sender_did, &key_extractor).await?;
        tracing::trace!("[DIDComm v1] sender key resolved");

        // Pack with DIDComm v1 using shared helper
        let packed_json = pack_message_v1(
            &message_map,
            &recipient_auth_key,
            &recipient_encryption_key,
            &sender_key_id,
            self.wallet_provider.clone(),
        )
        .await?;

        tracing::debug!("[DIDComm v1] Packed authcrypt");

        Ok(packed_json)
    }

    /// Pack via the version-aware `EnvelopeService`.
    ///
    /// Called from `pack_encrypted_message` when the recipient's DID
    /// method advertises DIDComm v2 support (e.g. `did:peer:2`,
    /// `did:key`). We use `V2WithV1Fallback` so the envelope service
    /// itself can drop back to v1 if the recipient's resolved
    /// capabilities don't actually cover v2 — that way the caller
    /// (protocol packages) never has to handle the version question.
    ///
    /// Protocol messages today still serialise the legacy Aries
    /// top-level shape (`{"@type": …, "@id": …}`). We pass the whole
    /// JSON through as the v2 `body` envelope — `body`-style
    /// message classes read from there directly, and the conversion
    /// step in `EnvelopeService::convert_message_to_v1` flattens it
    /// back to top-level for v1 peers. So both wire formats stay
    /// readable without per-protocol changes.
    async fn pack_via_envelope_service(
        &self,
        env_svc: Arc<EnvelopeService>,
        message: &impl serde::Serialize,
        recipient_did: &str,
        sender_did: &str,
    ) -> Result<String> {
        let message_value = serde_json::to_value(message)
            .map_err(|e| AgentError::Transport(format!("Failed to serialize message: {}", e)))?;

        // Recover @type and @id so the envelope's outer `type`/`id`
        // fields are set correctly. Fall back to fresh UUID + the
        // serialised body's top-level `type` if anything is missing —
        // we'd rather pack with a generated id than fail outright.
        let msg_type = message_value
            .get("@type")
            .or_else(|| message_value.get("type"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::Transport("Message missing @type".into()))?
            .to_string();
        let msg_id = message_value
            .get("@id")
            .or_else(|| message_value.get("id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let mut didcomm_msg = Message::new(msg_id, msg_type, message_value);
        didcomm_msg.from = Some(sender_did.to_string());
        didcomm_msg.to = Some(vec![recipient_did.to_string()]);

        let pack_options = PackOptions {
            version: DIDCommVersion::V2WithV1Fallback,
            protect_sender: true,
            sign_message: false,
        };

        tracing::debug!(
            target: "didcomm.diag",
            %recipient_did,
            %sender_did,
            "pack_for (via EnvelopeService, version-aware)"
        );

        env_svc
            .pack_encrypted_with_version(
                &didcomm_msg,
                recipient_did,
                Some(sender_did),
                &pack_options,
            )
            .await
            .map_err(|e| AgentError::Transport(format!("EnvelopeService pack failed: {}", e)))
    }

    /// Decrypt a packed DIDComm message
    ///
    /// # Arguments
    /// * `packed_message` - The encrypted message (JWE format)
    ///
    /// # Returns
    /// Decrypted plaintext message as JSON string
    pub async fn decrypt_message(&self, packed_message: &str) -> Result<String> {
        use base64::Engine;

        // Detect if message is JWE format
        let is_jwe = if let Ok(json) = serde_json::from_str::<serde_json::Value>(packed_message) {
            json.get("protected").is_some()
                && json.get("iv").is_some()
                && json.get("ciphertext").is_some()
                && json.get("tag").is_some()
        } else {
            false
        };

        if is_jwe {
            tracing::debug!("[DIDComm] Decrypting JWE...");

            // Parse JWE to detect algorithm
            let jwe_json: serde_json::Value = serde_json::from_str(packed_message)
                .map_err(|e| AgentError::Transport(format!("Failed to parse JWE JSON: {}", e)))?;

            // Decode protected header to check algorithm
            let protected_b64 = jwe_json
                .get("protected")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AgentError::Transport("JWE missing protected header".to_string()))?;

            let protected_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(protected_b64)
                .map_err(|e| {
                    AgentError::Transport(format!("Failed to decode protected header: {}", e))
                })?;

            let protected_header: serde_json::Value = serde_json::from_slice(&protected_bytes)
                .map_err(|e| {
                    AgentError::Transport(format!("Failed to parse protected header: {}", e))
                })?;

            let alg = protected_header
                .get("alg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            // Use DIDComm v1 unpacking for "Authcrypt" or "Anoncrypt"
            if alg == "Authcrypt" || alg == "Anoncrypt" {
                tracing::debug!("[DIDComm v1] Unpacking {}", alg);

                // Parse as EncryptedMessage
                let encrypted: didcomm::v1::EncryptedMessage = serde_json::from_str(packed_message)
                    .map_err(|e| {
                        AgentError::Transport(format!("Failed to parse DIDComm v1 message: {}", e))
                    })?;

                // Unpack using DIDComm v1
                let (_message, metadata) =
                    didcomm::v1::unpack_message(&encrypted, self.wallet_provider.clone())
                        .await
                        .map_err(|e| {
                            AgentError::Transport(format!("DIDComm v1 decryption failed: {}", e))
                        })?;

                tracing::debug!("[DIDComm v1] Decrypted successfully");

                // Return the decrypted plaintext byte-for-byte as it came off
                // the wire (re-serializing the parsed map would reorder keys)
                Ok(metadata.raw_plaintext)
            } else {
                // ECDH-1PU+A256KW is DIDComm v2 - V1 fallback cannot handle it
                Err(AgentError::Transport(format!(
                    "V1 fallback cannot decrypt algorithm '{}' (this is a DIDComm v2 algorithm - V2 decryption failed earlier)",
                    alg
                )))
            }
        } else {
            // Message is plaintext
            Ok(packed_message.to_string())
        }
    }

    /// Pack a message with anonymous encryption (Anoncrypt)
    ///
    /// Used for Forward messages in mediation - no sender authentication.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (must be JSON serializable)
    /// * `recipient_did` - The recipient's DID (routing key)
    ///
    /// # Returns
    /// Anon-encrypted JWE message as a JSON string
    pub async fn pack_anon_message(
        &self,
        message: &impl serde::Serialize,
        recipient_did: &str,
    ) -> Result<String> {
        tracing::debug!("[DIDComm v1] Packing anoncrypt");

        // Serialize the protocol message to Value
        let message_value = serde_json::to_value(message)
            .map_err(|e| AgentError::Transport(format!("Failed to serialize message: {}", e)))?;

        tracing::debug!(
            "[DIDComm v1] type={}",
            message_value
                .get("@type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );

        // Convert Value to HashMap<String, Value> for didcomm_v1 packing
        let message_map: HashMap<String, serde_json::Value> =
            serde_json::from_value(message_value.clone()).map_err(|e| {
                AgentError::Transport(format!("Failed to convert message to HashMap: {}", e))
            })?;

        // Extract recipient keys from DID
        let key_extractor = KeyExtractor::with_did_repository(
            self.did_document_service.clone(),
            self.wallet_provider.clone(),
            self.did_repository.clone(),
        );

        // Get recipient authentication key (Ed25519) for kid and keyAgreement (X25519) for encryption
        let recipient_auth_key = key_extractor
            .extract_public_key_from_did(recipient_did)
            .await?;
        let recipient_encryption_key = key_extractor
            .extract_key_agreement_from_did(recipient_did)
            .await?;

        tracing::trace!("[DIDComm v1] recipient auth_key and agreement_key resolved");

        // Use anon_pack_message from didcomm_v1
        // Note: wallet_provider is not used for anoncrypt but API requires it
        let packed_json = crate::messaging::anon_pack_message_v1(
            &message_map,
            &recipient_auth_key,
            &recipient_encryption_key,
            self.wallet_provider.clone(),
        )
        .await?;

        tracing::debug!("[DIDComm v1] Packed anoncrypt");

        Ok(packed_json)
    }

    /// Find the sender's key ID in the wallet
    async fn find_sender_key(
        &self,
        sender_did: &str,
        key_extractor: &KeyExtractor,
    ) -> Result<String> {
        // Check if sender_did is the agent's own DID - if so, use stored key ID
        let agent_did_lock = self.agent_did.read().await;
        if let Some(agent_did) = agent_did_lock.as_ref() {
            if sender_did == agent_did {
                // This is the agent's own DID - use stored key ID directly
                drop(agent_did_lock);
                let agent_key_lock = self.agent_key_id.read().await;
                if let Some(key_id) = agent_key_lock.as_ref() {
                    return Ok(key_id.clone());
                }
                // agent_key_id not set — fall through to KeyExtractor lookup
            } else {
                drop(agent_did_lock);
            }
        } else {
            drop(agent_did_lock);
        }

        // Resolve key ID from DID via KeyExtractor (handles did:key, did:peer, etc.)
        key_extractor.find_key_for_did(sender_did).await
    }
}

#[cfg(test)]
mod raw_plaintext_tests {
    use crate::test_utils::InMemoryWallet;
    use agent_core::traits::{KeyPurpose, KeyType, WalletProvider};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// The decrypted v1 wire plaintext must survive unpack byte-for-byte in
    /// `UnpackMetadata::raw_plaintext`, decorators intact. The normalized
    /// `Message` alone is lossy (`@type`→`type`, synthesized `body`,
    /// `~attach`→`attachments`), which breaks controllers that forward the
    /// message to a wire-faithful consumer (e.g. Credo).
    #[tokio::test]
    async fn v1_unpack_preserves_raw_wire_plaintext() {
        let wallet: Arc<dyn WalletProvider> = Arc::new(InMemoryWallet::new());
        let sender = wallet
            .create_key(KeyType::Ed25519, KeyPurpose::AgentMessaging)
            .await
            .unwrap();
        let recipient = wallet
            .create_key(KeyType::Ed25519, KeyPurpose::AgentMessaging)
            .await
            .unwrap();

        // Aries convention: kid is the recipient Ed25519 verkey; the CEK is
        // wrapped for its X25519 conversion.
        let recipient_kid = bs58::encode(&recipient.public_key).into_string();
        let recipient_x25519 = aries_askar::kms::LocalKey::from_public_bytes(
            aries_askar::kms::KeyAlg::Ed25519,
            &recipient.public_key,
        )
        .unwrap()
        .convert_key(aries_askar::kms::KeyAlg::X25519)
        .unwrap()
        .to_public_bytes()
        .unwrap();
        let recipient_enc = bs58::encode(recipient_x25519.as_ref()).into_string();

        let original = serde_json::json!({
            "@type": "https://didcomm.org/basicmessage/1.0/message",
            "@id": "raw-fidelity-1",
            "~thread": { "thid": "thread-42", "sender_order": 1 },
            "~transport": { "return_route": "all" },
            "~attach": [{
                "@id": "att-1",
                "mime-type": "application/json",
                "data": { "base64": "eyJrIjoidiJ9" }
            }],
            "content": "hello",
            "sent_time": "2026-08-27T00:00:00Z",
        });
        let message: HashMap<String, serde_json::Value> =
            serde_json::from_value(original.clone()).unwrap();

        let encrypted = didcomm::v1::pack_message(
            &message,
            &[(recipient_kid, recipient_enc)],
            Some(&sender.id),
            wallet.clone(),
        )
        .await
        .unwrap();

        let (_normalized, metadata) = didcomm::v1::unpack_message(&encrypted, wallet.clone())
            .await
            .unwrap();

        // Semantically identical to what was packed…
        let raw: serde_json::Value = serde_json::from_str(&metadata.raw_plaintext).unwrap();
        assert_eq!(raw, original);
        // …and the v1 wire keys survive verbatim (normalization renames these)
        for key in [
            "\"@type\"",
            "\"@id\"",
            "\"~thread\"",
            "\"~transport\"",
            "\"~attach\"",
        ] {
            assert!(
                metadata.raw_plaintext.contains(key),
                "raw plaintext lost {key}"
            );
        }
        assert!(metadata.authenticated);
    }
}
