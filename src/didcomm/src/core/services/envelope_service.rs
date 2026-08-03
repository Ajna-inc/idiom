use crate::core::{
    capability_detector::{CapabilityDetector, DIDCommCapabilities},
    error::Result,
    version::PackOptions,
    DidcommError, Message,
};
use agent_core::traits::WalletProvider;
use base64::Engine;
use sicpa_didcomm::{
    did::DIDResolver as DidcommDIDResolver, secrets::SecretsResolver as DidcommSecretsResolver,
    Message as DidcommMessage, PackEncryptedOptions, UnpackOptions,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Metadata from unpacking a message
#[derive(Debug, Clone)]
pub struct UnpackMetadata {
    /// Authenticated sender DID (if authcrypt)
    pub authenticated: bool,

    /// Anonymous sender (if anoncrypt)
    pub anonymous: bool,

    /// Sender DID (if authenticated)
    pub from: Option<String>,

    /// Recipient DID
    pub to: Option<String>,

    /// Whether message was encrypted
    pub encrypted: bool,

    /// Whether message was signed
    pub signed: bool,
}

/// EnvelopeService handles packing and unpacking DIDComm messages
///
/// This service provides message encryption (authcrypt/anoncrypt) and signing
/// for both DIDComm v1 and v2 protocols.
pub struct EnvelopeService {
    did_resolver: Arc<dyn DidcommDIDResolver + Send + Sync>,
    secrets_resolver: Arc<dyn DidcommSecretsResolver + Send + Sync>,
    wallet: Arc<dyn WalletProvider>,
}

impl EnvelopeService {
    /// Create a new EnvelopeService
    pub fn new(
        did_resolver: Arc<dyn DidcommDIDResolver + Send + Sync>,
        secrets_resolver: Arc<dyn DidcommSecretsResolver + Send + Sync>,
        wallet: Arc<dyn WalletProvider>,
    ) -> Self {
        Self {
            did_resolver,
            secrets_resolver,
            wallet,
        }
    }

    /// Pack a message with encryption (authcrypt or anoncrypt)
    ///
    /// # Arguments
    /// * `message` - The plaintext message to pack
    /// * `to` - Recipient DID
    /// * `from` - Sender DID (Some for authcrypt, None for anoncrypt)
    /// * `sign_from` - Optional DID to sign with
    ///
    /// # Returns
    /// Encrypted message as JSON string
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        sign_from: Option<&str>,
    ) -> Result<String> {
        // Strip any fragment from recipient DID - the fragment (e.g., #key-2)
        // comes from JWE's skid field during unpack but should not be used
        // in pack validation (message.to field doesn't have fragments)
        let to_did = to.split('#').next().unwrap_or(to);

        // Convert our Message to didcomm Message
        let didcomm_msg = self.to_didcomm_message(message)?;

        tracing::debug!("[PACK] to={}, from={:?}", to_did, from);

        let pack_options = PackEncryptedOptions::default();

        // Pack encrypted
        let (packed, _metadata) = didcomm_msg
            .pack_encrypted(
                to_did,
                from,
                sign_from,
                self.did_resolver.as_ref(),
                self.secrets_resolver.as_ref(),
                &pack_options,
            )
            .await
            .map_err(|e| DidcommError::PackingFailed(e.to_string()))?;

        tracing::debug!("[PACK] Message packed successfully");

        // Parse the packed JWE to see what algorithm was actually used
        if let Ok(jwe_json) = serde_json::from_str::<serde_json::Value>(&packed) {
            if let Some(protected) = jwe_json.get("protected").and_then(|v| v.as_str()) {
                if let Ok(decoded) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected)
                {
                    if let Ok(header) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                        tracing::debug!(
                            "[PACK] JWE alg={}, enc={}",
                            header.get("alg").and_then(|v| v.as_str()).unwrap_or("?"),
                            header.get("enc").and_then(|v| v.as_str()).unwrap_or("?")
                        );
                    }
                }
            }
        }

        Ok(packed)
    }

    /// Pack a message with only signing (no encryption)
    ///
    /// # Arguments
    /// * `message` - The plaintext message to pack
    /// * `sign_from` - DID to sign with
    ///
    /// # Returns
    /// Signed message as JSON string
    pub async fn pack_signed(&self, message: &Message, sign_from: &str) -> Result<String> {
        // Convert our Message to didcomm Message
        let didcomm_msg = self.to_didcomm_message(message)?;

        // Pack signed
        let (packed, _metadata) = didcomm_msg
            .pack_signed(
                sign_from,
                self.did_resolver.as_ref(),
                self.secrets_resolver.as_ref(),
            )
            .await
            .map_err(|e| DidcommError::SigningFailed(e.to_string()))?;

        Ok(packed)
    }

    /// Pack a message with version-aware encryption
    ///
    /// This method automatically selects the appropriate DIDComm version based on:
    /// 1. The PackOptions version preference (V1Only, V2Only, V2WithV1Fallback, Auto)
    /// 2. The recipient's DID document capabilities
    ///
    /// # Arguments
    /// * `message` - The plaintext message to pack
    /// * `to` - Recipient DID
    /// * `from` - Sender DID (Some for authcrypt, None for anoncrypt)
    /// * `options` - Packing options including version preference
    ///
    /// # Returns
    /// Encrypted message as JSON string in the appropriate format (v1 or v2)
    pub async fn pack_encrypted_with_version(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        options: &PackOptions,
    ) -> Result<String> {
        // Determine which version to use based on both sender and recipient capabilities
        let use_v1 = self.should_use_v1(to, from, options);

        if use_v1 {
            debug!("Using DIDComm v1 to pack message to {}", to);
            self.pack_v1(message, to, from, options).await
        } else {
            debug!("Using DIDComm v2 to pack message to {}", to);
            // v2 path: directly call pack_encrypted (Sicpa didcomm crate).
            // pack_v2 used to be a 1-line passthrough wrapper; inlined here
            // so there's a single visible v2 entry. `sign_message` toggles
            // whether to attach a JWS as the sender; today the only v2
            // callers want authcrypt without signing.
            let sign_from = if options.sign_message { from } else { None };
            self.pack_encrypted(message, to, from, sign_from).await
        }
    }

    /// Determine if v1 should be used based on options and both sender/recipient capabilities
    ///
    /// Both the sender and recipient must support v2 for v2 packing to work.
    /// If either party only supports v1, we must fall back to v1.
    fn should_use_v1(&self, to_did: &str, from_did: Option<&str>, options: &PackOptions) -> bool {
        use crate::core::version::DIDCommVersion;

        match options.version {
            DIDCommVersion::V1Only => {
                trace!("Version preference: V1Only");
                true
            }
            DIDCommVersion::V2Only => {
                trace!("Version preference: V2Only");
                false
            }
            DIDCommVersion::V2WithV1Fallback | DIDCommVersion::Auto => {
                // Check recipient capabilities
                trace!(
                    "Detecting DIDComm capabilities from recipient DID: {}",
                    to_did
                );
                let recipient_caps = CapabilityDetector::detect_from_did_string(to_did);
                debug!(
                    "Recipient capabilities for {}: v1={}, v2={}",
                    to_did, recipient_caps.supports_v1, recipient_caps.supports_v2
                );

                // Check sender capabilities (if present - authcrypt)
                let sender_caps = if let Some(from) = from_did {
                    trace!("Detecting DIDComm capabilities from sender DID: {}", from);
                    let caps = CapabilityDetector::detect_from_did_string(from);
                    debug!(
                        "Sender capabilities for {}: v1={}, v2={}",
                        from, caps.supports_v1, caps.supports_v2
                    );
                    caps
                } else {
                    // Anoncrypt - no sender, assume we can do v2
                    DIDCommCapabilities {
                        supports_v1: true,
                        supports_v2: true,
                    }
                };

                // For v2 to work, BOTH sender and recipient must support v2
                // If either only supports v1, we must use v1
                let both_support_v2 = recipient_caps.supports_v2 && sender_caps.supports_v2;
                let either_v1_only = (recipient_caps.supports_v1 && !recipient_caps.supports_v2)
                    || (sender_caps.supports_v1 && !sender_caps.supports_v2);

                if either_v1_only {
                    debug!("Either sender or recipient only supports v1, using v1");
                    true // Fall back to v1
                } else if both_support_v2 {
                    debug!("Both sender and recipient support v2, using v2");
                    false // Use v2
                } else if recipient_caps.supports_v1 || sender_caps.supports_v1 {
                    debug!("Falling back to v1 for compatibility");
                    true // Fall back to v1
                } else {
                    // No clear support detected, default based on mode
                    match options.version {
                        DIDCommVersion::V2WithV1Fallback => {
                            debug!("No clear version support, defaulting to v2");
                            false
                        }
                        DIDCommVersion::Auto => {
                            debug!("No clear version support, defaulting to v1 for safety");
                            true
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    /// Pack message using DIDComm v1
    ///
    /// This implements full DIDComm v1 packing with:
    /// - Automatic DID resolution to extract recipient keys
    /// - Multibase to base58 key conversion
    /// - Message format conversion (v2 to v1)
    /// - Authcrypt or Anoncrypt based on sender presence
    async fn pack_v1(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        _options: &PackOptions,
    ) -> Result<String> {
        debug!("[pack_v1] Packing with DIDComm v1 to {}", to);

        // Step 1: Convert v2 Message to v1 format (HashMap with @type, @id)
        let v1_message = self.convert_message_to_v1(message)?;
        debug!("[pack_v1] Converted message to v1 format");

        // Step 2: Resolve recipient DID to get DIDDoc
        let recipient_doc = self
            .did_resolver
            .resolve(to)
            .await
            .map_err(|e| DidcommError::PackingFailed(format!("DID resolution failed: {:?}", e)))?
            .ok_or_else(|| DidcommError::PackingFailed(format!("DID not found: {}", to)))?;
        debug!("[pack_v1] Resolved recipient DID document");

        // Step 3: Extract base58 keys from DIDDoc
        let (auth_key_base58, ka_key_base58) = self.extract_v1_keys_from_diddoc(&recipient_doc)?;
        debug!(
            "  Auth key (first 20 chars): {}...",
            &auth_key_base58[..auth_key_base58.len().min(20)]
        );
        debug!(
            "  KA key (first 20 chars): {}...",
            &ka_key_base58[..ka_key_base58.len().min(20)]
        );

        // DIAG: surface what EnvelopeService is packing FOR. Mirrors the
        // four logs in MessageEncryption — needed because OOB-time sends
        // (DidExchange Request) go through this path, not pack_encrypted_message.
        tracing::debug!(
            target: "didcomm.diag",
            to_did = %to,
            from_did = ?from,
            msg_type = %message.msg_type,
            auth_kid = %auth_key_base58,
            agreement_kid = %ka_key_base58,
            "envelope.pack_v1"
        );

        // Step 4: Get sender key ID if authcrypt
        let sender_key_id = if let Some(from_did) = from {
            Some(self.find_sender_key_id(from_did).await?)
        } else {
            None
        };
        debug!("  Sender key ID: {:?}", sender_key_id);

        // Step 5: Pack using didcomm_v1
        let encrypted = crate::v1::pack_message(
            &v1_message,
            &[(auth_key_base58, ka_key_base58)],
            sender_key_id.as_deref(),
            self.wallet.clone(),
        )
        .await
        .map_err(|e| DidcommError::PackingFailed(format!("v1 pack failed: {}", e)))?;

        debug!("[pack_v1] Successfully packed with DIDComm v1");

        // Step 6: Serialize to JSON
        let json = serde_json::to_string(&encrypted)
            .map_err(|e| DidcommError::PackingFailed(e.to_string()))?;

        // DIAG: extract the JWE recipients[*].header.kid actually on the wire.
        // Gated on `enabled!` so the parse cost is only paid when the diag
        // target is on.
        if tracing::enabled!(target: "didcomm.diag", tracing::Level::DEBUG) {
            if let Ok(jwe_val) = serde_json::from_str::<serde_json::Value>(&json) {
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
                    to_did = %to,
                    wire_kids = ?kids,
                    "envelope.pack_v1 wire_kids"
                );
            }
        }
        Ok(json)
    }

    /// Convert v2 Message format to v1 PlaintextMessage (HashMap)
    ///
    /// DIDComm v1 uses:
    /// - `@type` instead of `type`
    /// - `@id` instead of `id`
    /// - Flattened body fields at top level
    fn convert_message_to_v1(
        &self,
        message: &Message,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut v1_msg: HashMap<String, serde_json::Value> = HashMap::new();

        // DIDComm v1 uses @type, @id instead of type, id
        v1_msg.insert(
            "@type".to_string(),
            serde_json::Value::String(message.msg_type.clone()),
        );
        v1_msg.insert(
            "@id".to_string(),
            serde_json::Value::String(message.id.clone()),
        );

        // Flatten body into top level for v1
        if let serde_json::Value::Object(body_map) = &message.body {
            for (k, v) in body_map {
                v1_msg.insert(k.clone(), v.clone());
            }
        }

        // Add extra fields
        for (k, v) in &message.extra {
            v1_msg.insert(k.clone(), v.clone());
        }

        // Add ~thread if present in extra or create from thread
        if let Some(ref thread) = message.thread {
            if thread.thid.is_some() && !v1_msg.contains_key("~thread") {
                v1_msg.insert(
                    "~thread".to_string(),
                    serde_json::json!({
                        "thid": thread.thid
                    }),
                );
            }
        }

        // Copy attachments as ~attach for v1 compatibility
        if let Some(ref attachments) = message.attachments {
            if !attachments.is_empty() {
                let v1_attachments: Vec<serde_json::Value> = attachments
                    .iter()
                    .map(|a| serde_json::to_value(a).unwrap_or_default())
                    .collect();
                v1_msg.insert(
                    "~attach".to_string(),
                    serde_json::Value::Array(v1_attachments),
                );
            }
        }

        Ok(v1_msg)
    }

    /// Extract base58 keys from SICPA DIDDoc for v1 packing
    ///
    /// Returns (authentication_key_base58, key_agreement_key_base58)
    fn extract_v1_keys_from_diddoc(
        &self,
        doc: &sicpa_didcomm::did::DIDDoc,
    ) -> Result<(String, String)> {
        // Find authentication key (Ed25519) - prefer one in authentication array
        let auth_vm = doc
            .verification_method
            .iter()
            .find(|vm| doc.authentication.contains(&vm.id))
            .or_else(|| doc.verification_method.first())
            .ok_or_else(|| {
                DidcommError::PackingFailed("No verification method found".to_string())
            })?;

        let auth_key_base58 = self.extract_base58_from_vm(auth_vm)?;

        // Find key agreement key (X25519)
        let ka_key_base58 = if let Some(ka_id) = doc.key_agreement.first() {
            let ka_vm = doc
                .verification_method
                .iter()
                .find(|vm| &vm.id == ka_id)
                .ok_or_else(|| {
                    DidcommError::PackingFailed(format!("Key agreement VM not found: {}", ka_id))
                })?;
            self.extract_base58_from_vm(ka_vm)?
        } else {
            // Fallback: use auth key (didcomm_v1 will convert Ed25519 to X25519)
            debug!("  No key agreement found, using auth key as fallback");
            auth_key_base58.clone()
        };

        Ok((auth_key_base58, ka_key_base58))
    }

    /// Extract base58 public key from SICPA VerificationMethod
    fn extract_base58_from_vm(
        &self,
        vm: &sicpa_didcomm::did::VerificationMethod,
    ) -> Result<String> {
        match &vm.verification_material {
            sicpa_didcomm::did::VerificationMaterial::Base58 { public_key_base58 } => {
                Ok(public_key_base58.clone())
            }
            sicpa_didcomm::did::VerificationMaterial::Multibase {
                public_key_multibase,
            } => {
                // Convert multibase (z6Mk...) to base58
                self.multibase_to_base58(public_key_multibase)
            }
            sicpa_didcomm::did::VerificationMaterial::JWK { public_key_jwk } => {
                // Extract from JWK - decode x parameter
                let x = public_key_jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        DidcommError::PackingFailed("JWK missing x parameter".to_string())
                    })?;

                let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| {
                        DidcommError::PackingFailed(format!("JWK decode failed: {}", e))
                    })?;

                Ok(bs58::encode(&key_bytes).into_string())
            }
        }
    }

    /// Convert multibase (z6Mk...) to base58
    ///
    /// Multibase format: z{base58btc(multicodec_prefix + key_bytes)}
    /// - Ed25519: multicodec prefix = 0xed01
    /// - X25519: multicodec prefix = 0xec01
    fn multibase_to_base58(&self, multibase: &str) -> Result<String> {
        let (_, decoded) = multibase::decode(multibase)
            .map_err(|e| DidcommError::PackingFailed(format!("Multibase decode failed: {}", e)))?;

        // Skip multicodec prefix (2 bytes)
        if decoded.len() < 3 {
            return Err(DidcommError::PackingFailed(format!(
                "Multibase too short: {} bytes",
                decoded.len()
            )));
        }

        let key_bytes = &decoded[2..];
        Ok(bs58::encode(key_bytes).into_string())
    }

    /// Find sender's wallet key ID from their DID
    async fn find_sender_key_id(&self, from_did: &str) -> Result<String> {
        // Resolve sender's DID document
        let sender_doc = self
            .did_resolver
            .resolve(from_did)
            .await
            .map_err(|e| {
                DidcommError::PackingFailed(format!("Sender DID resolution failed: {:?}", e))
            })?
            .ok_or_else(|| {
                DidcommError::PackingFailed(format!("Sender DID not found: {}", from_did))
            })?;

        // Get first authentication key
        let auth_vm = sender_doc
            .verification_method
            .iter()
            .find(|vm| sender_doc.authentication.contains(&vm.id))
            .or_else(|| sender_doc.verification_method.first())
            .ok_or_else(|| {
                DidcommError::PackingFailed("No sender verification method".to_string())
            })?;

        // Extract public key to find in wallet
        let public_key_base58 = self.extract_base58_from_vm(auth_vm)?;
        let public_key_bytes = bs58::decode(&public_key_base58)
            .into_vec()
            .map_err(|e| DidcommError::PackingFailed(format!("Base58 decode failed: {}", e)))?;

        // Search wallet for matching key
        let keys = self
            .wallet
            .list_keys()
            .await
            .map_err(|e| DidcommError::PackingFailed(format!("Wallet list failed: {}", e)))?;

        for key in keys {
            if key.public_key == public_key_bytes {
                return Ok(key.id);
            }
        }

        Err(DidcommError::PackingFailed(format!(
            "Sender key not found in wallet for DID: {}",
            from_did
        )))
    }

    /// Unpack an encrypted or signed message
    ///
    /// Automatically detects DIDComm v1 or v2 format and uses the appropriate decryption.
    ///
    /// # Arguments
    /// * `packed` - The packed message (encrypted or signed JSON string)
    ///
    /// # Returns
    /// Tuple of (unpacked message, metadata about unpacking)
    pub async fn unpack(&self, packed: &str) -> Result<(Message, UnpackMetadata)> {
        // Detect DIDComm version
        if is_didcomm_v1(packed)? {
            tracing::debug!("Detected DIDComm v1 message, using v1 decryption");
            self.unpack_v1(packed).await
        } else {
            tracing::debug!("Detected DIDComm v2 message, using v2 decryption");
            self.unpack_v2(packed).await
        }
    }

    /// Unpack a DIDComm v1 message
    async fn unpack_v1(&self, packed: &str) -> Result<(Message, UnpackMetadata)> {
        // Parse as v1 encrypted message
        let encrypted: crate::v1::EncryptedMessage = serde_json::from_str(packed).map_err(|e| {
            DidcommError::UnpackingFailed(format!("Failed to parse v1 message: {}", e))
        })?;

        // Unpack using v1 implementation
        let (plaintext, v1_metadata) = crate::v1::unpack_message(&encrypted, self.wallet.clone())
            .await
            .map_err(|e| DidcommError::UnpackingFailed(format!("v1 unpacking failed: {}", e)))?;

        // Convert DIDComm v1 format (@id, @type) to DIDComm v2 format (id, type)
        let mut normalized = plaintext.clone();
        if let Some(id) = normalized.remove("@id") {
            normalized.insert("id".to_string(), id);
        } else if !normalized.contains_key("id") {
            // Generate a UUID if no ID present
            normalized.insert(
                "id".to_string(),
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            );
        }
        if let Some(msg_type) = normalized.remove("@type") {
            normalized.insert("type".to_string(), msg_type);
        }

        // DIDComm v1 messages don't have a separate body field
        // All protocol-specific fields are at the top level
        // For proper handling, we need to copy non-envelope fields into the body
        if !normalized.contains_key("body") {
            // Standard DIDComm envelope fields that should NOT go into body
            let envelope_fields = [
                "id",
                "type",
                "from",
                "to",
                "thread",
                "pthid",
                "created_time",
                "expires_time",
                "attachments",
            ];

            // Create body with all non-envelope fields (protocol-specific content)
            let mut body = serde_json::Map::new();
            for (key, value) in normalized.iter() {
                if !envelope_fields.contains(&key.as_str()) {
                    body.insert(key.clone(), value.clone());
                }
            }

            // Also copy @id, @type, ~thread if present for Aries compatibility
            if let Some(id) = normalized.get("id") {
                body.insert("@id".to_string(), id.clone());
            }
            if let Some(msg_type) = normalized.get("type") {
                body.insert("@type".to_string(), msg_type.clone());
            }
            if let Some(thread) = normalized.get("~thread") {
                body.insert("~thread".to_string(), thread.clone());
            }

            normalized.insert("body".to_string(), serde_json::Value::Object(body));
        }

        // Convert v1 ~attach to v2 attachments
        if let Some(attach) = normalized.remove("~attach") {
            normalized.insert("attachments".to_string(), attach);
        }

        // Convert plaintext to our Message type
        let message = serde_json::from_value(serde_json::to_value(normalized)?)
            .map_err(|e| DidcommError::InvalidMessage(format!("Failed to parse message: {}", e)))?;

        // Convert v1 metadata to our metadata format
        let metadata = UnpackMetadata {
            authenticated: v1_metadata.authenticated,
            anonymous: v1_metadata.anonymous,
            from: v1_metadata.sender_key,
            to: Some(v1_metadata.recipient_key),
            encrypted: true,
            signed: false,
        };

        Ok((message, metadata))
    }

    /// Unpack a DIDComm v2 message
    async fn unpack_v2(&self, packed: &str) -> Result<(Message, UnpackMetadata)> {
        tracing::debug!("[unpack_v2] Starting DIDComm v2 unpack");

        // Parse the JWE to see what we're working with
        if let Ok(jwe_json) = serde_json::from_str::<serde_json::Value>(packed) {
            if let Some(protected) = jwe_json.get("protected").and_then(|v| v.as_str()) {
                if let Ok(decoded) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected)
                {
                    if let Ok(header) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                        let alg = header
                            .get("alg")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let enc = header
                            .get("enc")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let typ = header
                            .get("typ")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        tracing::debug!(
                            "[unpack_v2] JWE header: alg={}, enc={}, typ={}",
                            alg,
                            enc,
                            typ
                        );
                    }
                }
            }
        }

        // Unpack using SICPA didcomm v2
        // IMPORTANT: SICPA library contains blocking I/O operations that prevent tokio timeouts
        // from working. We must use spawn_blocking to handle this correctly.
        // NOTE: We capture a Handle to the current runtime BEFORE entering spawn_blocking,
        // and use handle.block_on() inside. This avoids creating a NEW Runtime per call,
        // which exhausts iOS GCD thread pool and causes abort.
        tracing::debug!("[unpack_v2] Calling SICPA DidcommMessage::unpack via spawn_blocking");
        // Clone what we need for the blocking task
        let packed_clone = packed.to_string();
        let did_resolver = self.did_resolver.clone();
        let secrets_resolver = self.secrets_resolver.clone();

        // Capture handle to current runtime — reuse it inside spawn_blocking
        let handle = tokio::runtime::Handle::current();

        // Run SICPA unpack in a blocking thread pool with timeout
        let unpack_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let unpack_options = UnpackOptions::default();
                handle.block_on(async {
                    DidcommMessage::unpack(
                        &packed_clone,
                        did_resolver.as_ref(),
                        secrets_resolver.as_ref(),
                        &unpack_options,
                    )
                    .await
                    .map_err(|e| DidcommError::UnpackingFailed(e.to_string()))
                })
            }),
        )
        .await
        .map_err(|_| {
            tracing::error!("[SICPA] Unpack timeout after 30s");
            DidcommError::UnpackingFailed("SICPA unpack timeout after 30s".to_string())
        })?
        .map_err(|e| {
            tracing::error!("[SICPA] spawn_blocking join error: {:?}", e);
            DidcommError::UnpackingFailed(format!("spawn_blocking failed: {}", e))
        })??;

        let (didcomm_msg, unpack_metadata) = unpack_result;

        // Convert didcomm Message back to our Message
        let message = self.convert_didcomm_message(&didcomm_msg)?;

        // Extract metadata
        // IMPORTANT: Strip fragment from encrypted_from_kid - it contains the full key reference
        // (e.g., "did:peer:2...#key-2") but we only want the base DID for the "from" field.
        // The fragment is used for key selection but should not be stored as the sender DID.
        let metadata = UnpackMetadata {
            authenticated: unpack_metadata.authenticated,
            anonymous: unpack_metadata.anonymous_sender,
            from: unpack_metadata
                .encrypted_from_kid
                .map(|kid| kid.split('#').next().unwrap_or(&kid).to_string()),
            to: unpack_metadata
                .encrypted_to_kids
                .and_then(|kids| kids.first().cloned()),
            encrypted: unpack_metadata.encrypted,
            signed: unpack_metadata.non_repudiation,
        };

        Ok((message, metadata))
    }

    /// Pack a plaintext message (no encryption or signing)
    ///
    /// This is useful for testing or protocols that don't require encryption.
    pub fn pack_plaintext(&self, message: &Message) -> Result<String> {
        serde_json::to_string(message).map_err(|e| DidcommError::PackingFailed(e.to_string()))
    }

    /// Convert our Message type to didcomm's Message type
    fn to_didcomm_message(&self, message: &Message) -> Result<DidcommMessage> {
        // Serialize to JSON and deserialize as didcomm Message
        let json = serde_json::to_value(message)?;
        let didcomm_msg: DidcommMessage = serde_json::from_value(json)
            .map_err(|e| DidcommError::InvalidMessage(e.to_string()))?;
        Ok(didcomm_msg)
    }

    /// Convert didcomm's Message type to our Message type
    fn convert_didcomm_message(&self, didcomm_msg: &DidcommMessage) -> Result<Message> {
        // Serialize to JSON and deserialize as our Message
        let json = serde_json::to_value(didcomm_msg)?;
        let message: Message = serde_json::from_value(json)
            .map_err(|e| DidcommError::InvalidMessage(e.to_string()))?;
        Ok(message)
    }
}

/// Detect if a packed message is DIDComm v1 or v2 format
///
/// DIDComm v1 uses JWE format with specific structure:
/// - Has "protected", "iv", "ciphertext", "tag" fields at top level
/// - Protected header contains "typ": "JWM/1.0"
///
/// DIDComm v2 uses different JWE structure
fn is_didcomm_v1(packed: &str) -> Result<bool> {
    // Try to parse as JSON
    let json: serde_json::Value = serde_json::from_str(packed)
        .map_err(|e| DidcommError::UnpackingFailed(format!("Invalid JSON: {}", e)))?;

    // Check for v1 JWE structure: must have these exact top-level fields
    let has_v1_structure = json.get("protected").is_some()
        && json.get("iv").is_some()
        && json.get("ciphertext").is_some()
        && json.get("tag").is_some();

    if !has_v1_structure {
        return Ok(false);
    }

    // Additionally check the protected header for "JWM/1.0" type
    // DIDComm v1 ALWAYS sets typ: "JWM/1.0"
    // DIDComm v2 may or may not include typ (SICPA library doesn't always include it)
    if let Some(protected_b64) = json.get("protected").and_then(|p| p.as_str()) {
        // Decode protected header
        if let Ok(protected_bytes) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(protected_b64)
        {
            if let Ok(protected_json) =
                serde_json::from_slice::<serde_json::Value>(&protected_bytes)
            {
                if let Some(typ) = protected_json.get("typ").and_then(|t| t.as_str()) {
                    // v1 explicitly marks itself as "JWM/1.0"
                    return Ok(typ == "JWM/1.0");
                }
                // typ is missing - this is v2 (SICPA's v2 library doesn't always set typ)
                debug!("Protected header has no 'typ' field - assuming v2");
                return Ok(false);
            }
        }
    }

    // Could not decode protected header - default to v2 as it's more common in our system
    // Only v1 explicitly identifies itself with "JWM/1.0"
    debug!("Could not decode protected header - defaulting to v2");
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DIDCommVersion, MessageBuilder};

    // Note: Full integration tests with actual DID resolution and secrets
    // will be in integration tests. These are unit tests for the service structure.

    #[test]
    fn test_envelope_service_creation() {
        // This test just ensures the type structure is correct
        // We'll add real tests once we have DIDResolver and SecretsResolver implementations
    }

    #[test]
    fn test_pack_plaintext() {
        let msg = MessageBuilder::new("https://didcomm.org/test/1.0/message")
            .body(serde_json::json!({"content": "Hello"}))
            .build();

        // Create a mock service (we can't actually instantiate without resolvers)
        // So this test just validates message creation works
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("https://didcomm.org/test/1.0/message"));
    }

    #[test]
    fn test_unpack_metadata_structure() {
        let metadata = UnpackMetadata {
            authenticated: true,
            anonymous: false,
            from: Some("did:key:alice".to_string()),
            to: Some("did:key:bob".to_string()),
            encrypted: true,
            signed: true,
        };

        assert!(metadata.authenticated);
        assert!(!metadata.anonymous);
        assert_eq!(metadata.from, Some("did:key:alice".to_string()));
    }

    // ============== pack_v1 helper tests ==============

    #[test]
    fn test_convert_message_to_v1_basic() {
        // Create a DIDComm v2 style message
        let msg = MessageBuilder::new("https://didcomm.org/basicmessage/2.0/message")
            .id("msg-123".to_string())
            .body(serde_json::json!({
                "content": "Hello World"
            }))
            .build();

        // We need to create a minimal mock for testing conversion
        // Since convert_message_to_v1 takes &self, we test the logic directly
        let mut v1_msg: HashMap<String, serde_json::Value> = HashMap::new();
        v1_msg.insert(
            "@type".to_string(),
            serde_json::Value::String(msg.msg_type.clone()),
        );
        v1_msg.insert("@id".to_string(), serde_json::Value::String(msg.id.clone()));

        // Flatten body into top level for v1
        if let serde_json::Value::Object(body_map) = &msg.body {
            for (k, v) in body_map {
                v1_msg.insert(k.clone(), v.clone());
            }
        }

        // Verify v1 format
        assert_eq!(
            v1_msg.get("@type").unwrap(),
            "https://didcomm.org/basicmessage/2.0/message"
        );
        assert_eq!(v1_msg.get("@id").unwrap(), "msg-123");
        assert_eq!(v1_msg.get("content").unwrap(), "Hello World");

        // Verify v2 fields are NOT present (flattened to top level)
        assert!(!v1_msg.contains_key("type")); // v2 uses "type", not "@type"
        assert!(!v1_msg.contains_key("body")); // body is flattened
    }

    #[test]
    fn test_convert_message_to_v1_with_thread() {
        // Create a message with thread info
        let msg = MessageBuilder::new("https://didcomm.org/issue-credential/3.0/offer-credential")
            .id("msg-456".to_string())
            .body(serde_json::json!({
                "comment": "Here's your credential"
            }))
            .thread("thread-123".to_string())
            .build();

        let mut v1_msg: HashMap<String, serde_json::Value> = HashMap::new();
        v1_msg.insert(
            "@type".to_string(),
            serde_json::Value::String(msg.msg_type.clone()),
        );
        v1_msg.insert("@id".to_string(), serde_json::Value::String(msg.id.clone()));

        if let serde_json::Value::Object(body_map) = &msg.body {
            for (k, v) in body_map {
                v1_msg.insert(k.clone(), v.clone());
            }
        }

        // Add ~thread decorator if present
        if let Some(ref thread) = msg.thread {
            if thread.thid.is_some() {
                v1_msg.insert(
                    "~thread".to_string(),
                    serde_json::json!({
                        "thid": thread.thid
                    }),
                );
            }
        }

        // Verify ~thread decorator is present (v1 style)
        assert!(v1_msg.contains_key("~thread"));
        let thread_decorator = v1_msg.get("~thread").unwrap();
        assert_eq!(thread_decorator.get("thid").unwrap(), "thread-123");
    }

    #[test]
    fn test_multibase_to_base58_ed25519() {
        // Test multibase decoding with known Ed25519 key
        // Ed25519 public key multicodec prefix: 0xed01
        // z6Mk... format is base58btc(multicodec_prefix + key_bytes)

        // Create a known test key
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        // Create multibase: z (base58btc) + base58(ed25519_prefix + key)
        let mut prefixed = vec![0xed, 0x01]; // Ed25519 multicodec
        prefixed.extend_from_slice(&key_bytes);
        let multibase = format!("z{}", bs58::encode(&prefixed).into_string());

        // Decode using multibase crate
        let (_, decoded) = multibase::decode(&multibase).unwrap();

        // Should have 2-byte prefix + 32-byte key
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);

        // Extract just the key bytes (skip multicodec prefix)
        let extracted_key = &decoded[2..];
        assert_eq!(extracted_key, &key_bytes);

        // Encode as base58
        let base58_key = bs58::encode(extracted_key).into_string();
        assert!(!base58_key.starts_with('z'));
    }

    #[test]
    fn test_multibase_to_base58_x25519() {
        // Test X25519 key (key agreement)
        // X25519 public key multicodec prefix: 0xec01

        let key_bytes: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];

        // Create multibase: z (base58btc) + base58(x25519_prefix + key)
        let mut prefixed = vec![0xec, 0x01]; // X25519 multicodec
        prefixed.extend_from_slice(&key_bytes);
        let multibase = format!("z{}", bs58::encode(&prefixed).into_string());

        // Decode
        let (_, decoded) = multibase::decode(&multibase).unwrap();

        // Verify prefix
        assert_eq!(decoded[0], 0xec);
        assert_eq!(decoded[1], 0x01);

        // Extract key
        let extracted_key = &decoded[2..];
        assert_eq!(extracted_key, &key_bytes);
    }

    #[test]
    fn test_pack_options_v1_only() {
        let options = PackOptions::v1_only();
        assert_eq!(options.version, DIDCommVersion::V1Only);
    }

    #[test]
    fn test_pack_options_v2_only() {
        let options = PackOptions::v2_only();
        assert_eq!(options.version, DIDCommVersion::V2Only);
    }

    #[test]
    fn test_pack_options_with_fallback() {
        let options = PackOptions::with_fallback();
        assert_eq!(options.version, DIDCommVersion::V2WithV1Fallback);
    }
}
