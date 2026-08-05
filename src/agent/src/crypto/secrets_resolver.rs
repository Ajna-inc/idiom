//! Secrets Resolver adapter for SICPA didcomm crate
//!
//! Bridges our wallet to the didcomm crate's SecretsResolver trait.

use agent_core::traits::WalletProvider;
use async_trait::async_trait;
use bs58;
use did::registry::DidRegistry;
use sicpa_didcomm::error::{Error, ErrorKind, Result};
use sicpa_didcomm::secrets::{Secret, SecretMaterial, SecretType, SecretsResolver};
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// Adapter that implements didcomm's SecretsResolver using our wallet
pub struct AgentSecretsResolver {
    wallet: Arc<dyn WalletProvider>,
    did_registry: Arc<DidRegistry>,
    /// Memoized `did#fragment → (public_key_id, key_type)`. `find_wallet_key_id`
    /// otherwise re-resolves the DID doc and re-scans its verification methods on
    /// every `get_secret` (called per pack/unpack). Deterministic for
    /// did:peer/did:key; the actual secret bytes are cached in the wallet.
    key_id_cache: dashmap::DashMap<String, (String, String)>,
}

impl AgentSecretsResolver {
    /// Create a new AgentSecretsResolver
    pub fn new(wallet: Arc<dyn WalletProvider>, did_registry: Arc<DidRegistry>) -> Self {
        Self {
            wallet,
            did_registry,
            key_id_cache: dashmap::DashMap::new(),
        }
    }

    /// Parse a key ID to extract DID and fragment
    ///
    /// Examples:
    /// - "did:key:z6Mk...#z6Mk..." -> ("did:key:z6Mk...", "z6Mk...")
    /// - "did:peer:2...#key-1" -> ("did:peer:2...", "key-1")
    fn parse_key_id(&self, key_id: &str) -> (String, String) {
        if let Some(hash_pos) = key_id.rfind('#') {
            let did = key_id[..hash_pos].to_string();
            let fragment = key_id[hash_pos + 1..].to_string();
            (did, fragment)
        } else {
            // If no fragment, treat the whole thing as a DID
            (key_id.to_string(), String::new())
        }
    }

    /// Find wallet key ID from DID document verification method
    /// Returns (public_key_identifier, key_type)
    async fn find_wallet_key_id(
        &self,
        did: &str,
        fragment: &str,
    ) -> Result<Option<(String, String)>> {
        trace!("Looking up key for {}#{}", did, fragment);

        let cache_key = format!("{did}#{fragment}");
        if let Some(hit) = self.key_id_cache.get(&cache_key) {
            return Ok(Some(hit.clone()));
        }

        // Special handling for did:peer:2 (self-resolving from DID string)
        // This avoids going through the registry which may not have the peer resolver working
        if did.starts_with("did:peer:2.") {
            trace!("Resolving did:peer:2 directly (self-resolving)");
            let resolved = self.resolve_peer_2_key(did, fragment)?;
            if let Some(ref v) = resolved {
                self.key_id_cache.insert(cache_key, v.clone());
            }
            return Ok(resolved);
        }

        // Parse DID
        let parsed_did =
            did::core::DID::parse(did).map_err(|e| Error::new(ErrorKind::Malformed, e))?;

        // Resolve DID document
        let doc = match self.did_registry.resolve(&parsed_did).await {
            Ok(doc) => doc,
            Err(_) => {
                warn!("Failed to resolve DID: {}", did);
                return Ok(None);
            }
        };

        // Find verification method matching the fragment
        let vm = doc.verification_method.iter().find(|vm| {
            // Match by full ID or just fragment
            vm.id == format!("{}#{}", did, fragment) || vm.id.ends_with(&format!("#{}", fragment))
        });

        if let Some(vm) = vm {
            trace!("Found verification method: {} (type: {})", vm.id, vm.type_);

            // Try to extract wallet key ID from multibase public key
            if let Some(multibase_key) = &vm.public_key_multibase {
                trace!("Public key (multibase): {}", multibase_key);
                let v = (multibase_key.clone(), vm.type_.clone());
                self.key_id_cache.insert(cache_key, v.clone());
                return Ok(Some(v));
            }

            if let Some(base58_key) = &vm.public_key_base58 {
                trace!("Public key (base58): {}", base58_key);
                let v = (base58_key.clone(), vm.type_.clone());
                self.key_id_cache.insert(cache_key, v.clone());
                return Ok(Some(v));
            }
        }

        warn!(
            "No matching verification method found for {}#{}",
            did, fragment
        );
        Ok(None)
    }

    /// Resolve did:peer:2 key directly from the DID string (self-resolving)
    ///
    /// did:peer:2 format: did:peer:2.V<auth_key>.E<agreement_key>.S<service>
    /// - V = Verification (Ed25519, #key-1) - key is already multibase encoded (starts with 'z')
    /// - E = Encryption/keyAgreement (X25519, #key-2) - key is already multibase encoded (starts with 'z')
    fn resolve_peer_2_key(&self, did: &str, fragment: &str) -> Result<Option<(String, String)>> {
        // Parse did:peer:2 format
        let parts: Vec<&str> = match did.strip_prefix("did:peer:2.") {
            Some(suffix) => suffix.split('.').collect(),
            None => return Ok(None),
        };

        for part in parts {
            if fragment == "key-1" {
                // Looking for authentication key (V element)
                // The encoded key already includes 'z' prefix (multibase base58btc)
                if let Some(encoded) = part.strip_prefix('V') {
                    // Verify it's a valid Ed25519 multibase key
                    let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode V element: {}", e),
                        )
                    })?;

                    if decoded.len() >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
                        trace!("Found Ed25519 key from did:peer:2 V element");
                        // Return the encoded key as-is (already has 'z' prefix)
                        return Ok(Some((
                            encoded.to_string(),
                            "Ed25519VerificationKey2020".to_string(),
                        )));
                    }
                }
            } else if fragment == "key-2" {
                // Looking for key agreement key (E element)
                // The encoded key already includes 'z' prefix (multibase base58btc)
                if let Some(encoded) = part.strip_prefix('E') {
                    // Verify it's a valid X25519 multibase key
                    let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode E element: {}", e),
                        )
                    })?;

                    if decoded.len() >= 2 && decoded[0] == 0xec && decoded[1] == 0x01 {
                        trace!("Found X25519 key from did:peer:2 E element");
                        // Return the encoded key as-is (already has 'z' prefix)
                        return Ok(Some((
                            encoded.to_string(),
                            "X25519KeyAgreementKey2020".to_string(),
                        )));
                    }
                }
            }
        }

        warn!("Key {} not found in did:peer:2", fragment);
        Ok(None)
    }

    /// Convert Ed25519 private key to X25519 private and public keys
    ///
    /// This uses the standard Curve25519 conversion from Ed25519 (signing) to X25519 (encryption).
    /// Ed25519 → X25519 private-key derivation.
    ///
    /// Thin adapter over the canonical helper in
    /// `did::methods::ed25519_private_to_x25519`. Kept as a private
    /// wrapper on this type only because the surrounding call sites
    /// return `sicpa_didcomm::Error` — we convert the free helper's string
    /// error into the framework error type here.
    fn ed25519_private_to_x25519(ed25519_private: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (secret, public) = did::methods::ed25519_private_to_x25519(ed25519_private)
            .map_err(|e| Error::msg(ErrorKind::Malformed, e))?;
        Ok((secret.to_vec(), public.to_vec()))
    }

    // Ed25519 → X25519 public-key conversion lives in
    // `did::methods::ed25519_public_to_x25519` — the canonical helper.

    /// Get private key bytes from wallet
    ///
    /// Retrieves the secret/private key bytes for a given public key identifier.
    /// This implementation searches for the matching key by comparing public keys,
    /// then retrieves the private key bytes using the wallet's get_secret_bytes() method.
    ///
    /// If the requested key is X25519, it will:
    /// 1. First look for a native X25519 key in the wallet
    /// 2. If not found, derive X25519 from Ed25519 on-the-fly
    ///
    /// Returns (private_key_bytes, public_key_bytes) tuple for X25519 keys
    /// so we don't have to recompute the public key (which is error-prone).
    async fn get_private_key_bytes(
        &self,
        public_key_identifier: &str,
        key_type: &str,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        trace!("Looking for key type: {}", key_type);

        // Check if this is an X25519 key request
        let is_x25519 = key_type.contains("X25519") || key_type.contains("KeyAgreement");

        // List all wallet keys
        let keys = self
            .wallet
            .list_keys()
            .await
            .map_err(|e| Error::new(ErrorKind::SecretNotFound, e))?;

        // For X25519 keys, first look for native X25519, then fallback to Ed25519 derivation
        if is_x25519 {
            // Decode the X25519 public key - handle both multibase and plain base58 formats
            // - multibase format: starts with 'z' (base58btc) and includes multicodec prefix
            // - plain base58 format: used by did:key X25519KeyAgreementKey2019
            let x25519_public = if public_key_identifier.starts_with('z') {
                // Multibase format (e.g., from did:ajna or X25519KeyAgreementKey2020)
                let x25519_with_codec = multibase::decode(public_key_identifier)
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode X25519 multibase: {}", e),
                        )
                    })?
                    .1; // Get the decoded bytes (second element of tuple)

                // Remove multicodec prefix (0xec 0x01 for X25519)
                if x25519_with_codec.len() > 2
                    && x25519_with_codec[0] == 0xec
                    && x25519_with_codec[1] == 0x01
                {
                    x25519_with_codec[2..].to_vec()
                } else {
                    x25519_with_codec
                }
            } else {
                // Plain base58 format (e.g., from did:key X25519KeyAgreementKey2019)
                bs58::decode(public_key_identifier)
                    .into_vec()
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode X25519 base58: {}", e),
                        )
                    })?
            };

            // FIRST: Look for native X25519 key in wallet (did:ajna creates these separately)
            for key in &keys {
                if key.key_type == agent_core::traits::KeyType::X25519 {
                    // Compare public keys directly
                    if key.public_key == x25519_public {
                        debug!("Found native X25519 key in wallet: {}", key.id);

                        // Get the X25519 private key bytes directly from the wallet
                        let x25519_private =
                            self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                                Error::msg(
                                    ErrorKind::SecretNotFound,
                                    format!("Failed to get X25519 secret bytes: {}", e),
                                )
                            })?;

                        // Return both private and public key - public key from wallet is correct
                        return Ok((x25519_private, Some(key.public_key.clone())));
                    }
                }
            }

            // SECOND: Fallback - Search for Ed25519 key in wallet and derive X25519
            trace!("No native X25519 found, trying Ed25519 derivation");
            for key in &keys {
                if key.key_type != agent_core::traits::KeyType::Ed25519 {
                    continue;
                }

                if let Ok(derived_x25519_public) =
                    did::methods::ed25519_public_to_x25519(&key.public_key)
                {
                    if derived_x25519_public.as_slice() == x25519_public.as_slice() {
                        trace!(
                            "Found matching Ed25519 key for X25519 derivation: {}",
                            key.id
                        );

                        let ed25519_private =
                            self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                                Error::msg(
                                    ErrorKind::SecretNotFound,
                                    format!("Failed to get Ed25519 secret bytes: {}", e),
                                )
                            })?;

                        let (x25519_private, x25519_public_derived) =
                            Self::ed25519_private_to_x25519(&ed25519_private)?;

                        return Ok((x25519_private, Some(x25519_public_derived)));
                    }
                }
            }

            trace!("No X25519/Ed25519 key found for target public key");
            return Err(Error::msg(
                ErrorKind::SecretNotFound,
                "No X25519 or Ed25519 key found matching the requested public key".to_string(),
            ));
        }

        // For non-X25519 keys (Ed25519, etc.), use the original logic
        // First, try to decode the public key identifier from multibase
        let ed25519_public = if let Ok((_, decoded)) = multibase::decode(public_key_identifier) {
            // Check if it has Ed25519 multicodec prefix (0xed 0x01)
            if decoded.len() > 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
                decoded[2..].to_vec()
            } else {
                decoded
            }
        } else {
            // Fallback: plain base58 decode, or empty if it can't be decoded
            bs58::decode(public_key_identifier)
                .into_vec()
                .unwrap_or_default()
        };

        for key in keys {
            // Compare the public keys directly
            let matches = if !ed25519_public.is_empty() {
                key.public_key == ed25519_public
            } else {
                // Fallback to string matching
                let pub_key_base58 = bs58::encode(&key.public_key).into_string();
                public_key_identifier.contains(&pub_key_base58)
                    || pub_key_base58.contains(public_key_identifier)
            };

            if matches {
                debug!("Found matching wallet key: {}", key.id);

                // Get the private key bytes from the wallet
                let secret_bytes = self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                    Error::msg(
                        ErrorKind::SecretNotFound,
                        format!("Failed to get secret bytes: {}", e),
                    )
                })?;

                // For Ed25519, return without public key (will be decoded from multibase later)
                return Ok((secret_bytes, None));
            }
        }

        Err(Error::msg(
            ErrorKind::SecretNotFound,
            format!("Key not found for identifier: {}", public_key_identifier),
        ))
    }
}

#[async_trait]
impl SecretsResolver for AgentSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        trace!("get_secret({})", secret_id);

        // Parse key ID to extract DID and fragment
        let (did, fragment) = self.parse_key_id(secret_id);

        // Find wallet key ID from DID document (returns public_key_identifier and key_type)
        let (public_key_identifier, key_type) =
            match self.find_wallet_key_id(&did, &fragment).await? {
                Some(result) => result,
                None => {
                    trace!("Secret not found for: {}", secret_id);
                    return Ok(None);
                }
            };

        // Determine if this is X25519 or Ed25519
        let is_x25519 = key_type.contains("X25519") || key_type.contains("KeyAgreement");

        // Get private key bytes from wallet (will derive X25519 from Ed25519 if needed)
        // Also returns public key for X25519 to avoid incorrect recomputation
        let (private_key_bytes, wallet_public_key) = self
            .get_private_key_bytes(&public_key_identifier, &key_type)
            .await?;

        // Get the public key bytes for the JWK
        let public_key_bytes = if is_x25519 {
            // For X25519, use the public key returned from wallet lookup
            // This is correct because:
            // 1. Native X25519 keys: public key comes directly from wallet
            // 2. Ed25519-derived: public key is computed correctly in ed25519_private_to_x25519
            if let Some(pub_key) = wallet_public_key {
                pub_key
            } else {
                // Fallback: should not happen for X25519, but handle gracefully
                return Err(Error::msg(
                    ErrorKind::Malformed,
                    "X25519 key missing public key",
                ));
            }
        } else {
            // For Ed25519, use the public key from DID document
            bs58::decode(&public_key_identifier)
                .into_vec()
                .map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Failed to decode Ed25519 public key: {}", e),
                    )
                })?
        };

        // Convert keys to base64url encoding (required for JWK)
        use base64::Engine;
        let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let private_key_b64url = base64_engine.encode(&private_key_bytes);
        let public_key_b64url = base64_engine.encode(&public_key_bytes);

        // Create JWK based on key type
        let private_key_jwk = if is_x25519 {
            trace!("Creating X25519 JWK for {}", secret_id);
            serde_json::json!({
                "kty": "OKP",           // Octet Key Pair
                "crv": "X25519",        // Curve: X25519 for key agreement
                "d": private_key_b64url, // Private key
                "x": public_key_b64url,  // Public key
            })
        } else {
            trace!("Creating Ed25519 JWK for {}", secret_id);
            serde_json::json!({
                "kty": "OKP",           // Octet Key Pair
                "crv": "Ed25519",       // Curve: Ed25519 for signing
                "d": private_key_b64url, // Private key
                "x": public_key_b64url,  // Public key
            })
        };

        // Use JsonWebKey2020 as the secret type (standard for JWK format)
        let secret_type = SecretType::JsonWebKey2020;

        let secret = Secret {
            id: secret_id.to_string(),
            type_: secret_type,
            secret_material: SecretMaterial::JWK { private_key_jwk },
        };
        Ok(Some(secret))
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        trace!("find_secrets({} ids)", secret_ids.len());

        let mut found = Vec::new();

        for &id in secret_ids {
            if self.get_secret(id).await?.is_some() {
                found.push(id);
            }
        }

        debug!("Found {} out of {} secrets", found.len(), secret_ids.len());
        Ok(found)
    }
}

#[cfg(test)]
mod tests {

    // TODO: Re-enable after creating MockWalletProvider
    // #[test]
    // fn test_parse_key_id() {
    //     let resolver = AgentSecretsResolver::new(
    //         Arc::new(crate::test_utils::MockWalletProvider),
    //         Arc::new(DidRegistry::new()),
    //     );

    //     let (did, fragment) = resolver.parse_key_id("did:key:z6Mk...#z6Mk...");
    //     assert_eq!(did, "did:key:z6Mk...");
    //     assert_eq!(fragment, "z6Mk...");

    //     let (did, fragment) = resolver.parse_key_id("did:peer:2...#key-1");
    //     assert_eq!(did, "did:peer:2...");
    //     assert_eq!(fragment, "key-1");
    // }

    // TODO: Re-enable after creating MockWalletProvider
    // #[test]
    // fn test_map_secret_type() {
    //     use agent_core::traits::KeyType;

    //     let resolver = AgentSecretsResolver::new(
    //         Arc::new(crate::test_utils::MockWalletProvider),
    //         Arc::new(DidRegistry::new()),
    //     );

    //     assert!(matches!(
    //         resolver.map_secret_type(&KeyType::Ed25519),
    //         SecretType::Ed25519VerificationKey2020
    //     ));

    //     assert!(matches!(
    //         resolver.map_secret_type(&KeyType::X25519),
    //         SecretType::X25519KeyAgreementKey2020
    //     ));
    // }
}
