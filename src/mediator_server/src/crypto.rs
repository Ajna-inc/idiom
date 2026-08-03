//! DID Resolver and Secrets Resolver adapters for the mediator server.
//!
//! Lightweight implementations of SICPA didcomm's `DIDResolver` and `SecretsResolver`
//! traits. These handle did:key (via DidRegistry) and did:peer:2 (self-resolving)
//! without pulling in the full agent crate's heavy dependencies (kademlia, mesh, etc.).

use agent_core::traits::WalletProvider;
use async_trait::async_trait;
use base64::Engine;
use did::core::{
    DidDocument, VerificationMethod as OurVerificationMethod, VerificationRelationship,
};
use did::registry::DidRegistry;
use sicpa_didcomm::did::{
    DIDCommMessagingService, DIDDoc, DIDResolver, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};
use sicpa_didcomm::error::{Error, ErrorKind, Result};
use sicpa_didcomm::secrets::{Secret, SecretMaterial, SecretType, SecretsResolver};
use std::sync::Arc;
use tracing::{debug, trace, warn};

// ────────────────────────────────────────────────────────────────────
// MediatorDIDResolver
// ────────────────────────────────────────────────────────────────────

/// DID Resolver for the mediator server.
///
/// Handles did:key (via DidRegistry + KeyDidResolver) and did:peer:2 (self-resolving).
/// Does NOT support DHT/kademlia — the mediator only needs local DID resolution.
pub struct MediatorDIDResolver {
    registry: Arc<DidRegistry>,
}

impl MediatorDIDResolver {
    pub fn new(registry: Arc<DidRegistry>) -> Self {
        Self { registry }
    }

    /// Resolve did:peer:2 locally (self-resolving, no registry needed).
    ///
    /// did:peer:2 format: `did:peer:2.V<auth_key>.E<agreement_key>.S<service>`
    fn resolve_peer_2(&self, did: &str) -> Result<DIDDoc> {
        trace!("[MediatorDIDResolver] Resolving did:peer:2: {}", did);

        let parts: Vec<&str> = did
            .strip_prefix("did:peer:2.")
            .ok_or_else(|| {
                Error::msg(
                    ErrorKind::Malformed,
                    "Invalid did:peer:2 format - missing prefix",
                )
            })?
            .split('.')
            .collect();

        if parts.len() < 2 {
            return Err(Error::msg(
                ErrorKind::Malformed,
                "Invalid did:peer:2 format - need at least V and E elements",
            ));
        }

        let mut verification_methods = Vec::new();
        let mut key_agreement = Vec::new();
        let mut authentication = Vec::new();
        let mut services = Vec::new();

        for part in parts {
            if let Some(encoded) = part.strip_prefix('V') {
                // Authentication key (Ed25519)
                let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Failed to decode V element: {}", e),
                    )
                })?;

                if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
                    return Err(Error::msg(
                        ErrorKind::Malformed,
                        "Invalid Ed25519 multicodec prefix",
                    ));
                }

                let vm_id = format!("{}#key-1", did);
                verification_methods.push(VerificationMethod {
                    id: vm_id.clone(),
                    type_: VerificationMethodType::Ed25519VerificationKey2020,
                    controller: did.to_string(),
                    verification_material: VerificationMaterial::Multibase {
                        public_key_multibase: encoded.to_string(),
                    },
                });
                authentication.push(vm_id);
            } else if let Some(encoded) = part.strip_prefix('E') {
                // Key agreement key (X25519)
                let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Failed to decode E element: {}", e),
                    )
                })?;

                if decoded.len() < 2 || decoded[0] != 0xec || decoded[1] != 0x01 {
                    return Err(Error::msg(
                        ErrorKind::Malformed,
                        "Invalid X25519 multicodec prefix",
                    ));
                }

                let vm_id = format!("{}#key-2", did);
                verification_methods.push(VerificationMethod {
                    id: vm_id.clone(),
                    type_: VerificationMethodType::X25519KeyAgreementKey2020,
                    controller: did.to_string(),
                    verification_material: VerificationMaterial::Multibase {
                        public_key_multibase: encoded.to_string(),
                    },
                });
                key_agreement.push(vm_id);
            } else if let Some(encoded) = part.strip_prefix('S') {
                // Service endpoint — base64url or multibase (legacy)
                let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .or_else(|_| multibase::decode(encoded).map(|(_, bytes)| bytes))
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode S element: {}", e),
                        )
                    })?;

                let service_json_str = String::from_utf8(decoded).map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Service not valid UTF-8: {}", e),
                    )
                })?;

                let service_data: serde_json::Value = serde_json::from_str(&service_json_str)
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to parse service JSON: {}", e),
                        )
                    })?;

                let uri = service_data
                    .get("s")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::msg(ErrorKind::Malformed, "Service missing 's' field"))?
                    .to_string();

                let routing_keys = service_data
                    .get("r")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let accept = service_data.get("a").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });

                services.push(Service {
                    id: "#didcomm".to_string(),
                    service_endpoint: ServiceKind::DIDCommMessaging {
                        value: DIDCommMessagingService {
                            uri,
                            routing_keys,
                            accept,
                        },
                    },
                });
            }
        }

        Ok(DIDDoc {
            id: did.to_string(),
            verification_method: verification_methods,
            key_agreement,
            authentication,
            service: services,
        })
    }

    /// Convert our DidDocument to SICPA's DIDDoc format.
    fn convert_to_didcomm_doc(&self, our_doc: DidDocument) -> Result<DIDDoc> {
        let verification_method = our_doc
            .verification_method
            .iter()
            .map(convert_verification_method)
            .collect::<Result<Vec<_>>>()?;

        let key_agreement = our_doc
            .key_agreement
            .iter()
            .map(|rel| match rel {
                VerificationRelationship::Reference(r) => r.clone(),
                VerificationRelationship::Embedded(vm) => vm.id.clone(),
            })
            .collect();

        let authentication = our_doc
            .authentication
            .iter()
            .map(|rel| match rel {
                VerificationRelationship::Reference(r) => r.clone(),
                VerificationRelationship::Embedded(vm) => vm.id.clone(),
            })
            .collect();

        let service = our_doc
            .service
            .iter()
            .filter_map(|s| convert_service(s).ok())
            .collect();

        Ok(DIDDoc {
            id: our_doc.id,
            verification_method,
            key_agreement,
            authentication,
            service,
        })
    }
}

#[async_trait]
impl DIDResolver for MediatorDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        let base_did = did.split('#').next().unwrap_or(did);
        trace!("[MediatorDIDResolver] Resolving: {}", base_did);

        // did:peer:2 — self-resolving
        if base_did.starts_with("did:peer:2.") {
            let doc = self.resolve_peer_2(base_did)?;
            return Ok(Some(doc));
        }

        // All other DIDs — use registry (KeyDidResolver handles did:key)
        let parsed_did =
            did::core::DID::parse(base_did).map_err(|e| Error::new(ErrorKind::Malformed, e))?;

        match self.registry.resolve(&parsed_did).await {
            Ok(our_doc) => {
                let didcomm_doc = self.convert_to_didcomm_doc(our_doc)?;
                trace!(
                    "[MediatorDIDResolver] Resolved locally (vms={}, ka={}, svc={})",
                    didcomm_doc.verification_method.len(),
                    didcomm_doc.key_agreement.len(),
                    didcomm_doc.service.len()
                );
                Ok(Some(didcomm_doc))
            }
            Err(e) => Err(Error::msg(
                ErrorKind::DIDNotResolved,
                format!("DID {} not resolved: {}", did, e),
            )),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// MediatorSecretsResolver
// ────────────────────────────────────────────────────────────────────

/// Secrets Resolver for the mediator server.
///
/// Bridges our wallet to the SICPA didcomm crate's SecretsResolver trait.
/// Handles Ed25519 and X25519 keys, with automatic Ed25519 → X25519 derivation.
pub struct MediatorSecretsResolver {
    wallet: Arc<dyn WalletProvider>,
    did_registry: Arc<DidRegistry>,
}

impl MediatorSecretsResolver {
    pub fn new(wallet: Arc<dyn WalletProvider>, did_registry: Arc<DidRegistry>) -> Self {
        Self {
            wallet,
            did_registry,
        }
    }

    /// Parse key ID into (DID, fragment).
    fn parse_key_id(key_id: &str) -> (String, String) {
        if let Some(hash_pos) = key_id.rfind('#') {
            let did = key_id[..hash_pos].to_string();
            let fragment = key_id[hash_pos + 1..].to_string();
            (did, fragment)
        } else {
            (key_id.to_string(), String::new())
        }
    }

    /// Find wallet key identifier from DID document verification method.
    async fn find_wallet_key_id(
        &self,
        did: &str,
        fragment: &str,
    ) -> Result<Option<(String, String)>> {
        trace!("Looking up key for {}#{}", did, fragment);

        // did:peer:2 — self-resolving
        if did.starts_with("did:peer:2.") {
            return self.resolve_peer_2_key(did, fragment);
        }

        // Resolve DID document via registry
        let parsed_did =
            did::core::DID::parse(did).map_err(|e| Error::new(ErrorKind::Malformed, e))?;

        let doc = match self.did_registry.resolve(&parsed_did).await {
            Ok(doc) => doc,
            Err(_) => {
                warn!("Failed to resolve DID: {}", did);
                return Ok(None);
            }
        };

        // Find matching verification method
        let vm = doc.verification_method.iter().find(|vm| {
            vm.id == format!("{}#{}", did, fragment) || vm.id.ends_with(&format!("#{}", fragment))
        });

        if let Some(vm) = vm {
            trace!("Found verification method: {} (type: {})", vm.id, vm.type_);

            if let Some(multibase_key) = &vm.public_key_multibase {
                return Ok(Some((multibase_key.clone(), vm.type_.clone())));
            }

            if let Some(base58_key) = &vm.public_key_base58 {
                return Ok(Some((base58_key.clone(), vm.type_.clone())));
            }
        }

        warn!(
            "No matching verification method found for {}#{}",
            did, fragment
        );
        Ok(None)
    }

    /// Resolve did:peer:2 key directly from DID string.
    fn resolve_peer_2_key(&self, did: &str, fragment: &str) -> Result<Option<(String, String)>> {
        let parts: Vec<&str> = match did.strip_prefix("did:peer:2.") {
            Some(suffix) => suffix.split('.').collect(),
            None => return Ok(None),
        };

        for part in parts {
            if fragment == "key-1" {
                if let Some(encoded) = part.strip_prefix('V') {
                    let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode V element: {}", e),
                        )
                    })?;

                    if decoded.len() >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
                        trace!("Found Ed25519 key from did:peer:2 V element");
                        return Ok(Some((
                            encoded.to_string(),
                            "Ed25519VerificationKey2020".to_string(),
                        )));
                    }
                }
            } else if fragment == "key-2" {
                if let Some(encoded) = part.strip_prefix('E') {
                    let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode E element: {}", e),
                        )
                    })?;

                    if decoded.len() >= 2 && decoded[0] == 0xec && decoded[1] == 0x01 {
                        trace!("Found X25519 key from did:peer:2 E element");
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

    /// Get private key bytes from wallet, with automatic Ed25519 → X25519 derivation.
    ///
    /// Returns (private_key_bytes, Option<public_key_bytes>).
    async fn get_private_key_bytes(
        &self,
        public_key_identifier: &str,
        key_type: &str,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        trace!("Looking for key type: {}", key_type);

        let is_x25519 = key_type.contains("X25519") || key_type.contains("KeyAgreement");

        let keys = self
            .wallet
            .list_keys()
            .await
            .map_err(|e| Error::new(ErrorKind::SecretNotFound, e))?;

        if is_x25519 {
            // Decode the X25519 public key
            let x25519_public = if public_key_identifier.starts_with('z') {
                let x25519_with_codec = multibase::decode(public_key_identifier)
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode X25519 multibase: {}", e),
                        )
                    })?
                    .1;

                if x25519_with_codec.len() > 2
                    && x25519_with_codec[0] == 0xec
                    && x25519_with_codec[1] == 0x01
                {
                    x25519_with_codec[2..].to_vec()
                } else {
                    x25519_with_codec
                }
            } else {
                bs58::decode(public_key_identifier)
                    .into_vec()
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode X25519 base58: {}", e),
                        )
                    })?
            };

            // First: look for native X25519 key
            for key in &keys {
                if key.key_type == agent_core::traits::KeyType::X25519
                    && key.public_key == x25519_public
                {
                    debug!("Found native X25519 key in wallet: {}", key.id);
                    let x25519_private =
                        self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                            Error::msg(
                                ErrorKind::SecretNotFound,
                                format!("Failed to get X25519 secret: {}", e),
                            )
                        })?;
                    return Ok((x25519_private, Some(key.public_key.clone())));
                }
            }

            // Second: derive X25519 from Ed25519
            trace!("No native X25519 found, trying Ed25519 derivation");
            for key in &keys {
                if key.key_type != agent_core::traits::KeyType::Ed25519 {
                    continue;
                }
                if let Ok(derived) = did::methods::ed25519_public_to_x25519(&key.public_key) {
                    if derived.as_slice() == x25519_public.as_slice() {
                        trace!(
                            "Found matching Ed25519 key for X25519 derivation: {}",
                            key.id
                        );
                        let ed25519_private =
                            self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                                Error::msg(
                                    ErrorKind::SecretNotFound,
                                    format!("Failed to get Ed25519 secret: {}", e),
                                )
                            })?;
                        let (x25519_priv, x25519_pub) =
                            did::methods::ed25519_private_to_x25519(&ed25519_private)
                                .map_err(|e| Error::msg(ErrorKind::Malformed, e))?;
                        return Ok((x25519_priv.to_vec(), Some(x25519_pub.to_vec())));
                    }
                }
            }

            return Err(Error::msg(
                ErrorKind::SecretNotFound,
                "No X25519 or Ed25519 key found matching the requested public key",
            ));
        }

        // For Ed25519 keys
        let ed25519_public = if let Ok((_, decoded)) = multibase::decode(public_key_identifier) {
            if decoded.len() > 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
                decoded[2..].to_vec()
            } else {
                decoded
            }
        } else {
            bs58::decode(public_key_identifier)
                .into_vec()
                .unwrap_or_default()
        };

        for key in keys {
            let matches = if !ed25519_public.is_empty() {
                key.public_key == ed25519_public
            } else {
                let pub_key_base58 = bs58::encode(&key.public_key).into_string();
                public_key_identifier.contains(&pub_key_base58)
                    || pub_key_base58.contains(public_key_identifier)
            };

            if matches {
                debug!("Found matching wallet key: {}", key.id);
                let secret_bytes = self.wallet.get_secret_bytes(&key.id).await.map_err(|e| {
                    Error::msg(
                        ErrorKind::SecretNotFound,
                        format!("Failed to get secret bytes: {}", e),
                    )
                })?;
                return Ok((secret_bytes, None));
            }
        }

        Err(Error::msg(
            ErrorKind::SecretNotFound,
            format!("Key not found for: {}", public_key_identifier),
        ))
    }
}

#[async_trait]
impl SecretsResolver for MediatorSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        trace!("get_secret({})", secret_id);

        let (did, fragment) = Self::parse_key_id(secret_id);
        let (public_key_identifier, key_type) =
            match self.find_wallet_key_id(&did, &fragment).await? {
                Some(result) => result,
                None => {
                    trace!("Secret not found for: {}", secret_id);
                    return Ok(None);
                }
            };

        let is_x25519 = key_type.contains("X25519") || key_type.contains("KeyAgreement");

        let (private_key_bytes, wallet_public_key) = self
            .get_private_key_bytes(&public_key_identifier, &key_type)
            .await?;

        let public_key_bytes = if is_x25519 {
            wallet_public_key
                .ok_or_else(|| Error::msg(ErrorKind::Malformed, "X25519 key missing public key"))?
        } else {
            // For Ed25519 — decode from identifier
            if let Ok((_, decoded)) = multibase::decode(&public_key_identifier) {
                if decoded.len() > 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
                    decoded[2..].to_vec()
                } else {
                    decoded
                }
            } else {
                bs58::decode(&public_key_identifier)
                    .into_vec()
                    .map_err(|e| {
                        Error::msg(
                            ErrorKind::Malformed,
                            format!("Failed to decode public key: {}", e),
                        )
                    })?
            }
        };

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let private_key_b64url = b64.encode(&private_key_bytes);
        let public_key_b64url = b64.encode(&public_key_bytes);

        let private_key_jwk = if is_x25519 {
            serde_json::json!({
                "kty": "OKP",
                "crv": "X25519",
                "d": private_key_b64url,
                "x": public_key_b64url,
            })
        } else {
            serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": private_key_b64url,
                "x": public_key_b64url,
            })
        };

        Ok(Some(Secret {
            id: secret_id.to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK { private_key_jwk },
        }))
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

// ────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────

/// Convert our VerificationMethod to SICPA's VerificationMethod.
fn convert_verification_method(vm: &OurVerificationMethod) -> Result<VerificationMethod> {
    let type_ = map_verification_method_type(&vm.type_)?;

    let verification_material = if let Some(jwk) = &vm.public_key_jwk {
        VerificationMaterial::JWK {
            public_key_jwk: jwk.clone(),
        }
    } else if let Some(multibase) = &vm.public_key_multibase {
        VerificationMaterial::Multibase {
            public_key_multibase: multibase.clone(),
        }
    } else if let Some(base58) = &vm.public_key_base58 {
        VerificationMaterial::Base58 {
            public_key_base58: base58.clone(),
        }
    } else {
        return Err(Error::msg(
            ErrorKind::Malformed,
            "Verification method missing public key material",
        ));
    };

    Ok(VerificationMethod {
        id: vm.id.clone(),
        type_,
        controller: vm.controller.clone(),
        verification_material,
    })
}

fn map_verification_method_type(type_str: &str) -> Result<VerificationMethodType> {
    match type_str {
        "JsonWebKey2020" => Ok(VerificationMethodType::JsonWebKey2020),
        "X25519KeyAgreementKey2019" => Ok(VerificationMethodType::X25519KeyAgreementKey2019),
        "X25519KeyAgreementKey2020" => Ok(VerificationMethodType::X25519KeyAgreementKey2020),
        "Ed25519VerificationKey2018" => Ok(VerificationMethodType::Ed25519VerificationKey2018),
        "Ed25519VerificationKey2020" => Ok(VerificationMethodType::Ed25519VerificationKey2020),
        "EcdsaSecp256k1VerificationKey2019" => {
            Ok(VerificationMethodType::EcdsaSecp256k1VerificationKey2019)
        }
        _ => Ok(VerificationMethodType::Other),
    }
}

fn convert_service(service: &did::core::Service) -> Result<Service> {
    let service_endpoint = if service.type_ == "DIDCommMessaging" || service.type_ == "DIDComm" {
        let uri = if let Some(uri_str) = service.service_endpoint.as_str() {
            uri_str.to_string()
        } else if let Some(obj) = service.service_endpoint.as_object() {
            obj.get("uri")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    Error::msg(ErrorKind::Malformed, "Service endpoint missing uri field")
                })?
                .to_string()
        } else {
            return Err(Error::msg(
                ErrorKind::Malformed,
                "Invalid service endpoint format",
            ));
        };

        let routing_keys = service
            .properties
            .get("routingKeys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let accept = service
            .properties
            .get("accept")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        ServiceKind::DIDCommMessaging {
            value: DIDCommMessagingService {
                uri,
                routing_keys,
                accept,
            },
        }
    } else {
        ServiceKind::Other {
            value: serde_json::json!({
                "type": service.type_,
                "serviceEndpoint": service.service_endpoint
            }),
        }
    };

    Ok(Service {
        id: service.id.clone(),
        service_endpoint,
    })
}

// Ed25519 ↔ X25519 conversions live in `did::methods::x25519` — the
// canonical helpers are `ed25519_public_to_x25519` and
// `ed25519_private_to_x25519`. The mediator's ECDH-decrypt path calls
// them directly (see `get_private_key_bytes` above).

#[cfg(test)]
mod tests {
    use super::*;
    use did::methods::KeyDidResolver;

    #[tokio::test]
    async fn test_mediator_did_resolver_key() {
        let mut registry = DidRegistry::new();
        registry.register_resolver(Arc::new(KeyDidResolver::new()));
        let registry = Arc::new(registry);

        let resolver = MediatorDIDResolver::new(registry);
        let doc = resolver
            .resolve("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
            .await
            .unwrap();

        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert!(doc
            .id
            .contains("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"));
        assert!(!doc.verification_method.is_empty());
        assert!(!doc.authentication.is_empty());
    }

    #[test]
    fn test_vm_type_mapping() {
        assert!(matches!(
            map_verification_method_type("Ed25519VerificationKey2018").unwrap(),
            VerificationMethodType::Ed25519VerificationKey2018
        ));
        assert!(matches!(
            map_verification_method_type("X25519KeyAgreementKey2019").unwrap(),
            VerificationMethodType::X25519KeyAgreementKey2019
        ));
        assert!(matches!(
            map_verification_method_type("UnknownType").unwrap(),
            VerificationMethodType::Other
        ));
    }

    #[test]
    fn test_parse_key_id() {
        let (did, fragment) = MediatorSecretsResolver::parse_key_id("did:key:z6Mk...#z6Mk...");
        assert_eq!(did, "did:key:z6Mk...");
        assert_eq!(fragment, "z6Mk...");

        let (did, fragment) = MediatorSecretsResolver::parse_key_id("did:peer:2...#key-1");
        assert_eq!(did, "did:peer:2...");
        assert_eq!(fragment, "key-1");
    }
}
