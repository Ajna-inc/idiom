//! DID Resolver adapter for SICPA didcomm crate
//!
//! Bridges our DidRegistry to the didcomm crate's DIDResolver trait.
//! Optionally integrates with Kademlia DHT for network-based DID resolution.

use async_trait::async_trait;
use did::core::{
    DidDocument, VerificationMethod as OurVerificationMethod, VerificationRelationship,
};
use did::registry::DidRegistry;
use sicpa_didcomm::did::{
    DIDCommMessagingService, DIDDoc, DIDResolver, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};
use sicpa_didcomm::error::{Error, ErrorKind, Result};
use std::sync::Arc;

/// Adapter that implements didcomm's DIDResolver using our DidRegistry
///
/// Supports optional DHT fallback for network-based DID resolution when
/// local resolution fails. Uses interior mutability to allow setting DHT
/// after the resolver is created (required because Agent creates DHT after
/// initializing the resolver).
pub struct AgentDIDResolver {
    registry: Arc<DidRegistry>,
    /// Resolved-DIDDoc cache. `resolve()` is called several times per DIDComm
    /// pack/unpack (recipient + sender key material) and otherwise rebuilds the
    /// whole doc — multibase decodes + ~20 allocations — every time. did:peer /
    /// did:key resolution is deterministic (the DID encodes the doc), so caching
    /// is safe; registry DIDs are effectively immutable over a session. This is
    /// the dominant per-message plumbing cost, not the crypto.
    cache: dashmap::DashMap<String, DIDDoc>,
}

impl AgentDIDResolver {
    /// Create a new AgentDIDResolver
    pub fn new(registry: Arc<DidRegistry>) -> Self {
        Self {
            registry,
            cache: dashmap::DashMap::new(),
        }
    }

    /// Resolve did:peer:2 locally (self-resolving, no registry needed)
    ///
    /// did:peer:2 format: did:peer:2.V<auth_key>.E<agreement_key>.S<service>
    ///
    /// This is a SELF-RESOLVING DID - all information is encoded in the DID itself!
    fn resolve_peer_2(&self, did: &str) -> Result<DIDDoc> {
        tracing::debug!("[DIDResolver] Resolving did:peer:2: {}", did);

        // Parse did:peer:2 format
        let parts: Vec<&str> = did
            .strip_prefix("did:peer:2.")
            .ok_or_else(|| {
                Error::msg(
                    ErrorKind::Malformed,
                    "Invalid did:peer:2 format - missing 'did:peer:2.' prefix",
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
                // Verification method (authentication)
                let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Failed to decode V element: {}", e),
                    )
                })?;

                // Extract multicodec prefix (0xed 0x01 for Ed25519)
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
                // Encryption (key agreement)
                let (_, decoded) = multibase::decode(encoded).map_err(|e| {
                    Error::msg(
                        ErrorKind::Malformed,
                        format!("Failed to decode E element: {}", e),
                    )
                })?;

                // Extract multicodec prefix (0xec 0x01 for X25519)
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
                // Service endpoint - service uses base64url (NOT multibase)
                // Try base64url first, fall back to multibase for legacy support
                use base64::engine::Engine;
                let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .or_else(|_| {
                        // Fall back to multibase (legacy format) for backwards compatibility
                        multibase::decode(encoded).map(|(_, bytes)| bytes)
                    })
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

                // Extract service endpoint
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

        tracing::debug!(
            "[DIDResolver] Resolved did:peer:2 (vms={}, ka={}, svc={})",
            verification_methods.len(),
            key_agreement.len(),
            services.len()
        );

        Ok(DIDDoc {
            id: did.to_string(),
            verification_method: verification_methods,
            key_agreement,
            authentication,
            service: services,
        })
    }

    /// Convert our DidDocument to didcomm's DIDDoc format
    fn convert_to_didcomm_doc(&self, our_doc: DidDocument) -> Result<DIDDoc> {
        // Convert verification methods
        let verification_method = our_doc
            .verification_method
            .iter()
            .map(|vm| self.convert_verification_method(vm))
            .collect::<Result<Vec<_>>>()?;

        // Extract key agreement references
        let key_agreement = our_doc
            .key_agreement
            .iter()
            .map(|rel| match rel {
                VerificationRelationship::Reference(r) => r.clone(),
                VerificationRelationship::Embedded(vm) => vm.id.clone(),
            })
            .collect();

        // Extract authentication references
        let authentication = our_doc
            .authentication
            .iter()
            .map(|rel| match rel {
                VerificationRelationship::Reference(r) => r.clone(),
                VerificationRelationship::Embedded(vm) => vm.id.clone(),
            })
            .collect();

        // Convert services
        let service = our_doc
            .service
            .iter()
            .filter_map(|s| self.convert_service(s).ok())
            .collect();

        Ok(DIDDoc {
            id: our_doc.id,
            verification_method,
            key_agreement,
            authentication,
            service,
        })
    }

    /// Convert our VerificationMethod to didcomm's VerificationMethod
    fn convert_verification_method(
        &self,
        vm: &OurVerificationMethod,
    ) -> Result<VerificationMethod> {
        tracing::trace!("[DIDResolver] convert_vm id={}, type={}", vm.id, vm.type_);

        // Determine verification method type
        let type_ = self.map_verification_method_type(&vm.type_)?;

        // Extract verification material
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

    /// Map our verification method type string to didcomm's enum
    fn map_verification_method_type(&self, type_str: &str) -> Result<VerificationMethodType> {
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

    /// Convert our Service to didcomm's Service
    fn convert_service(&self, service: &did::core::Service) -> Result<Service> {
        let service_endpoint = if service.type_ == "DIDCommMessaging" || service.type_ == "DIDComm"
        {
            // Parse DIDComm messaging service
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

            // Extract routing keys if present
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

            // Extract accept if present
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
            // Other service types
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
}

#[async_trait]
impl DIDResolver for AgentDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        // Strip fragment from DID URL if present (e.g., "did:key:z6Mk...#z6Mk..." -> "did:key:z6Mk...")
        // DID URLs can include fragments to reference specific verification methods.
        // The resolver should resolve the base DID; the DIDComm library handles fragment dereferencing.
        let base_did = did.split('#').next().unwrap_or(did);

        // Fast path: memoized resolution (deterministic for did:peer/did:key,
        // immutable-over-session for registry DIDs). Avoids rebuilding the doc on
        // every pack/unpack.
        if let Some(doc) = self.cache.get(base_did) {
            return Ok(Some(doc.clone()));
        }

        tracing::debug!("[DIDResolver] Resolving: {}", base_did);

        // Check if this is did:peer:2 (self-resolving)
        if base_did.starts_with("did:peer:2.") {
            let didcomm_doc = self.resolve_peer_2(base_did)?;
            self.cache.insert(base_did.to_string(), didcomm_doc.clone());
            return Ok(Some(didcomm_doc));
        }

        // For other DIDs, use registry
        // Parse DID string
        let parsed_did =
            did::core::DID::parse(base_did).map_err(|e| Error::new(ErrorKind::Malformed, e))?;

        // Try resolving using our registry first (fast path - local)
        let registry_result = self.registry.resolve(&parsed_did).await;

        match registry_result {
            Ok(our_doc) => {
                // Convert to didcomm format
                let didcomm_doc = self.convert_to_didcomm_doc(our_doc)?;

                tracing::debug!(
                    "[DIDResolver] Resolved locally (vms={}, ka={}, svc={})",
                    didcomm_doc.verification_method.len(),
                    didcomm_doc.key_agreement.len(),
                    didcomm_doc.service.len()
                );

                self.cache.insert(base_did.to_string(), didcomm_doc.clone());
                Ok(Some(didcomm_doc))
            }
            Err(local_error) => {
                // Return the original local error if DHT lookup didn't succeed
                Err(Error::msg(
                    ErrorKind::DIDNotResolved,
                    format!(
                        "DID {} not found in DHT or local storage: {}",
                        did, local_error
                    ),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did::core::VerificationMethod as OurVM;

    #[test]
    fn test_verification_method_type_mapping() {
        let resolver = AgentDIDResolver::new(Arc::new(DidRegistry::new()));

        assert!(matches!(
            resolver
                .map_verification_method_type("Ed25519VerificationKey2018")
                .unwrap(),
            VerificationMethodType::Ed25519VerificationKey2018
        ));

        assert!(matches!(
            resolver
                .map_verification_method_type("X25519KeyAgreementKey2019")
                .unwrap(),
            VerificationMethodType::X25519KeyAgreementKey2019
        ));

        assert!(matches!(
            resolver
                .map_verification_method_type("JsonWebKey2020")
                .unwrap(),
            VerificationMethodType::JsonWebKey2020
        ));

        assert!(matches!(
            resolver
                .map_verification_method_type("UnknownType")
                .unwrap(),
            VerificationMethodType::Other
        ));
    }

    #[test]
    fn test_convert_verification_method_with_multibase() {
        let resolver = AgentDIDResolver::new(Arc::new(DidRegistry::new()));

        let our_vm = OurVM::new(
            "did:key:z6Mk...#key-1".to_string(),
            "Ed25519VerificationKey2020".to_string(),
            "did:key:z6Mk...".to_string(),
        )
        .with_public_key_multibase("z6Mk...".to_string());

        let didcomm_vm = resolver.convert_verification_method(&our_vm).unwrap();

        assert_eq!(didcomm_vm.id, "did:key:z6Mk...#key-1");
        assert!(matches!(
            didcomm_vm.type_,
            VerificationMethodType::Ed25519VerificationKey2020
        ));
        assert!(matches!(
            didcomm_vm.verification_material,
            VerificationMaterial::Multibase { .. }
        ));
    }
}
