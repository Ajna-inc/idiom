use crate::core::{error::Result, DidcommError};
use did::core::{DidDocument, DID};
use std::sync::Arc;

/// Service endpoint for DIDComm messaging
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    /// Service ID
    pub id: String,

    /// Service type (e.g., "DIDCommMessaging")
    pub service_type: Vec<String>,

    /// Service endpoint URI
    pub service_endpoint: String,

    /// Routing keys for message forwarding
    pub routing_keys: Vec<String>,

    /// Accept types (message types this endpoint accepts)
    pub accept: Vec<String>,
}

/// Trait for DID resolution (to be implemented by did_registry)
#[async_trait::async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve a DID to a DID Document
    async fn resolve(&self, did: &str) -> Result<DidDocument>;
}

/// DIDComm Document Service
///
/// Provides DID document resolution and service endpoint extraction
/// specifically for DIDComm messaging operations.
pub struct DidCommDocumentService {
    did_resolver: Arc<dyn DidResolver>,
}

impl DidCommDocumentService {
    /// Create a new DidCommDocumentService
    pub fn new(did_resolver: Arc<dyn DidResolver>) -> Self {
        Self { did_resolver }
    }

    /// Resolve a DID for DIDComm use
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    /// The DID Document
    pub async fn resolve_for_didcomm(&self, did: &str) -> Result<DidDocument> {
        let did_obj = DID::parse(did).map_err(|e| DidcommError::InvalidDid(e.to_string()))?;

        self.did_resolver
            .resolve(did_obj.as_str())
            .await
            .map_err(|e| DidcommError::DidResolution(e.to_string()))
    }

    /// Extract DIDComm service endpoints from a DID Document
    ///
    /// # Arguments
    /// * `doc` - The DID Document to extract services from
    ///
    /// # Returns
    /// Vector of DIDComm service endpoints
    pub fn get_didcomm_services(&self, doc: &DidDocument) -> Vec<ServiceEndpoint> {
        let mut endpoints = Vec::new();

        for service in &doc.service {
            // Check if this is a DIDComm service
            let type_str = &service.type_;
            let is_didcomm = type_str == "DIDCommMessaging"
                || type_str == "DIDComm"
                || type_str == "dm"
                || type_str.contains("didcomm");

            if !is_didcomm {
                continue;
            }

            // Extract service endpoint
            let service_endpoint = match &service.service_endpoint {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => {
                    // Take first endpoint if array
                    arr.first()
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                }
                serde_json::Value::Object(obj) => {
                    // Extract "uri" field from object
                    obj.get("uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                }
                _ => continue,
            };

            if service_endpoint.is_empty() {
                continue;
            }

            // Extract routing keys if present
            let routing_keys = service
                .properties
                .get("routingKeys")
                .or_else(|| service.properties.get("routing_keys"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Extract accept types if present
            let accept = service
                .properties
                .get("accept")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            endpoints.push(ServiceEndpoint {
                id: service.id.clone(),
                service_type: vec![service.type_.clone()],
                service_endpoint,
                routing_keys,
                accept,
            });
        }

        endpoints
    }

    /// Find the primary DIDComm endpoint for a DID
    ///
    /// # Arguments
    /// * `did` - The DID to find endpoint for
    ///
    /// # Returns
    /// The primary service endpoint URI, or error if none found
    pub async fn get_primary_endpoint(&self, did: &str) -> Result<String> {
        let doc = self.resolve_for_didcomm(did).await?;
        let services = self.get_didcomm_services(&doc);

        services
            .first()
            .map(|s| s.service_endpoint.clone())
            .ok_or_else(|| DidcommError::ServiceNotFound(did.to_string()))
    }

    /// Get all DIDComm endpoints for a DID
    ///
    /// # Arguments
    /// * `did` - The DID to find endpoints for
    ///
    /// # Returns
    /// Vector of service endpoint URIs
    pub async fn get_all_endpoints(&self, did: &str) -> Result<Vec<String>> {
        let doc = self.resolve_for_didcomm(did).await?;
        let services = self.get_didcomm_services(&doc);

        Ok(services.into_iter().map(|s| s.service_endpoint).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did::core::{Service, VerificationMethod, VerificationRelationship};

    fn create_test_did_document() -> DidDocument {
        DidDocument {
            context: Some(serde_json::json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ])),
            id: "did:example:123".to_string(),
            verification_method: vec![VerificationMethod {
                id: "did:example:123#key-1".to_string(),
                controller: "did:example:123".to_string(),
                type_: "Ed25519VerificationKey2020".to_string(),
                public_key_multibase: Some(
                    "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string(),
                ),
                public_key_jwk: None,
                public_key_base58: None,
            }],
            authentication: vec![VerificationRelationship::Reference(
                "did:example:123#key-1".to_string(),
            )],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![Service {
                id: "did:example:123#didcomm-1".to_string(),
                type_: "DIDCommMessaging".to_string(),
                service_endpoint: serde_json::Value::String(
                    "https://example.com/didcomm".to_string(),
                ),
                properties: std::collections::HashMap::new(),
            }],
            also_known_as: vec![],
            controller: None,
        }
    }

    #[test]
    fn test_extract_didcomm_services() {
        let doc = create_test_did_document();

        // Create a mock resolver (we'll just test the extraction logic)
        struct MockResolver;
        #[async_trait::async_trait]
        impl DidResolver for MockResolver {
            async fn resolve(&self, _did: &str) -> Result<DidDocument> {
                Ok(create_test_did_document())
            }
        }

        let service = DidCommDocumentService::new(Arc::new(MockResolver));
        let endpoints = service.get_didcomm_services(&doc);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].service_endpoint, "https://example.com/didcomm");
        assert_eq!(endpoints[0].service_type, vec!["DIDCommMessaging"]);
    }

    #[test]
    fn test_service_endpoint_with_routing_keys() {
        let mut doc = create_test_did_document();

        // Add routing keys to the service
        let mut properties = std::collections::HashMap::new();
        properties.insert(
            "routingKeys".to_string(),
            serde_json::json!(["did:example:mediator#key-1"]),
        );

        doc.service[0].properties = properties;

        struct MockResolver;
        #[async_trait::async_trait]
        impl DidResolver for MockResolver {
            async fn resolve(&self, _did: &str) -> Result<DidDocument> {
                Ok(create_test_did_document())
            }
        }

        let service = DidCommDocumentService::new(Arc::new(MockResolver));
        let endpoints = service.get_didcomm_services(&doc);

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].routing_keys.len(), 1);
        assert_eq!(endpoints[0].routing_keys[0], "did:example:mediator#key-1");
    }

    #[tokio::test]
    async fn test_resolve_for_didcomm() {
        struct MockResolver;
        #[async_trait::async_trait]
        impl DidResolver for MockResolver {
            async fn resolve(&self, _did: &str) -> Result<DidDocument> {
                Ok(create_test_did_document())
            }
        }

        let service = DidCommDocumentService::new(Arc::new(MockResolver));
        let doc = service
            .resolve_for_didcomm("did:example:123")
            .await
            .unwrap();

        assert_eq!(doc.id, "did:example:123");
    }

    #[tokio::test]
    async fn test_get_primary_endpoint() {
        struct MockResolver;
        #[async_trait::async_trait]
        impl DidResolver for MockResolver {
            async fn resolve(&self, _did: &str) -> Result<DidDocument> {
                Ok(create_test_did_document())
            }
        }

        let service = DidCommDocumentService::new(Arc::new(MockResolver));
        let endpoint = service
            .get_primary_endpoint("did:example:123")
            .await
            .unwrap();

        assert_eq!(endpoint, "https://example.com/didcomm");
    }
}
