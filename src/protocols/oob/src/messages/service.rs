use serde::{Deserialize, Serialize};

/// Service descriptor in an Out-of-Band invitation
///
/// Can be either a DID reference or an inline service descriptor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutOfBandService {
    /// DID reference - the service is defined in the DID document
    Did(String),

    /// Inline service descriptor with full details
    Inline(InlineService),
}

/// Inline service descriptor for Out-of-Band invitations
///
/// Provides all necessary information to communicate without resolving a DID
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineService {
    /// Service ID (usually #inline-0, #inline-1, etc.)
    pub id: String,

    /// Service type (typically "did-communication" or "DIDCommMessaging")
    #[serde(rename = "type")]
    pub service_type: String,

    /// Recipient keys for sending messages (as did:key DIDs)
    #[serde(rename = "recipientKeys")]
    pub recipient_keys: Vec<String>,

    /// Routing keys for mediation (as did:key DIDs)
    #[serde(rename = "routingKeys", default)]
    pub routing_keys: Vec<String>,

    /// Service endpoint URL
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

impl InlineService {
    /// Create a new inline service
    pub fn new(
        id: String,
        recipient_keys: Vec<String>,
        routing_keys: Vec<String>,
        service_endpoint: String,
    ) -> Self {
        Self {
            id,
            service_type: "did-communication".to_string(),
            recipient_keys,
            routing_keys,
            service_endpoint,
        }
    }

    /// Create with default type
    pub fn with_type(mut self, service_type: String) -> Self {
        self.service_type = service_type;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_service_serialization() {
        let service = OutOfBandService::Did("did:example:123".to_string());
        let json = serde_json::to_string(&service).unwrap();
        assert_eq!(json, "\"did:example:123\"");

        let deserialized: OutOfBandService = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, service);
    }

    #[test]
    fn test_inline_service_serialization() {
        let service = OutOfBandService::Inline(InlineService {
            id: "#inline-0".to_string(),
            service_type: "did-communication".to_string(),
            recipient_keys: vec!["did:key:z6MkpTHR...".to_string()],
            routing_keys: vec![],
            service_endpoint: "https://example.com/didcomm".to_string(),
        });

        let json = serde_json::to_string(&service).unwrap();
        let deserialized: OutOfBandService = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, service);

        // Verify field names
        assert!(json.contains("\"recipientKeys\""));
        assert!(json.contains("\"routingKeys\""));
        assert!(json.contains("\"serviceEndpoint\""));
        assert!(json.contains("\"type\""));
    }

    #[test]
    fn test_inline_service_builder() {
        let service = InlineService::new(
            "#inline-0".to_string(),
            vec!["did:key:z6MkpTHR...".to_string()],
            vec![],
            "https://example.com/didcomm".to_string(),
        );

        assert_eq!(service.id, "#inline-0");
        assert_eq!(service.service_type, "did-communication");
        assert_eq!(service.recipient_keys.len(), 1);
        assert_eq!(service.routing_keys.len(), 0);
    }

    #[test]
    fn test_with_type() {
        let service = InlineService::new(
            "#inline-0".to_string(),
            vec!["did:key:z6MkpTHR...".to_string()],
            vec![],
            "https://example.com/didcomm".to_string(),
        )
        .with_type("DIDCommMessaging".to_string());

        assert_eq!(service.service_type, "DIDCommMessaging");
    }

    #[test]
    fn test_inline_service_with_routing_keys_deserialization() {
        // This is the exact JSON format from an OOB invitation with mediator routing
        let json = r##"{"id":"#service-1","type":"did-communication","recipientKeys":["did:key:z6MktaasSsK6hczCN8xqmEtLfe1vry7UiQRRHcgBjhjoxwGa"],"routingKeys":["did:key:z6MkfkdtCVysvdiEsEpKdnhwb7FjoPBjc67MTeR3bQCp68tS"],"serviceEndpoint":"https://mediator.ajna.dev"}"##;

        let service: OutOfBandService = serde_json::from_str(json).unwrap();

        match service {
            OutOfBandService::Inline(inline) => {
                assert_eq!(inline.id, "#service-1");
                assert_eq!(inline.service_type, "did-communication");
                assert_eq!(inline.recipient_keys.len(), 1);
                assert!(inline.recipient_keys[0].starts_with("did:key:z6Mkt"));
                assert_eq!(
                    inline.routing_keys.len(),
                    1,
                    "routing_keys should have 1 element"
                );
                assert!(inline.routing_keys[0].starts_with("did:key:z6Mkf"));
                assert_eq!(inline.service_endpoint, "https://mediator.ajna.dev");
                println!(
                    "routing_keys correctly deserialized: {:?}",
                    inline.routing_keys
                );
            }
            OutOfBandService::Did(_) => {
                panic!("Expected InlineService, got Did");
            }
        }
    }

    #[test]
    fn test_full_invitation_with_routing_keys() {
        // Full invitation JSON from iOS logs
        let json = r##"{"@type":"https://didcomm.org/out-of-band/1.1/invitation","@id":"97d77213-0ba7-4b11-87c5-f54162e29a48","label":"BWN Wallet","accept":["didcomm/aip2;env=rfc19"],"handshake_protocols":["https://didcomm.org/didexchange/1.1"],"services":[{"id":"#service-1","type":"did-communication","recipientKeys":["did:key:z6MktaasSsK6hczCN8xqmEtLfe1vry7UiQRRHcgBjhjoxwGa"],"routingKeys":["did:key:z6MkfkdtCVysvdiEsEpKdnhwb7FjoPBjc67MTeR3bQCp68tS"],"serviceEndpoint":"https://mediator.ajna.dev"}]}"##;

        let invitation: super::super::OutOfBandInvitation = serde_json::from_str(json).unwrap();

        assert_eq!(invitation.services.len(), 1);
        match &invitation.services[0] {
            OutOfBandService::Inline(inline) => {
                assert_eq!(
                    inline.routing_keys.len(),
                    1,
                    "routing_keys should have 1 element in full invitation"
                );
                println!("Full invitation routing_keys: {:?}", inline.routing_keys);
            }
            _ => panic!("Expected InlineService"),
        }
    }
}
