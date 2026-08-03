use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::service::{InlineService, OutOfBandService};

/// Out-of-Band Invitation message as defined in RFC 0434
///
/// This message is used to invite an agent to establish a connection or
/// to initiate a protocol exchange.
///
/// # Message Type
/// `https://didcomm.org/out-of-band/1.1/invitation`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutOfBandInvitation {
    /// Message type
    #[serde(rename = "@type")]
    pub msg_type: String,

    /// Message ID (also serves as invitation ID)
    #[serde(rename = "@id")]
    pub id: String,

    /// Human-readable label for the inviter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Goal code - machine-readable purpose
    #[serde(rename = "goal_code", skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,

    /// Goal - human-readable purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,

    /// Accepted DIDComm profiles
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,

    /// Supported handshake protocols
    #[serde(
        rename = "handshake_protocols",
        skip_serializing_if = "Option::is_none"
    )]
    pub handshake_protocols: Option<Vec<String>>,

    /// Attached protocol request messages
    #[serde(rename = "requests~attach", skip_serializing_if = "Option::is_none")]
    pub requests: Option<Vec<serde_json::Value>>,

    /// Service endpoints (DIDs or inline services)
    pub services: Vec<OutOfBandService>,

    /// Optional image URL
    #[serde(rename = "imageUrl", skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
}

impl OutOfBandInvitation {
    /// Message type constant
    pub const MESSAGE_TYPE: &'static str = "https://didcomm.org/out-of-band/1.1/invitation";

    /// Default accepted profiles
    pub const DEFAULT_ACCEPT: &'static [&'static str] = &["didcomm/aip2;env=rfc19"];

    /// Create a new invitation with services
    pub fn new(services: Vec<OutOfBandService>) -> Self {
        Self {
            msg_type: Self::MESSAGE_TYPE.to_string(),
            id: Uuid::new_v4().to_string(),
            label: None,
            goal_code: None,
            goal: None,
            accept: Some(Self::DEFAULT_ACCEPT.iter().map(|s| s.to_string()).collect()),
            handshake_protocols: None,
            requests: None,
            services,
            image_url: None,
        }
    }

    /// Set label
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Set goal code and goal
    pub fn with_goal(mut self, goal_code: String, goal: String) -> Self {
        self.goal_code = Some(goal_code);
        self.goal = Some(goal);
        self
    }

    /// Set handshake protocols
    pub fn with_handshake_protocols(mut self, protocols: Vec<String>) -> Self {
        self.handshake_protocols = Some(protocols);
        self
    }

    /// Set image URL
    pub fn with_image_url(mut self, url: String) -> Self {
        self.image_url = Some(url);
        self
    }

    /// Encode invitation to base64url for URL embedding
    pub fn to_url(&self, domain: &str) -> Result<String, Box<dyn std::error::Error>> {
        let json = serde_json::to_string(self)?;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        Ok(format!("{}?oob={}", domain, encoded))
    }

    /// Decode invitation from URL
    pub fn from_url(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parsed = url::Url::parse(url)?;

        // Find the 'oob' query parameter
        let oob_param = parsed
            .query_pairs()
            .find(|(key, _)| key == "oob")
            .map(|(_, value)| value)
            .ok_or("Missing 'oob' parameter in URL")?;

        // Decode base64
        let json = URL_SAFE_NO_PAD.decode(oob_param.as_bytes())?;

        // Parse JSON
        let invitation: Self = serde_json::from_slice(&json)?;

        // Debug: Log parsed invitation services
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!(
                "Parsed OOB invitation from URL: id={}, services count={}",
                invitation.id,
                invitation.services.len()
            );
            for (i, service) in invitation.services.iter().enumerate() {
                match service {
                    super::service::OutOfBandService::Did(did) => {
                        tracing::debug!("  service[{}]: Did({})", i, did);
                    }
                    super::service::OutOfBandService::Inline(inline) => {
                        tracing::debug!(
                            "  service[{}]: Inline endpoint={} recipient_keys={:?} routing_keys={:?}",
                            i,
                            inline.service_endpoint,
                            inline.recipient_keys,
                            inline.routing_keys
                        );
                    }
                }
            }
        }

        Ok(invitation)
    }

    /// Get all DIDs from services
    ///
    /// For inline services, this would require converting to did:peer
    /// For now, we just return DID references
    pub fn get_invitation_dids(&self) -> Vec<String> {
        self.services
            .iter()
            .filter_map(|service| match service {
                OutOfBandService::Did(did) => Some(did.clone()),
                OutOfBandService::Inline(_) => None, // Would need to convert to did:peer
            })
            .collect()
    }

    /// Get inline service descriptors
    pub fn get_inline_services(&self) -> Vec<&InlineService> {
        self.services
            .iter()
            .filter_map(|service| match service {
                OutOfBandService::Inline(inline) => Some(inline),
                OutOfBandService::Did(_) => None,
            })
            .collect()
    }

    /// Get DID services (references only)
    pub fn get_did_services(&self) -> Vec<&String> {
        self.services
            .iter()
            .filter_map(|service| match service {
                OutOfBandService::Did(did) => Some(did),
                OutOfBandService::Inline(_) => None,
            })
            .collect()
    }

    /// Check if invitation includes handshake protocols
    pub fn has_handshake(&self) -> bool {
        self.handshake_protocols
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    /// Check if invitation includes attached requests
    pub fn has_requests(&self) -> bool {
        self.requests
            .as_ref()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_creation() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        assert_eq!(invitation.msg_type, OutOfBandInvitation::MESSAGE_TYPE);
        assert!(!invitation.id.is_empty());
        assert_eq!(invitation.services.len(), 1);
    }

    #[test]
    fn test_invitation_builder() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Faber College".to_string())
                .with_goal("issue-vc".to_string(), "To issue a credential".to_string())
                .with_handshake_protocols(vec!["https://didcomm.org/didexchange/1.1".to_string()])
                .with_image_url("https://faber.edu/logo.png".to_string());

        assert_eq!(invitation.label, Some("Faber College".to_string()));
        assert_eq!(invitation.goal_code, Some("issue-vc".to_string()));
        assert_eq!(invitation.goal, Some("To issue a credential".to_string()));
        assert_eq!(invitation.handshake_protocols.as_ref().unwrap().len(), 1);
        assert_eq!(
            invitation.image_url,
            Some("https://faber.edu/logo.png".to_string())
        );
    }

    #[test]
    fn test_invitation_serialization() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Test".to_string())
                .with_goal("test".to_string(), "Testing".to_string());

        let json = serde_json::to_string(&invitation).unwrap();

        // Verify field names
        assert!(json.contains("\"@type\""));
        assert!(json.contains("\"@id\""));
        assert!(json.contains("\"goal_code\""));
        assert!(json.contains("\"label\""));

        // Deserialize
        let deserialized: OutOfBandInvitation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, invitation);
    }

    #[test]
    fn test_invitation_with_inline_service() {
        let service = InlineService::new(
            "#inline-0".to_string(),
            vec!["did:key:z6MkpTHR...".to_string()],
            vec![],
            "https://example.com/didcomm".to_string(),
        );

        let invitation = OutOfBandInvitation::new(vec![OutOfBandService::Inline(service.clone())]);

        let inline_services = invitation.get_inline_services();
        assert_eq!(inline_services.len(), 1);
        assert_eq!(inline_services[0], &service);
    }

    #[test]
    fn test_url_encoding_decoding() {
        let invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())])
                .with_label("Test".to_string());

        let url = invitation.to_url("https://example.com").unwrap();

        assert!(url.starts_with("https://example.com?oob="));

        let decoded = OutOfBandInvitation::from_url(&url).unwrap();
        assert_eq!(decoded.id, invitation.id);
        assert_eq!(decoded.label, invitation.label);
        assert_eq!(decoded.services, invitation.services);
    }

    #[test]
    fn test_get_invitation_dids() {
        let invitation = OutOfBandInvitation::new(vec![
            OutOfBandService::Did("did:example:123".to_string()),
            OutOfBandService::Did("did:example:456".to_string()),
            OutOfBandService::Inline(InlineService::new(
                "#inline-0".to_string(),
                vec![],
                vec![],
                "https://example.com".to_string(),
            )),
        ]);

        let dids = invitation.get_invitation_dids();
        assert_eq!(dids.len(), 2);
        assert!(dids.contains(&"did:example:123".to_string()));
        assert!(dids.contains(&"did:example:456".to_string()));
    }

    #[test]
    fn test_has_handshake_and_requests() {
        let mut invitation =
            OutOfBandInvitation::new(vec![OutOfBandService::Did("did:example:123".to_string())]);

        assert!(!invitation.has_handshake());
        assert!(!invitation.has_requests());

        invitation.handshake_protocols = Some(vec!["test".to_string()]);
        assert!(invitation.has_handshake());

        invitation.requests = Some(vec![serde_json::json!({"test": "data"})]);
        assert!(invitation.has_requests());
    }

    #[test]
    fn test_aries_ts_compatibility() {
        let aries_json = r#"{
            "@type": "https://didcomm.org/out-of-band/1.1/invitation",
            "@id": "test-id",
            "label": "Aries TS Agent",
            "goal_code": "issue-vc",
            "goal": "To issue a credential",
            "accept": ["didcomm/aip2;env=rfc19"],
            "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
            "services": ["did:example:123"]
        }"#;

        let invitation: OutOfBandInvitation = serde_json::from_str(aries_json).unwrap();

        assert_eq!(invitation.id, "test-id");
        assert_eq!(invitation.label, Some("Aries TS Agent".to_string()));
        assert_eq!(invitation.goal_code, Some("issue-vc".to_string()));

        // Serialize back and compare
        let rust_json = serde_json::to_value(&invitation).unwrap();
        let aries_value: serde_json::Value = serde_json::from_str(aries_json).unwrap();

        assert_eq!(rust_json["@type"], aries_value["@type"]);
        assert_eq!(rust_json["goal_code"], aries_value["goal_code"]);
    }
}
