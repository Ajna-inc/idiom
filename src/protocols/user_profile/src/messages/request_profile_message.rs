use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const REQUEST_PROFILE_MESSAGE_TYPE: &str =
    "https://didcomm.org/user-profile/1.0/request-profile";

/// DIDComm `user-profile/1.0/request-profile` message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProfileMessage {
    #[serde(rename = "@id")]
    pub id: String,

    #[serde(rename = "@type")]
    pub msg_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<Vec<String>>,
}

impl Default for RequestProfileMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestProfileMessage {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            msg_type: REQUEST_PROFILE_MESSAGE_TYPE.to_string(),
            query: None,
        }
    }

    pub fn with_query(mut self, fields: Vec<String>) -> Self {
        self.query = Some(fields);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_profile_serialization() {
        let msg = RequestProfileMessage::new()
            .with_query(vec!["displayName".into(), "displayPicture".into()]);

        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["@type"], REQUEST_PROFILE_MESSAGE_TYPE);
        assert_eq!(json["query"][0], "displayName");
        assert_eq!(json["query"][1], "displayPicture");
    }

    #[test]
    fn test_request_profile_no_query() {
        let msg = RequestProfileMessage::new();
        let json = serde_json::to_value(&msg).unwrap();

        assert_eq!(json["@type"], REQUEST_PROFILE_MESSAGE_TYPE);
        assert!(json.get("query").is_none());
    }

    #[test]
    fn test_request_profile_deserialization() {
        let wire = serde_json::json!({
            "@type": "https://didcomm.org/user-profile/1.0/request-profile",
            "@id": "req-1",
            "query": ["displayName"]
        });

        let msg: RequestProfileMessage = serde_json::from_value(wire).unwrap();
        assert_eq!(msg.id, "req-1");
        assert_eq!(msg.query, Some(vec!["displayName".to_string()]));
    }
}
