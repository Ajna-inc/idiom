use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::attachment::{V1Attachment, V1AttachmentData};

pub const PROFILE_MESSAGE_TYPE: &str = "https://didcomm.org/user-profile/1.0/profile";

/// Profile data payload (camelCase on wire for interop with Python/TypeScript)
///
/// `displayPicture` and `displayIcon` use `serde_json::Value` because they can be:
/// - A sentinel string like `"#displayPicture"` (references `~attach`)
/// - An inline object `{"mimeType":"...","base64":"...","links":[]}`
/// - An empty string `""` (clear the field)
/// - JSON `null` (clear the field)
/// - Absent (no change — merge semantics)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileData {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(rename = "displayPicture", skip_serializing_if = "Option::is_none")]
    pub display_picture: Option<serde_json::Value>,

    #[serde(rename = "displayIcon", skip_serializing_if = "Option::is_none")]
    pub display_icon: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "preferredLanguage", skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
}

impl Default for ProfileData {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileData {
    pub fn new() -> Self {
        Self {
            display_name: None,
            display_picture: None,
            display_icon: None,
            description: None,
            preferred_language: None,
        }
    }
}

/// DIDComm `user-profile/1.0/profile` message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMessage {
    #[serde(rename = "@id")]
    pub id: String,

    #[serde(rename = "@type")]
    pub msg_type: String,

    pub profile: ProfileData,

    #[serde(default)]
    pub send_back_yours: bool,

    #[serde(rename = "~attach", skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<V1Attachment>>,
}

impl ProfileMessage {
    pub fn new(profile: ProfileData) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            msg_type: PROFILE_MESSAGE_TYPE.to_string(),
            profile,
            send_back_yours: false,
            attachments: None,
        }
    }

    pub fn with_send_back_yours(mut self, val: bool) -> Self {
        self.send_back_yours = val;
        self
    }

    /// Move `displayPicture` inline data into `~attach` and replace with sentinel.
    pub fn with_picture_attachment(mut self, mime_type: &str, base64_data: &str) -> Self {
        self.profile.display_picture = Some(serde_json::Value::String("#displayPicture".into()));
        let attach = V1Attachment {
            id: "displayPicture".to_string(),
            mime_type: mime_type.to_string(),
            data: V1AttachmentData {
                base64: base64_data.to_string(),
            },
        };
        self.attachments.get_or_insert_with(Vec::new).push(attach);
        self
    }

    /// Move `displayIcon` inline data into `~attach` and replace with sentinel.
    pub fn with_icon_attachment(mut self, mime_type: &str, base64_data: &str) -> Self {
        self.profile.display_icon = Some(serde_json::Value::String("#displayIcon".into()));
        let attach = V1Attachment {
            id: "displayIcon".to_string(),
            mime_type: mime_type.to_string(),
            data: V1AttachmentData {
                base64: base64_data.to_string(),
            },
        };
        self.attachments.get_or_insert_with(Vec::new).push(attach);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_message_serialization() {
        let mut profile = ProfileData::new();
        profile.display_name = Some("Alice".into());
        profile.description = Some("Hello world".into());
        profile.preferred_language = Some("en".into());

        let msg = ProfileMessage::new(profile);
        let json = serde_json::to_value(&msg).unwrap();

        assert_eq!(json["@type"], PROFILE_MESSAGE_TYPE);
        assert_eq!(json["profile"]["displayName"], "Alice");
        assert_eq!(json["profile"]["description"], "Hello world");
        assert_eq!(json["profile"]["preferredLanguage"], "en");
        assert_eq!(json["send_back_yours"], false);
        assert!(json.get("~attach").is_none());
    }

    #[test]
    fn test_profile_message_with_picture_attachment() {
        let profile = ProfileData::new();
        let msg = ProfileMessage::new(profile).with_picture_attachment("image/png", "iVBORw0KGgo=");

        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["profile"]["displayPicture"], "#displayPicture");
        assert_eq!(json["~attach"][0]["@id"], "displayPicture");
        assert_eq!(json["~attach"][0]["mime-type"], "image/png");
        assert_eq!(json["~attach"][0]["data"]["base64"], "iVBORw0KGgo=");
    }

    #[test]
    fn test_profile_message_deserialization_from_wire() {
        let wire_json = serde_json::json!({
            "@type": "https://didcomm.org/user-profile/1.0/profile",
            "@id": "abc-123",
            "profile": {
                "displayName": "Bob",
                "displayPicture": "#displayPicture",
                "description": "I am Bob"
            },
            "send_back_yours": true,
            "~attach": [{
                "@id": "displayPicture",
                "mime-type": "image/jpeg",
                "data": { "base64": "abc==" }
            }]
        });

        let msg: ProfileMessage = serde_json::from_value(wire_json).unwrap();
        assert_eq!(msg.id, "abc-123");
        assert_eq!(msg.profile.display_name, Some("Bob".into()));
        assert_eq!(
            msg.profile.display_picture,
            Some(serde_json::Value::String("#displayPicture".into()))
        );
        assert!(msg.send_back_yours);
        assert_eq!(msg.attachments.as_ref().unwrap().len(), 1);
        assert_eq!(msg.attachments.as_ref().unwrap()[0].mime_type, "image/jpeg");
    }

    #[test]
    fn test_profile_clear_fields() {
        let wire_json = serde_json::json!({
            "@type": "https://didcomm.org/user-profile/1.0/profile",
            "@id": "clear-test",
            "profile": {
                "displayName": "Keep",
                "displayPicture": "",
                "displayIcon": null
            },
            "send_back_yours": false
        });

        let msg: ProfileMessage = serde_json::from_value(wire_json).unwrap();
        assert_eq!(msg.profile.display_name, Some("Keep".into()));
        // Empty string is explicit clear
        assert_eq!(
            msg.profile.display_picture,
            Some(serde_json::Value::String("".into()))
        );
        // JSON null for Option<Value> deserializes to None (same as absent).
        // The service layer treats None as "no change" (merge semantics),
        // which is correct — explicit clear should use empty string "".
        assert_eq!(msg.profile.display_icon, None);
    }

    #[test]
    fn test_absent_fields_are_none() {
        let wire_json = serde_json::json!({
            "@type": "https://didcomm.org/user-profile/1.0/profile",
            "@id": "partial",
            "profile": {
                "displayName": "Just a name"
            },
            "send_back_yours": false
        });

        let msg: ProfileMessage = serde_json::from_value(wire_json).unwrap();
        assert_eq!(msg.profile.display_name, Some("Just a name".into()));
        assert!(msg.profile.display_picture.is_none());
        assert!(msg.profile.display_icon.is_none());
        assert!(msg.profile.description.is_none());
        assert!(msg.profile.preferred_language.is_none());
    }
}
