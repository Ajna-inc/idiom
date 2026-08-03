use serde::{Deserialize, Serialize};

/// DIDComm v1 attachment format (wire-compatible with `~attach` decorator)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1Attachment {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "mime-type")]
    pub mime_type: String,
    pub data: V1AttachmentData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1AttachmentData {
    pub base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_attachment_serialization() {
        let attach = V1Attachment {
            id: "displayPicture".to_string(),
            mime_type: "image/png".to_string(),
            data: V1AttachmentData {
                base64: "iVBORw0KGgo=".to_string(),
            },
        };

        let json = serde_json::to_value(&attach).unwrap();
        assert_eq!(json["@id"], "displayPicture");
        assert_eq!(json["mime-type"], "image/png");
        assert_eq!(json["data"]["base64"], "iVBORw0KGgo=");
    }

    #[test]
    fn test_v1_attachment_deserialization() {
        let json = serde_json::json!({
            "@id": "displayIcon",
            "mime-type": "image/jpeg",
            "data": { "base64": "abc123==" }
        });

        let attach: V1Attachment = serde_json::from_value(json).unwrap();
        assert_eq!(attach.id, "displayIcon");
        assert_eq!(attach.mime_type, "image/jpeg");
        assert_eq!(attach.data.base64, "abc123==");
    }
}
