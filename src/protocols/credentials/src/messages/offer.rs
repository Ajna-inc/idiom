use crate::messages::{formats, AttachmentFormatDescriptor};
use didcomm::core::{Attachment, AttachmentData, Message as DidcommMessage};
use serde::{Deserialize, Serialize};

/// Offer Credential message (Issue Credential v3)
///
/// Sent by the issuer to offer a credential to the holder.
/// Contains the AnonCreds credential offer as a JSON attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferCredentialMessage {
    /// Message ID
    pub id: String,

    /// Thread ID for correlation
    pub thread_id: String,

    /// Attachment format descriptors
    pub formats: Vec<AttachmentFormatDescriptor>,

    /// Optional comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Serialized credential offer JSON
    pub credential_offer_json: String,
}

impl OfferCredentialMessage {
    /// Message type constant (Aries Issue-Credential 2.0, for interoperable peers)
    pub const TYPE: &'static str = "https://didcomm.org/issue-credential/2.0/offer-credential";

    /// Build the Aries Issue-Credential 2.0 offer as a plain top-level `@type`
    /// value: `credential_preview` (the attribute name/values the holder shows)
    /// + `offers~attach` (the base64 AnonCreds offer). Sent as-is via the
    /// agent's DIDComm sender; the envelope service handles v1/v2 packing.
    pub fn to_aries_v2_value(&self, preview_attributes: &[(String, String)]) -> serde_json::Value {
        let attach_id = &self.formats[0].attach_id;
        let attrs: Vec<serde_json::Value> = preview_attributes
            .iter()
            .map(|(n, v)| serde_json::json!({ "name": n, "value": v }))
            .collect();
        serde_json::json!({
            "@type": Self::TYPE,
            "@id": self.id,
            "comment": self.comment,
            "credential_preview": {
                "@type": "https://didcomm.org/issue-credential/2.0/credential-preview",
                "attributes": attrs,
            },
            "formats": self.formats,
            "offers~attach": [
                crate::messages::v2_attachment(
                    attach_id,
                    crate::messages::formats::ANONCREDS_CREDENTIAL_OFFER,
                    &self.credential_offer_json,
                )
            ],
        })
    }

    /// Create a new offer credential message
    pub fn new(credential_offer_json: String) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let attach_id = uuid::Uuid::new_v4().to_string();

        Self {
            id: id.clone(),
            thread_id: id,
            formats: vec![AttachmentFormatDescriptor {
                attach_id,
                format: formats::ANONCREDS_CREDENTIAL_OFFER.to_string(),
            }],
            comment: None,
            credential_offer_json,
        }
    }

    /// Set an optional comment
    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Convert to a DIDComm Message
    pub fn to_didcomm_message(&self) -> DidcommMessage {
        let attach_id = &self.formats[0].attach_id;

        let body = serde_json::json!({
            "formats": self.formats,
            "comment": self.comment,
        });

        let offer_value: serde_json::Value =
            serde_json::from_str(&self.credential_offer_json).unwrap_or_default();

        let attachment = Attachment {
            id: Some(attach_id.clone()),
            description: None,
            filename: None,
            media_type: Some("application/json".to_string()),
            format: Some(formats::ANONCREDS_CREDENTIAL_OFFER.to_string()),
            lastmod_time: None,
            byte_count: None,
            data: AttachmentData::Json { json: offer_value },
        };

        DidcommMessage::builder(Self::TYPE)
            .id(&self.id)
            .body(body)
            .thread(&self.thread_id)
            .add_attachment(attachment)
            .build()
    }

    /// Create from an inbound DIDComm Message
    pub fn from_didcomm_message(message: &DidcommMessage) -> Result<Self, crate::CredentialError> {
        let thread_id = message.thread_id().to_string();

        let formats: Vec<AttachmentFormatDescriptor> = message
            .body
            .get("formats")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let credential_offer_json = extract_attachment_json(message)?;

        Ok(Self {
            id: message.id.clone(),
            thread_id,
            formats,
            comment,
            credential_offer_json,
        })
    }
}

/// Extract JSON data from the first attachment of a DIDComm message
pub(crate) fn extract_attachment_json(
    message: &DidcommMessage,
) -> Result<String, crate::CredentialError> {
    let attachments = message
        .attachments
        .as_ref()
        .ok_or(crate::CredentialError::MissingAttachment)?;

    let attachment = attachments
        .first()
        .ok_or(crate::CredentialError::MissingAttachment)?;

    match &attachment.data {
        AttachmentData::Json { json } => {
            serde_json::to_string(json).map_err(crate::CredentialError::Serialization)
        }
        AttachmentData::Base64 { base64: data } => {
            // Decode base64 to string
            use std::str;
            let decoded = base64_decode(data).map_err(|e| {
                crate::CredentialError::InvalidAttachmentFormat(format!(
                    "Failed to decode base64 attachment: {}",
                    e
                ))
            })?;
            str::from_utf8(&decoded)
                .map(|s| s.to_string())
                .map_err(|e| {
                    crate::CredentialError::InvalidAttachmentFormat(format!(
                        "Base64 attachment is not valid UTF-8: {}",
                        e
                    ))
                })
        }
        _ => Err(crate::CredentialError::InvalidAttachmentFormat(
            "Unsupported attachment data format".to_string(),
        )),
    }
}

/// Simple base64 decoding (standard alphabet)
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    // Use serde_json roundtrip as a simple decoder fallback,
    // or manual decode. For simplicity, use a minimal approach.
    // In practice the attachment data comes as JSON inline, so base64 path
    // is rarely hit, but we handle it for completeness.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        if byte == b'\n' || byte == b'\r' || byte == b' ' {
            continue;
        }
        let val = alphabet
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| format!("Invalid base64 character: {}", byte as char))?
            as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offer_creation() {
        let offer_json = r#"{"schema_id":"schema:1","cred_def_id":"cred:1"}"#;
        let msg = OfferCredentialMessage::new(offer_json.to_string());

        assert_eq!(msg.formats.len(), 1);
        assert_eq!(msg.formats[0].format, formats::ANONCREDS_CREDENTIAL_OFFER);
        assert!(msg.comment.is_none());
        assert_eq!(msg.credential_offer_json, offer_json);
    }

    #[test]
    fn test_offer_with_comment() {
        let msg = OfferCredentialMessage::new(r#"{}"#.to_string())
            .with_comment("Please accept this credential".to_string());

        assert_eq!(
            msg.comment,
            Some("Please accept this credential".to_string())
        );
    }

    #[test]
    fn test_offer_to_didcomm() {
        let offer_json = r#"{"schema_id":"schema:1"}"#;
        let msg = OfferCredentialMessage::new(offer_json.to_string());
        let didcomm = msg.to_didcomm_message();

        assert_eq!(didcomm.msg_type, OfferCredentialMessage::TYPE);
        assert!(didcomm.attachments.is_some());
        assert_eq!(didcomm.attachments.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_offer_roundtrip() {
        let offer_json = r#"{"schema_id":"schema:1","cred_def_id":"cred:1"}"#;
        let original = OfferCredentialMessage::new(offer_json.to_string())
            .with_comment("Test offer".to_string());

        let didcomm = original.to_didcomm_message();
        let restored = OfferCredentialMessage::from_didcomm_message(&didcomm).unwrap();

        assert_eq!(restored.id, original.id);
        assert_eq!(restored.thread_id, original.thread_id);

        // Verify the JSON content is semantically equivalent
        let original_value: serde_json::Value =
            serde_json::from_str(&original.credential_offer_json).unwrap();
        let restored_value: serde_json::Value =
            serde_json::from_str(&restored.credential_offer_json).unwrap();
        assert_eq!(original_value, restored_value);
    }
}
