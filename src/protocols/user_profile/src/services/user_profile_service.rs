use std::sync::Arc;
use tracing::{debug, warn};

use crate::messages::{ProfileData, ProfileMessage, V1Attachment, V1AttachmentData};
use crate::repository::{fields, ImageData, UserProfileRecord, UserProfileRepositoryTrait};

/// Hard cap on the decoded byte size of any single image field
/// (`display_picture`, `display_icon`) embedded in a profile record.
///
/// Why 100 KiB: a 256×256 JPEG at quality ~0.8 of a photograph is
/// typically 15–40 KB, so 100 KiB leaves headroom for higher-quality
/// renders without letting a misbehaving client (or an older client
/// still shipping PNG-of-a-photo) blow up the mediator queue — each
/// profile broadcast gets DIDComm-wrapped to roughly 4× the raw
/// picture size, fanned out to every connection, and then queued for
/// any offline recipients.
pub const MAX_PROFILE_IMAGE_BYTES: usize = 100 * 1024;

/// Validate one image field's decoded byte length. Returns `Err` if the
/// base64 payload decodes to more than [`MAX_PROFILE_IMAGE_BYTES`].
fn enforce_image_size(field: &str, image: &ImageData) -> Result<(), String> {
    if image.base64.is_empty() {
        return Ok(());
    }
    // Each 4 base64 chars encode 3 bytes; padding shaves up to 2 bytes.
    // Use the conservative upper bound — we only need to know whether
    // the payload _could_ exceed the cap.
    let upper = (image.base64.len() / 4).saturating_mul(3);
    if upper > MAX_PROFILE_IMAGE_BYTES {
        return Err(format!(
            "{} exceeds {} KiB cap (~{} bytes encoded)",
            field,
            MAX_PROFILE_IMAGE_BYTES / 1024,
            upper
        ));
    }
    Ok(())
}

/// Apply [`enforce_image_size`] to both image fields on a record.
fn validate_record_image_sizes(record: &UserProfileRecord) -> Result<(), String> {
    if let Some(ref img) = record.display_picture {
        enforce_image_size("display_picture", img)?;
    }
    if let Some(ref img) = record.display_icon {
        enforce_image_size("display_icon", img)?;
    }
    Ok(())
}

#[cfg(feature = "events")]
use agent_events::event_bus::EventBus;

pub struct UserProfileService {
    repository: Arc<dyn UserProfileRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Arc<EventBus>,

    #[cfg(feature = "events")]
    agent_id: String,
}

impl UserProfileService {
    #[cfg(not(feature = "events"))]
    pub fn new(repository: Arc<dyn UserProfileRepositoryTrait>) -> Self {
        Self { repository }
    }

    #[cfg(feature = "events")]
    pub fn new(
        repository: Arc<dyn UserProfileRepositoryTrait>,
        event_bus: Arc<EventBus>,
        agent_id: String,
    ) -> Self {
        Self {
            repository,
            event_bus,
            agent_id,
        }
    }

    #[cfg(feature = "events")]
    async fn emit_peer_updated(&self, connection_id: &str, record: &UserProfileRecord) {
        let payload = crate::events::ProfilePeerUpdatedPayload {
            connection_id: connection_id.to_string(),
            record: record.clone(),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
        if let Err(e) = self.event_bus.emit(&meta, payload).await {
            tracing::debug!("Failed to publish profile.peer_updated event: {}", e);
        }
    }

    #[cfg(feature = "events")]
    async fn emit_own_updated(&self, record: &UserProfileRecord) {
        let payload = crate::events::ProfileOwnUpdatedPayload {
            record: record.clone(),
        };
        let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
        if let Err(e) = self.event_bus.emit(&meta, payload).await {
            tracing::debug!("Failed to publish profile.own_updated event: {}", e);
        }
    }

    /// Resolve a ProfileMessage's profile data by hydrating attachment sentinels
    /// and converting to a stored record. Merges with existing peer profile.
    pub fn resolve_profile_data(
        profile: &ProfileData,
        attachments: &Option<Vec<V1Attachment>>,
        existing: Option<&UserProfileRecord>,
    ) -> UserProfileRecord {
        let mut record = existing.cloned().unwrap_or_default();

        // displayName
        if let Some(ref name) = profile.display_name {
            record.display_name = Some(name.clone());
        }

        // description
        if let Some(ref desc) = profile.description {
            record.description = Some(desc.clone());
        }

        // preferredLanguage
        if let Some(ref lang) = profile.preferred_language {
            record.preferred_language = Some(lang.clone());
        }

        // displayPicture
        if let Some(ref val) = profile.display_picture {
            record.display_picture = resolve_media_field(val, fields::DISPLAY_PICTURE, attachments);
        }

        // displayIcon
        if let Some(ref val) = profile.display_icon {
            record.display_icon = resolve_media_field(val, fields::DISPLAY_ICON, attachments);
        }

        record
    }

    /// Save an incoming peer profile (from a ProfileMessage)
    pub async fn save_peer_profile(
        &self,
        connection_id: &str,
        message: &ProfileMessage,
    ) -> Result<UserProfileRecord, String> {
        let existing = self.repository.get_peer_profile(connection_id).await?;
        let record =
            Self::resolve_profile_data(&message.profile, &message.attachments, existing.as_ref());
        // Refuse to persist oversize peer images. A malicious or buggy
        // peer cannot use us as a mediator-queue amplifier — we drop
        // the message rather than store + re-broadcast a 4 MB blob.
        if let Err(e) = validate_record_image_sizes(&record) {
            warn!(connection_id, error = %e, "Rejected oversize peer profile image");
            return Err(e);
        }
        self.repository
            .save_peer_profile(connection_id, &record)
            .await?;
        debug!(connection_id, "Saved peer profile");

        #[cfg(feature = "events")]
        self.emit_peer_updated(connection_id, &record).await;

        Ok(record)
    }

    /// Save a peer profile from an already-resolved record (used by tests
    /// and by callers that bypass the wire format).
    pub async fn save_peer_record(
        &self,
        connection_id: &str,
        record: &UserProfileRecord,
    ) -> Result<(), String> {
        validate_record_image_sizes(record)?;
        self.repository
            .save_peer_profile(connection_id, record)
            .await?;

        #[cfg(feature = "events")]
        self.emit_peer_updated(connection_id, record).await;

        Ok(())
    }

    /// Get own profile
    pub async fn get_own_profile(&self) -> Result<Option<UserProfileRecord>, String> {
        self.repository.get_own_profile().await
    }

    /// Set own profile
    pub async fn set_own_profile(&self, record: &UserProfileRecord) -> Result<(), String> {
        validate_record_image_sizes(record)?;
        self.repository.save_own_profile(record).await?;

        #[cfg(feature = "events")]
        self.emit_own_updated(record).await;

        Ok(())
    }

    /// Build an outbound ProfileMessage from own profile, optionally filtering by query
    pub fn build_profile_message(
        record: &UserProfileRecord,
        query: Option<&[String]>,
    ) -> ProfileMessage {
        let mut profile = ProfileData::new();
        let mut attachments: Vec<V1Attachment> = Vec::new();

        let include = |field: &str| -> bool { query.is_none_or(|q| q.iter().any(|f| f == field)) };

        if include(fields::DISPLAY_NAME) {
            profile.display_name = record.display_name.clone();
        }
        if include(fields::DESCRIPTION) {
            profile.description = record.description.clone();
        }
        if include(fields::PREFERRED_LANGUAGE) {
            profile.preferred_language = record.preferred_language.clone();
        }
        if include(fields::DISPLAY_PICTURE) {
            if let Some(ref img) = record.display_picture {
                profile.display_picture = Some(serde_json::Value::String(format!(
                    "#{}",
                    fields::DISPLAY_PICTURE
                )));
                attachments.push(V1Attachment {
                    id: fields::DISPLAY_PICTURE.into(),
                    mime_type: img.mime_type.clone(),
                    data: V1AttachmentData {
                        base64: img.base64.clone(),
                    },
                });
            }
        }
        if include(fields::DISPLAY_ICON) {
            if let Some(ref img) = record.display_icon {
                profile.display_icon = Some(serde_json::Value::String(format!(
                    "#{}",
                    fields::DISPLAY_ICON
                )));
                attachments.push(V1Attachment {
                    id: fields::DISPLAY_ICON.into(),
                    mime_type: img.mime_type.clone(),
                    data: V1AttachmentData {
                        base64: img.base64.clone(),
                    },
                });
            }
        }

        let mut msg = ProfileMessage::new(profile);
        if !attachments.is_empty() {
            msg.attachments = Some(attachments);
        }
        msg
    }

    /// Get a peer's stored profile
    pub async fn get_peer_profile(
        &self,
        connection_id: &str,
    ) -> Result<Option<UserProfileRecord>, String> {
        self.repository.get_peer_profile(connection_id).await
    }
}

/// Resolve a media field (displayPicture or displayIcon) from its wire value.
///
/// Returns `Some(ImageData)` for valid data, `None` to clear.
fn resolve_media_field(
    val: &serde_json::Value,
    field_name: &str,
    attachments: &Option<Vec<V1Attachment>>,
) -> Option<ImageData> {
    match val {
        // Sentinel string — look up in ~attach
        serde_json::Value::String(s) if s.starts_with('#') => {
            let attach_id = &s[1..]; // strip leading #
            if let Some(ref attaches) = attachments {
                if let Some(a) = attaches.iter().find(|a| a.id == attach_id) {
                    return Some(ImageData {
                        mime_type: a.mime_type.clone(),
                        base64: a.data.base64.clone(),
                        links: vec![],
                    });
                }
            }
            debug!(field_name, sentinel = %s, "Sentinel attachment not found, clearing field");
            None
        }
        // Empty string — explicit clear
        serde_json::Value::String(s) if s.is_empty() => None,
        // Null — explicit clear
        serde_json::Value::Null => None,
        // Inline object — parse directly
        serde_json::Value::Object(_) => serde_json::from_value::<ImageData>(val.clone()).ok(),
        _ => {
            debug!(field_name, "Unexpected media field value type, ignoring");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_size_cap_under_limit() {
        // 50 KiB of base64 chars ≈ 37.5 KB decoded — under cap.
        let img = ImageData {
            mime_type: "image/jpeg".into(),
            base64: "A".repeat(50 * 1024),
            links: vec![],
        };
        assert!(enforce_image_size("display_picture", &img).is_ok());
    }

    #[test]
    fn test_image_size_cap_at_limit() {
        // Exactly at the cap upper bound. base64 length where upper
        // bound = MAX is (MAX/3)*4. Use exactly MAX*4/3 so the upper
        // bound equals MAX (still allowed since check is `>`).
        let len = (MAX_PROFILE_IMAGE_BYTES / 3) * 4;
        let img = ImageData {
            mime_type: "image/jpeg".into(),
            base64: "A".repeat(len),
            links: vec![],
        };
        assert!(enforce_image_size("display_picture", &img).is_ok());
    }

    #[test]
    fn test_image_size_cap_rejects_over_limit() {
        // 1 MB of base64 → ~750 KB decoded — well over the 100 KiB cap.
        let img = ImageData {
            mime_type: "image/png".into(),
            base64: "A".repeat(1024 * 1024),
            links: vec![],
        };
        let err = enforce_image_size("display_picture", &img).unwrap_err();
        assert!(err.contains("display_picture"));
        assert!(err.contains("cap"));
    }

    #[test]
    fn test_image_size_cap_empty_is_ok() {
        let img = ImageData {
            mime_type: "image/jpeg".into(),
            base64: String::new(),
            links: vec![],
        };
        assert!(enforce_image_size("display_picture", &img).is_ok());
    }

    #[test]
    fn test_resolve_sentinel_attachment() {
        let profile = ProfileData {
            display_name: Some("Test".into()),
            display_picture: Some(serde_json::Value::String("#displayPicture".into())),
            display_icon: None,
            description: None,
            preferred_language: None,
        };
        let attachments = Some(vec![V1Attachment {
            id: "displayPicture".into(),
            mime_type: "image/png".into(),
            data: V1AttachmentData {
                base64: "iVBOR==".into(),
            },
        }]);

        let record = UserProfileService::resolve_profile_data(&profile, &attachments, None);
        assert_eq!(record.display_name, Some("Test".into()));
        let pic = record.display_picture.unwrap();
        assert_eq!(pic.mime_type, "image/png");
        assert_eq!(pic.base64, "iVBOR==");
    }

    #[test]
    fn test_resolve_inline_image() {
        let profile = ProfileData {
            display_name: None,
            display_picture: Some(serde_json::json!({
                "mimeType": "image/jpeg",
                "base64": "abc==",
                "links": ["https://example.com/pic.jpg"]
            })),
            display_icon: None,
            description: None,
            preferred_language: None,
        };

        let record = UserProfileService::resolve_profile_data(&profile, &None, None);
        let pic = record.display_picture.unwrap();
        assert_eq!(pic.mime_type, "image/jpeg");
        assert_eq!(pic.base64, "abc==");
        assert_eq!(pic.links, vec!["https://example.com/pic.jpg"]);
    }

    #[test]
    fn test_resolve_clear_fields() {
        let existing = UserProfileRecord {
            display_name: Some("Old".into()),
            display_picture: Some(ImageData {
                mime_type: "image/png".into(),
                base64: "old==".into(),
                links: vec![],
            }),
            display_icon: None,
            description: Some("Old bio".into()),
            preferred_language: None,
        };

        let profile = ProfileData {
            display_name: None,                                          // absent — keep
            display_picture: Some(serde_json::Value::String("".into())), // clear
            display_icon: Some(serde_json::Value::Null),                 // clear
            description: None,                                           // absent — keep
            preferred_language: None,
        };

        let record = UserProfileService::resolve_profile_data(&profile, &None, Some(&existing));
        assert_eq!(record.display_name, Some("Old".into())); // preserved
        assert!(record.display_picture.is_none()); // cleared
        assert!(record.display_icon.is_none()); // cleared
        assert_eq!(record.description, Some("Old bio".into())); // preserved
    }

    #[test]
    fn test_merge_semantics() {
        let existing = UserProfileRecord {
            display_name: Some("Alice".into()),
            display_picture: None,
            display_icon: None,
            description: Some("Original bio".into()),
            preferred_language: Some("en".into()),
        };

        let profile = ProfileData {
            display_name: Some("Alice Updated".into()),
            display_picture: None, // absent
            display_icon: None,
            description: None, // absent
            preferred_language: None,
        };

        let record = UserProfileService::resolve_profile_data(&profile, &None, Some(&existing));
        assert_eq!(record.display_name, Some("Alice Updated".into())); // updated
        assert_eq!(record.description, Some("Original bio".into())); // preserved
        assert_eq!(record.preferred_language, Some("en".into())); // preserved
    }

    #[test]
    fn test_build_profile_message_with_query() {
        let record = UserProfileRecord {
            display_name: Some("Alice".into()),
            display_picture: Some(ImageData {
                mime_type: "image/png".into(),
                base64: "abc==".into(),
                links: vec![],
            }),
            display_icon: None,
            description: Some("My bio".into()),
            preferred_language: Some("en".into()),
        };

        // Full profile
        let msg = UserProfileService::build_profile_message(&record, None);
        assert_eq!(msg.profile.display_name, Some("Alice".into()));
        assert_eq!(msg.profile.description, Some("My bio".into()));
        assert!(msg.attachments.is_some());

        // Filtered query
        let msg = UserProfileService::build_profile_message(
            &record,
            Some(&["displayName".to_string(), "description".to_string()]),
        );
        assert_eq!(msg.profile.display_name, Some("Alice".into()));
        assert_eq!(msg.profile.description, Some("My bio".into()));
        assert!(msg.profile.preferred_language.is_none()); // not requested
        assert!(msg.attachments.is_none()); // picture not requested
    }
}
