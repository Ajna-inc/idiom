use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const USER_PROFILE_CATEGORY: &str = "user_profile";
pub const OWN_PROFILE_ID: &str = "default";
pub const CONNECTION_PROFILE_METADATA_KEY: &str = "UserProfile";

/// Canonical user-profile field names used both as query keys and as
/// attachment `@id`s / sentinel references on the wire. Centralized so the
/// message, service, and repository layers cannot drift.
pub mod fields {
    pub const DISPLAY_NAME: &str = "displayName";
    pub const DESCRIPTION: &str = "description";
    pub const PREFERRED_LANGUAGE: &str = "preferredLanguage";
    pub const DISPLAY_PICTURE: &str = "displayPicture";
    pub const DISPLAY_ICON: &str = "displayIcon";
}

/// Resolved image data (after attachment sentinels are hydrated)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub base64: String,
    #[serde(default)]
    pub links: Vec<String>,
}

/// Stored user profile record
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserProfileRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_picture: Option<ImageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_icon: Option<ImageData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
}

impl UserProfileRecord {
    pub fn to_metadata_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        if let Some(ref name) = self.display_name {
            map.insert(
                fields::DISPLAY_NAME.into(),
                serde_json::Value::String(name.clone()),
            );
        }
        if let Some(ref pic) = self.display_picture {
            map.insert(
                fields::DISPLAY_PICTURE.into(),
                serde_json::to_value(pic).unwrap(),
            );
        }
        if let Some(ref icon) = self.display_icon {
            map.insert(
                fields::DISPLAY_ICON.into(),
                serde_json::to_value(icon).unwrap(),
            );
        }
        if let Some(ref desc) = self.description {
            map.insert(
                fields::DESCRIPTION.into(),
                serde_json::Value::String(desc.clone()),
            );
        }
        if let Some(ref lang) = self.preferred_language {
            map.insert(
                fields::PREFERRED_LANGUAGE.into(),
                serde_json::Value::String(lang.clone()),
            );
        }
        serde_json::Value::Object(map)
    }

    pub fn from_metadata_value(val: &serde_json::Value) -> Self {
        let mut record = Self::default();
        if let Some(obj) = val.as_object() {
            if let Some(name) = obj.get(fields::DISPLAY_NAME).and_then(|v| v.as_str()) {
                record.display_name = Some(name.to_string());
            }
            if let Some(pic) = obj.get(fields::DISPLAY_PICTURE) {
                if let Ok(img) = serde_json::from_value::<ImageData>(pic.clone()) {
                    record.display_picture = Some(img);
                }
            }
            if let Some(icon) = obj.get(fields::DISPLAY_ICON) {
                if let Ok(img) = serde_json::from_value::<ImageData>(icon.clone()) {
                    record.display_icon = Some(img);
                }
            }
            if let Some(desc) = obj.get(fields::DESCRIPTION).and_then(|v| v.as_str()) {
                record.description = Some(desc.to_string());
            }
            if let Some(lang) = obj.get(fields::PREFERRED_LANGUAGE).and_then(|v| v.as_str()) {
                record.preferred_language = Some(lang.to_string());
            }
        }
        record
    }
}

/// Repository trait for profile storage
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait UserProfileRepositoryTrait: Send + Sync {
    async fn save_own_profile(&self, record: &UserProfileRecord) -> Result<(), String>;
    async fn get_own_profile(&self) -> Result<Option<UserProfileRecord>, String>;
    async fn save_peer_profile(
        &self,
        connection_id: &str,
        record: &UserProfileRecord,
    ) -> Result<(), String>;
    async fn get_peer_profile(
        &self,
        connection_id: &str,
    ) -> Result<Option<UserProfileRecord>, String>;
}

/// In-memory profile repository
pub struct UserProfileRepository {
    own_profile: Arc<RwLock<Option<UserProfileRecord>>>,
    peer_profiles: Arc<RwLock<HashMap<String, UserProfileRecord>>>,
}

impl Default for UserProfileRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl UserProfileRepository {
    pub fn new() -> Self {
        Self {
            own_profile: Arc::new(RwLock::new(None)),
            peer_profiles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl UserProfileRepositoryTrait for UserProfileRepository {
    async fn save_own_profile(&self, record: &UserProfileRecord) -> Result<(), String> {
        let mut own = self.own_profile.write().await;
        *own = Some(record.clone());
        Ok(())
    }

    async fn get_own_profile(&self) -> Result<Option<UserProfileRecord>, String> {
        let own = self.own_profile.read().await;
        Ok(own.clone())
    }

    async fn save_peer_profile(
        &self,
        connection_id: &str,
        record: &UserProfileRecord,
    ) -> Result<(), String> {
        let mut peers = self.peer_profiles.write().await;
        peers.insert(connection_id.to_string(), record.clone());
        Ok(())
    }

    async fn get_peer_profile(
        &self,
        connection_id: &str,
    ) -> Result<Option<UserProfileRecord>, String> {
        let peers = self.peer_profiles.read().await;
        Ok(peers.get(connection_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_own_profile_crud() {
        let repo = UserProfileRepository::new();
        assert!(repo.get_own_profile().await.unwrap().is_none());

        let record = UserProfileRecord {
            display_name: Some("Alice".into()),
            ..Default::default()
        };
        repo.save_own_profile(&record).await.unwrap();

        let loaded = repo.get_own_profile().await.unwrap().unwrap();
        assert_eq!(loaded.display_name, Some("Alice".into()));
    }

    #[tokio::test]
    async fn test_peer_profile_crud() {
        let repo = UserProfileRepository::new();
        let conn_id = "conn-123";

        assert!(repo.get_peer_profile(conn_id).await.unwrap().is_none());

        let record = UserProfileRecord {
            display_name: Some("Bob".into()),
            description: Some("Hi".into()),
            ..Default::default()
        };
        repo.save_peer_profile(conn_id, &record).await.unwrap();

        let loaded = repo.get_peer_profile(conn_id).await.unwrap().unwrap();
        assert_eq!(loaded.display_name, Some("Bob".into()));
        assert_eq!(loaded.description, Some("Hi".into()));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let record = UserProfileRecord {
            display_name: Some("Test".into()),
            display_picture: Some(ImageData {
                mime_type: "image/png".into(),
                base64: "abc==".into(),
                links: vec![],
            }),
            display_icon: None,
            description: Some("Bio".into()),
            preferred_language: Some("en".into()),
        };

        let val = record.to_metadata_value();
        let restored = UserProfileRecord::from_metadata_value(&val);
        assert_eq!(restored.display_name, record.display_name);
        assert_eq!(restored.display_picture, record.display_picture);
        assert_eq!(restored.description, record.description);
        assert_eq!(restored.preferred_language, record.preferred_language);
    }
}
