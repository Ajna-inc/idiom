use crate::domain::{KeylistAction, KeylistResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Keylist record stored in the repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylistRecord {
    pub id: String,
    pub mediation_id: String,
    pub recipient_key: String,
    pub action: KeylistAction,
    pub result: KeylistResult,
    pub created_at: DateTime<Utc>,
}

impl KeylistRecord {
    pub fn new(
        mediation_id: String,
        recipient_key: String,
        action: KeylistAction,
        result: KeylistResult,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            mediation_id,
            recipient_key,
            action,
            result,
            created_at: Utc::now(),
        }
    }
}

/// Tags for querying keylist records
pub struct KeylistTags;

impl KeylistTags {
    pub const MEDIATION_ID: &'static str = "mediation_id";
    pub const RECIPIENT_KEY: &'static str = "recipient_key";
}
