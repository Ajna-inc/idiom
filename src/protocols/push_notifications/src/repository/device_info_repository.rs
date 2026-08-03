use crate::error::Result;
use crate::repository::DeviceInfoRecord;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait DeviceInfoRepositoryTrait: Send + Sync {
    /// Upsert by `connection_id`. If a record already exists for the same
    /// connection, it is overwritten in place and `updated_at` is bumped.
    /// Returns the stored record.
    async fn upsert(&self, record: DeviceInfoRecord) -> Result<DeviceInfoRecord>;

    /// Single row per connection (or None).
    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Option<DeviceInfoRecord>>;

    async fn delete_by_connection_id(&self, connection_id: &str) -> Result<()>;

    async fn get_all(&self) -> Result<Vec<DeviceInfoRecord>>;
}

/// In-memory implementation suitable for tests and for the in-process
/// mediator startup before persistence is wired.
pub struct DeviceInfoRepository {
    by_connection: Arc<RwLock<HashMap<String, DeviceInfoRecord>>>,
}

impl DeviceInfoRepository {
    pub fn new() -> Self {
        Self {
            by_connection: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for DeviceInfoRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DeviceInfoRepositoryTrait for DeviceInfoRepository {
    async fn upsert(&self, mut record: DeviceInfoRecord) -> Result<DeviceInfoRecord> {
        let mut map = self.by_connection.write().await;
        if let Some(existing) = map.get(&record.connection_id) {
            // Preserve the original id + created_at so the row remains the
            // same logical record across token rotations.
            record.id = existing.id.clone();
            record.created_at = existing.created_at;
        }
        record.updated_at = chrono::Utc::now();
        map.insert(record.connection_id.clone(), record.clone());
        Ok(record)
    }

    async fn find_by_connection_id(&self, connection_id: &str) -> Result<Option<DeviceInfoRecord>> {
        Ok(self.by_connection.read().await.get(connection_id).cloned())
    }

    async fn delete_by_connection_id(&self, connection_id: &str) -> Result<()> {
        self.by_connection.write().await.remove(connection_id);
        Ok(())
    }

    async fn get_all(&self) -> Result<Vec<DeviceInfoRecord>> {
        Ok(self.by_connection.read().await.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DevicePlatform;

    fn rec(conn: &str, tok: &str, plat: DevicePlatform) -> DeviceInfoRecord {
        DeviceInfoRecord::new(conn.to_string(), tok.to_string(), plat)
    }

    #[tokio::test]
    async fn upsert_then_find() {
        let repo = DeviceInfoRepository::new();
        let r = repo
            .upsert(rec("c1", "tok-1", DevicePlatform::Ios))
            .await
            .unwrap();
        assert_eq!(r.device_token, "tok-1");
        let f = repo.find_by_connection_id("c1").await.unwrap().unwrap();
        assert_eq!(f.id, r.id);
    }

    #[tokio::test]
    async fn upsert_preserves_id_on_token_rotation() {
        let repo = DeviceInfoRepository::new();
        let first = repo
            .upsert(rec("c1", "tok-1", DevicePlatform::Android))
            .await
            .unwrap();
        let second = repo
            .upsert(rec("c1", "tok-2", DevicePlatform::Android))
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.created_at, second.created_at);
        assert!(second.updated_at >= first.updated_at);
        assert_eq!(second.device_token, "tok-2");
    }

    #[tokio::test]
    async fn one_row_per_connection() {
        let repo = DeviceInfoRepository::new();
        repo.upsert(rec("c1", "t1", DevicePlatform::Ios))
            .await
            .unwrap();
        repo.upsert(rec("c1", "t2", DevicePlatform::Android))
            .await
            .unwrap();
        let all = repo.get_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].device_token, "t2");
        assert_eq!(all[0].device_platform, DevicePlatform::Android);
    }

    #[tokio::test]
    async fn delete_removes_the_row() {
        let repo = DeviceInfoRepository::new();
        repo.upsert(rec("c1", "t", DevicePlatform::Ios))
            .await
            .unwrap();
        repo.delete_by_connection_id("c1").await.unwrap();
        assert!(repo.find_by_connection_id("c1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_returns_none_for_unknown() {
        let repo = DeviceInfoRepository::new();
        assert!(repo
            .find_by_connection_id("missing")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn error_variant_smoke() {
        use crate::error::PushNotificationError;
        let _ = PushNotificationError::NotFound("x".to_string());
    }
}
