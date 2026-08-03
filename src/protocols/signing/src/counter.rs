//! Monotonic counter manager for authorization token replay protection
//!
//! Each (subject_did, device_id) pair maintains a strictly increasing counter.
//! Tokens with counter values <= last_seen are rejected.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use agent_core::traits::{Record, StorageProvider};

use crate::errors::{Result, SigningProtocolError};

/// Storage category for counter records
const COUNTER_CATEGORY: &str = "signing_counter";

/// Manages monotonic counters per (subject_did, device_id) pair
pub struct MonotonicCounterManager {
    /// Storage backend for persistence
    storage: Arc<dyn StorageProvider>,
    /// In-memory cache for fast reads
    counters: RwLock<HashMap<String, u64>>,
}

impl MonotonicCounterManager {
    /// Create a new counter manager with the given storage backend
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            storage,
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Build the composite key for a (subject_did, device_id) pair
    fn key(subject_did: &str, device_id: &str) -> String {
        format!("{}:{}", subject_did, device_id)
    }

    /// Get the current counter value for a (subject_did, device_id) pair.
    /// Returns 0 if no counter exists yet.
    pub async fn current(&self, subject_did: &str, device_id: &str) -> Result<u64> {
        let key = Self::key(subject_did, device_id);

        // Check in-memory cache first
        {
            let counters = self.counters.read().await;
            if let Some(&value) = counters.get(&key) {
                return Ok(value);
            }
        }

        // Load from storage
        let value = match self
            .storage
            .find(COUNTER_CATEGORY, &key)
            .await
            .map_err(|e| SigningProtocolError::StorageError(e.to_string()))?
        {
            Some(record) => {
                let s = String::from_utf8(record.value)
                    .map_err(|e| SigningProtocolError::StorageError(e.to_string()))?;
                s.parse::<u64>()
                    .map_err(|e| SigningProtocolError::StorageError(e.to_string()))?
            }
            None => 0,
        };

        // Cache it
        {
            let mut counters = self.counters.write().await;
            counters.insert(key, value);
        }

        Ok(value)
    }

    /// Get the next counter value (atomically increment and persist).
    /// Returns the new counter value.
    pub async fn next(&self, subject_did: &str, device_id: &str) -> Result<u64> {
        let key = Self::key(subject_did, device_id);

        let mut counters = self.counters.write().await;
        let current = counters.entry(key.clone()).or_insert(0);

        // Load from storage if this is the first access
        if *current == 0 {
            if let Ok(Some(record)) = self.storage.find(COUNTER_CATEGORY, &key).await {
                if let Ok(s) = String::from_utf8(record.value) {
                    if let Ok(v) = s.parse::<u64>() {
                        *current = v;
                    }
                }
            }
        }

        *current += 1;
        let value = *current;

        // Persist to storage
        self.persist(&key, value, subject_did, device_id).await?;

        Ok(value)
    }

    /// Verify that a counter value is strictly greater than the last seen value.
    pub async fn verify(&self, subject_did: &str, device_id: &str, counter: u64) -> Result<bool> {
        let last_seen = self.current(subject_did, device_id).await?;
        Ok(counter > last_seen)
    }

    /// Accept a counter value (update last-seen after successful verification).
    /// This should be called BEFORE processing the associated token/secret
    /// to ensure replay protection even if processing fails.
    pub async fn accept(&self, subject_did: &str, device_id: &str, counter: u64) -> Result<()> {
        let key = Self::key(subject_did, device_id);

        let mut counters = self.counters.write().await;
        let current = counters.entry(key.clone()).or_insert(0);

        if counter <= *current {
            return Err(SigningProtocolError::CounterReplay {
                counter,
                last_seen: *current,
            });
        }

        *current = counter;

        // Persist BEFORE returning (critical for replay protection)
        self.persist(&key, counter, subject_did, device_id).await?;

        Ok(())
    }

    /// Persist a counter value to storage
    async fn persist(
        &self,
        key: &str,
        value: u64,
        subject_did: &str,
        device_id: &str,
    ) -> Result<()> {
        let record = Record::new(COUNTER_CATEGORY, key, value.to_string().into_bytes())
            .add_tag("did", subject_did)
            .add_tag("device_id", device_id);

        // Try update first, fall back to save
        match self.storage.update(&record).await {
            Ok(()) => Ok(()),
            Err(_) => self
                .storage
                .save(&record)
                .await
                .map_err(|e| SigningProtocolError::StorageError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::traits::Query;
    use std::sync::Mutex;

    /// Simple in-memory storage for testing
    struct MemoryStorage {
        records: Mutex<HashMap<String, Record>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageProvider for MemoryStorage {
        async fn save(&self, record: &Record) -> agent_core::Result<()> {
            let key = format!("{}:{}", record.category, record.name);
            self.records.lock().unwrap().insert(key, record.clone());
            Ok(())
        }

        async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
            let key = format!("{}:{}", category, name);
            Ok(self.records.lock().unwrap().get(&key).cloned())
        }

        async fn find_all(
            &self,
            category: &str,
            _query: &Query,
        ) -> agent_core::Result<Vec<Record>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .values()
                .filter(|r| r.category == category)
                .cloned()
                .collect())
        }

        async fn update(&self, record: &Record) -> agent_core::Result<()> {
            let key = format!("{}:{}", record.category, record.name);
            let mut records = self.records.lock().unwrap();
            if let std::collections::hash_map::Entry::Occupied(mut e) = records.entry(key) {
                e.insert(record.clone());
                Ok(())
            } else {
                Err(agent_core::AgentError::Storage("record not found".into()))
            }
        }

        async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
            let key = format!("{}:{}", category, name);
            self.records.lock().unwrap().remove(&key);
            Ok(())
        }

        async fn delete_all(&self, category: &str) -> agent_core::Result<()> {
            self.records
                .lock()
                .unwrap()
                .retain(|_, r| r.category != category);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_counter_increment() {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = MonotonicCounterManager::new(storage);

        assert_eq!(mgr.current("did:key:z1", "device1").await.unwrap(), 0);

        let v1 = mgr.next("did:key:z1", "device1").await.unwrap();
        assert_eq!(v1, 1);

        let v2 = mgr.next("did:key:z1", "device1").await.unwrap();
        assert_eq!(v2, 2);

        assert_eq!(mgr.current("did:key:z1", "device1").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_counter_verify() {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = MonotonicCounterManager::new(storage);

        // First counter, nothing seen yet
        assert!(mgr.verify("did:key:z1", "device1", 1).await.unwrap());
        assert!(mgr.verify("did:key:z1", "device1", 100).await.unwrap());
        assert!(!mgr.verify("did:key:z1", "device1", 0).await.unwrap());

        // Accept counter 5
        mgr.accept("did:key:z1", "device1", 5).await.unwrap();

        // 5 and below should fail
        assert!(!mgr.verify("did:key:z1", "device1", 5).await.unwrap());
        assert!(!mgr.verify("did:key:z1", "device1", 3).await.unwrap());
        // 6+ should pass
        assert!(mgr.verify("did:key:z1", "device1", 6).await.unwrap());
    }

    #[tokio::test]
    async fn test_counter_replay_rejection() {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = MonotonicCounterManager::new(storage);

        mgr.accept("did:key:z1", "device1", 10).await.unwrap();

        let result = mgr.accept("did:key:z1", "device1", 10).await;
        assert!(result.is_err());

        let result = mgr.accept("did:key:z1", "device1", 5).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_independent_devices() {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = MonotonicCounterManager::new(storage);

        mgr.accept("did:key:z1", "device1", 10).await.unwrap();
        mgr.accept("did:key:z1", "device2", 5).await.unwrap();

        // Device1 at 10, device2 at 5
        assert!(!mgr.verify("did:key:z1", "device1", 10).await.unwrap());
        assert!(mgr.verify("did:key:z1", "device1", 11).await.unwrap());
        assert!(!mgr.verify("did:key:z1", "device2", 5).await.unwrap());
        assert!(mgr.verify("did:key:z1", "device2", 6).await.unwrap());
    }
}
