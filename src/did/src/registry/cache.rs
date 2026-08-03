//! DID Document Cache with TTL
//!
//! Implements LRU cache with 5-minute TTL for remote-fetched DIDs.

use crate::core::{DidDocument, DID};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// Cache entry with TTL
#[derive(Clone)]
struct CacheEntry {
    document: DidDocument,
    inserted_at: Instant,
}

/// DID Document cache with LRU eviction and TTL
pub struct DidCache {
    cache: LruCache<String, CacheEntry>,
    ttl: Duration,
}

impl Default for DidCache {
    /// A cache with default settings (100 entries, 5-minute TTL).
    fn default() -> Self {
        Self::new(100, Duration::from_secs(300))
    }
}

impl DidCache {
    /// Create a new cache with given capacity and TTL
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
            ttl,
        }
    }

    /// Get a document from cache if it exists and hasn't expired
    pub fn get(&mut self, did: &DID) -> Option<DidDocument> {
        let key = did.as_str().to_string();

        if let Some(entry) = self.cache.get(&key) {
            // Check if entry has expired
            if entry.inserted_at.elapsed() < self.ttl {
                return Some(entry.document.clone());
            } else {
                // Entry expired, remove it
                self.cache.pop(&key);
            }
        }

        None
    }

    /// Put a document in the cache
    pub fn put(&mut self, did: &DID, document: DidDocument) {
        let key = did.as_str().to_string();
        let entry = CacheEntry {
            document,
            inserted_at: Instant::now(),
        };
        self.cache.put(key, entry);
    }

    /// Remove a document from the cache
    pub fn remove(&mut self, did: &DID) {
        let key = did.as_str().to_string();
        self.cache.pop(&key);
    }

    /// Clear all entries from the cache
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_cache_put_and_get() {
        let mut cache = DidCache::new(10, Duration::from_secs(300));

        let did = DID::parse("did:web:example.com").unwrap();
        let doc = DidDocument {
            id: did.as_str().to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            context: None,
            also_known_as: vec![],
            controller: None,
        };

        cache.put(&did, doc.clone());

        let retrieved = cache.get(&did);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, did.as_str());
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = DidCache::new(10, Duration::from_millis(100)); // 100ms TTL

        let did = DID::parse("did:web:example.com").unwrap();
        let doc = DidDocument {
            id: did.as_str().to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            context: None,
            also_known_as: vec![],
            controller: None,
        };

        cache.put(&did, doc.clone());

        // Should be in cache
        assert!(cache.get(&did).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Should be expired
        assert!(cache.get(&did).is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut cache = DidCache::new(2, Duration::from_secs(300)); // Capacity of 2

        let did1 = DID::parse("did:web:example1.com").unwrap();
        let did2 = DID::parse("did:web:example2.com").unwrap();
        let did3 = DID::parse("did:web:example3.com").unwrap();

        let doc = DidDocument {
            id: "test".to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            context: None,
            also_known_as: vec![],
            controller: None,
        };

        cache.put(&did1, doc.clone());
        cache.put(&did2, doc.clone());
        cache.put(&did3, doc.clone()); // Should evict did1

        assert!(cache.get(&did1).is_none()); // Evicted
        assert!(cache.get(&did2).is_some());
        assert!(cache.get(&did3).is_some());
    }
}
