//! LWW-Map (Last-Write-Wins Map) CRDT implementation
//!
//! LWW-Map resolves conflicts by using timestamps:
//! - Each value has an associated timestamp
//! - On conflict, the value with the highest timestamp wins
//! - Ties are broken using a deterministic rule (e.g., node ID comparison)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

/// Entry in the LWW-Map with timestamp and node ID for tie-breaking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LWWEntry<V> {
    /// The value
    pub value: V,

    /// Timestamp when this value was written
    pub timestamp: DateTime<Utc>,

    /// Node ID that wrote this value (for tie-breaking)
    pub node_id: String,

    /// Whether this entry is a tombstone (deleted)
    pub is_tombstone: bool,
}

impl<V> LWWEntry<V> {
    /// Create a new entry
    pub fn new(value: V, node_id: String) -> Self {
        Self {
            value,
            timestamp: Utc::now(),
            node_id,
            is_tombstone: false,
        }
    }

    /// Create a new entry with a specific timestamp
    pub fn with_timestamp(value: V, timestamp: DateTime<Utc>, node_id: String) -> Self {
        Self {
            value,
            timestamp,
            node_id,
            is_tombstone: false,
        }
    }

    /// Create a tombstone entry (for deletion)
    pub fn tombstone(timestamp: DateTime<Utc>, node_id: String) -> Self
    where
        V: Default,
    {
        Self {
            value: V::default(),
            timestamp,
            node_id,
            is_tombstone: true,
        }
    }

    /// Compare two entries to determine which wins
    ///
    /// Returns true if self wins over other
    pub fn wins_over(&self, other: &LWWEntry<V>) -> bool {
        // Compare timestamps first
        match self.timestamp.cmp(&other.timestamp) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => {
                // Tie-break using node ID (deterministic)
                self.node_id > other.node_id
            }
        }
    }
}

/// LWW-Map CRDT for conflict-free map operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWWMap<K: Clone + Eq + Hash, V: Clone> {
    /// Map of key -> LWW entry
    entries: HashMap<K, LWWEntry<V>>,
}

impl<K: Clone + Eq + Hash, V: Clone> LWWMap<K, V> {
    /// Create a new empty LWW-Map
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Set a value in the map
    pub fn set(&mut self, key: K, value: V, node_id: String) {
        let entry = LWWEntry::new(value, node_id);
        self.set_entry(key, entry);
    }

    /// Set a value with a specific timestamp
    pub fn set_with_timestamp(
        &mut self,
        key: K,
        value: V,
        timestamp: DateTime<Utc>,
        node_id: String,
    ) {
        let entry = LWWEntry::with_timestamp(value, timestamp, node_id);
        self.set_entry(key, entry);
    }

    /// Internal method to set an entry
    fn set_entry(&mut self, key: K, entry: LWWEntry<V>) {
        // Only update if the new entry wins
        if let Some(existing) = self.entries.get(&key) {
            if entry.wins_over(existing) {
                self.entries.insert(key, entry);
            }
        } else {
            self.entries.insert(key, entry);
        }
    }

    /// Remove a key from the map (creates a tombstone)
    pub fn remove(&mut self, key: K, node_id: String)
    where
        V: Default,
    {
        let entry = LWWEntry::tombstone(Utc::now(), node_id);
        self.set_entry(key, entry);
    }

    /// Remove a key with a specific timestamp
    pub fn remove_with_timestamp(&mut self, key: K, timestamp: DateTime<Utc>, node_id: String)
    where
        V: Default,
    {
        let entry = LWWEntry::tombstone(timestamp, node_id);
        self.set_entry(key, entry);
    }

    /// Get a value from the map
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).and_then(|entry| {
            if entry.is_tombstone {
                None
            } else {
                Some(&entry.value)
            }
        })
    }

    /// Check if a key exists in the map (and is not tombstoned)
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| !entry.is_tombstone)
    }

    /// Get all keys in the map (excluding tombstones)
    pub fn keys(&self) -> Vec<K> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.is_tombstone)
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Get all values in the map (excluding tombstones)
    pub fn values(&self) -> Vec<V> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.is_tombstone)
            .map(|(_, entry)| entry.value.clone())
            .collect()
    }

    /// Get all entries (key-value pairs, excluding tombstones)
    pub fn entries(&self) -> Vec<(K, V)> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.is_tombstone)
            .map(|(key, entry)| (key.clone(), entry.value.clone()))
            .collect()
    }

    /// Get the number of entries (excluding tombstones)
    pub fn len(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| !entry.is_tombstone)
            .count()
    }

    /// Check if the map is empty (no non-tombstone entries)
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge another LWW-Map into this one
    ///
    /// For each key, keep the entry with the higher timestamp
    pub fn merge(&mut self, other: &LWWMap<K, V>) {
        for (key, other_entry) in &other.entries {
            self.set_entry(key.clone(), other_entry.clone());
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the entry for a key (including tombstones)
    pub fn get_entry(&self, key: &K) -> Option<&LWWEntry<V>> {
        self.entries.get(key)
    }
}

impl<K: Clone + Eq + Hash, V: Clone> Default for LWWMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Clone + Eq + Hash, V: Clone + PartialEq> PartialEq for LWWMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl<K: Clone + Eq + Hash, V: Clone + PartialEq> Eq for LWWMap<K, V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_set_and_get() {
        let mut map = LWWMap::new();

        map.set(
            "key1".to_string(),
            "value1".to_string(),
            "node1".to_string(),
        );
        assert_eq!(map.get(&"key1".to_string()), Some(&"value1".to_string()));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_overwrite() {
        let mut map = LWWMap::new();
        let node = "node1".to_string();

        map.set("key1".to_string(), "value1".to_string(), node.clone());
        map.set("key1".to_string(), "value2".to_string(), node);

        // Second write should win (later timestamp)
        assert_eq!(map.get(&"key1".to_string()), Some(&"value2".to_string()));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut map = LWWMap::new();
        let node = "node1".to_string();

        map.set("key1".to_string(), "value1".to_string(), node.clone());
        assert!(map.contains_key(&"key1".to_string()));

        map.remove("key1".to_string(), node);
        assert!(!map.contains_key(&"key1".to_string()));
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_lww_conflict_resolution() {
        let mut map = LWWMap::new();

        let now = Utc::now();
        let past = now - Duration::seconds(10);

        // Set with older timestamp
        map.set_with_timestamp(
            "key1".to_string(),
            "old_value".to_string(),
            past,
            "node1".to_string(),
        );

        // Set with newer timestamp
        map.set_with_timestamp(
            "key1".to_string(),
            "new_value".to_string(),
            now,
            "node2".to_string(),
        );

        // Newer value should win
        assert_eq!(map.get(&"key1".to_string()), Some(&"new_value".to_string()));
    }

    #[test]
    fn test_tie_breaking() {
        let mut map = LWWMap::new();

        let timestamp = Utc::now();

        // Same timestamp, different nodes
        map.set_with_timestamp(
            "key1".to_string(),
            "value_a".to_string(),
            timestamp,
            "node_a".to_string(),
        );
        map.set_with_timestamp(
            "key1".to_string(),
            "value_b".to_string(),
            timestamp,
            "node_b".to_string(),
        );

        // "node_b" > "node_a" lexicographically, so value_b should win
        assert_eq!(map.get(&"key1".to_string()), Some(&"value_b".to_string()));
    }

    #[test]
    fn test_merge() {
        let mut map1 = LWWMap::new();
        map1.set(
            "key1".to_string(),
            "value1".to_string(),
            "node1".to_string(),
        );

        let mut map2 = LWWMap::new();
        map2.set(
            "key2".to_string(),
            "value2".to_string(),
            "node2".to_string(),
        );

        map1.merge(&map2);

        assert_eq!(map1.len(), 2);
        assert_eq!(map1.get(&"key1".to_string()), Some(&"value1".to_string()));
        assert_eq!(map1.get(&"key2".to_string()), Some(&"value2".to_string()));
    }

    #[test]
    fn test_merge_conflict() {
        let now = Utc::now();
        let past = now - Duration::seconds(10);

        let mut map1 = LWWMap::new();
        map1.set_with_timestamp(
            "key1".to_string(),
            "old_value".to_string(),
            past,
            "node1".to_string(),
        );

        let mut map2 = LWWMap::new();
        map2.set_with_timestamp(
            "key1".to_string(),
            "new_value".to_string(),
            now,
            "node2".to_string(),
        );

        map1.merge(&map2);

        // Newer value from map2 should win
        assert_eq!(
            map1.get(&"key1".to_string()),
            Some(&"new_value".to_string())
        );
    }

    #[test]
    fn test_keys_values_entries() {
        let mut map = LWWMap::new();

        map.set("key1".to_string(), 1, "node1".to_string());
        map.set("key2".to_string(), 2, "node1".to_string());
        map.set("key3".to_string(), 3, "node1".to_string());

        let keys = map.keys();
        assert_eq!(keys.len(), 3);

        let values = map.values();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&1));
        assert!(values.contains(&2));
        assert!(values.contains(&3));

        let entries = map.entries();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_remove_then_add() {
        let mut map = LWWMap::new();
        let node = "node1".to_string();

        let now = Utc::now();
        let future = now + Duration::seconds(10);

        // Add
        map.set_with_timestamp("key1".to_string(), "value1".to_string(), now, node.clone());
        assert!(map.contains_key(&"key1".to_string()));

        // Remove with later timestamp
        map.remove_with_timestamp("key1".to_string(), future, node.clone());
        assert!(!map.contains_key(&"key1".to_string()));
    }

    #[test]
    fn test_merge_idempotence() {
        let mut map1 = LWWMap::new();
        map1.set(
            "key1".to_string(),
            "value1".to_string(),
            "node1".to_string(),
        );

        let map2 = map1.clone();

        map1.merge(&map2);

        // Should still have the same value
        assert_eq!(map1.len(), 1);
        assert_eq!(map1.get(&"key1".to_string()), Some(&"value1".to_string()));
    }

    #[test]
    fn test_clear() {
        let mut map = LWWMap::new();

        map.set(
            "key1".to_string(),
            "value1".to_string(),
            "node1".to_string(),
        );
        map.set(
            "key2".to_string(),
            "value2".to_string(),
            "node1".to_string(),
        );

        assert_eq!(map.len(), 2);

        map.clear();

        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
    }
}
