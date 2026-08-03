//! OR-Set (Observed-Remove Set) CRDT implementation
//!
//! OR-Set handles concurrent additions and removals correctly by:
//! - Associating each added element with a unique UUID
//! - Removing an element means removing specific UUID instances
//! - Add wins over remove for concurrent operations

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use uuid::Uuid;

/// OR-Set CRDT for conflict-free set operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORSet<T: Clone + Eq + Hash> {
    /// Elements with their unique instance IDs (UUIDs)
    /// element -> set of UUIDs representing different additions
    elements: HashMap<T, HashSet<Uuid>>,

    /// Tombstones for removed (element, UUID) pairs
    tombstones: HashSet<(T, Uuid)>,
}

impl<T: Clone + Eq + Hash> ORSet<T> {
    /// Create a new empty OR-Set
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
            tombstones: HashSet::new(),
        }
    }

    /// Add an element to the set
    ///
    /// Returns the UUID associated with this addition instance
    pub fn add(&mut self, element: T) -> Uuid {
        let uuid = Uuid::new_v4();

        self.elements.entry(element).or_default().insert(uuid);

        uuid
    }

    /// Remove an element from the set
    ///
    /// Removes all instances of the element by moving their UUIDs to tombstones
    pub fn remove(&mut self, element: &T) {
        if let Some(uuids) = self.elements.remove(element) {
            for uuid in uuids {
                self.tombstones.insert((element.clone(), uuid));
            }
        }
    }

    /// Remove a specific instance of an element by UUID
    pub fn remove_instance(&mut self, element: &T, uuid: Uuid) {
        if let Some(uuids) = self.elements.get_mut(element) {
            if uuids.remove(&uuid) {
                self.tombstones.insert((element.clone(), uuid));

                // Clean up empty entries
                if uuids.is_empty() {
                    self.elements.remove(element);
                }
            }
        }
    }

    /// Check if an element is in the set
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains_key(element)
    }

    /// Get all elements in the set
    pub fn elements(&self) -> Vec<T> {
        self.elements.keys().cloned().collect()
    }

    /// Get the number of elements in the set
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Merge another OR-Set into this one
    ///
    /// Implements the CRDT merge operation:
    /// 1. Merge all element additions
    /// 2. Merge tombstones
    /// 3. Apply tombstones to remove observed deletions
    pub fn merge(&mut self, other: &ORSet<T>) {
        // Merge additions
        for (elem, uuids) in &other.elements {
            self.elements
                .entry(elem.clone())
                .or_default()
                .extend(uuids.iter());
        }

        // Merge tombstones
        self.tombstones.extend(other.tombstones.iter().cloned());

        // Apply tombstones to clean up removed elements
        self.apply_tombstones();
    }

    /// Apply tombstones to remove elements
    fn apply_tombstones(&mut self) {
        self.elements.retain(|elem, uuids| {
            uuids.retain(|uuid| !self.tombstones.contains(&(elem.clone(), *uuid)));
            !uuids.is_empty()
        });
    }

    /// Clear all elements and tombstones
    pub fn clear(&mut self) {
        self.elements.clear();
        self.tombstones.clear();
    }

    /// Get the UUIDs associated with an element
    pub fn get_uuids(&self, element: &T) -> Option<&HashSet<Uuid>> {
        self.elements.get(element)
    }
}

impl<T: Clone + Eq + Hash> Default for ORSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq + Hash> PartialEq for ORSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.elements == other.elements && self.tombstones == other.tombstones
    }
}

impl<T: Clone + Eq + Hash> Eq for ORSet<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_contains() {
        let mut set = ORSet::new();

        set.add("key1".to_string());
        assert!(set.contains(&"key1".to_string()));
        assert!(!set.contains(&"key2".to_string()));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut set = ORSet::new();

        set.add("key1".to_string());
        assert!(set.contains(&"key1".to_string()));

        set.remove(&"key1".to_string());
        assert!(!set.contains(&"key1".to_string()));
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_concurrent_add_remove() {
        // Simulate concurrent operations
        let mut set1 = ORSet::new();
        let _uuid = set1.add("key1".to_string());

        // set2 doesn't know about the addition yet, tries to remove
        let mut set2 = ORSet::new();
        set2.remove(&"key1".to_string());

        // Merge: add should win (add-wins semantics)
        set2.merge(&set1);

        // key1 should still be present (add wins)
        assert!(set2.contains(&"key1".to_string()));
    }

    #[test]
    fn test_observed_remove() {
        let mut set1 = ORSet::new();
        let mut set2 = ORSet::new();

        // Both nodes start with same state
        let _uuid = set1.add("key1".to_string());
        set2.merge(&set1);

        // set2 observes key1, then removes it
        set2.remove(&"key1".to_string());

        // Merge back to set1
        set1.merge(&set2);

        // key1 should be removed (observed remove)
        assert!(!set1.contains(&"key1".to_string()));
    }

    #[test]
    fn test_merge_multiple_additions() {
        let mut set1 = ORSet::new();
        set1.add("key1".to_string());

        let mut set2 = ORSet::new();
        set2.add("key2".to_string());

        let mut set3 = ORSet::new();
        set3.add("key3".to_string());

        // Merge all sets
        set1.merge(&set2);
        set1.merge(&set3);

        assert_eq!(set1.len(), 3);
        assert!(set1.contains(&"key1".to_string()));
        assert!(set1.contains(&"key2".to_string()));
        assert!(set1.contains(&"key3".to_string()));
    }

    #[test]
    fn test_multiple_additions_of_same_element() {
        let mut set = ORSet::new();

        // Add same element multiple times (different UUIDs)
        let uuid1 = set.add("key1".to_string());
        let uuid2 = set.add("key1".to_string());

        assert!(set.contains(&"key1".to_string()));

        // Get UUIDs
        let uuids = set.get_uuids(&"key1".to_string()).unwrap();
        assert_eq!(uuids.len(), 2);
        assert!(uuids.contains(&uuid1));
        assert!(uuids.contains(&uuid2));

        // Remove one instance
        set.remove_instance(&"key1".to_string(), uuid1);

        // Element should still be present (one UUID remains)
        assert!(set.contains(&"key1".to_string()));

        // Remove second instance
        set.remove_instance(&"key1".to_string(), uuid2);

        // Now element should be gone
        assert!(!set.contains(&"key1".to_string()));
    }

    #[test]
    fn test_clear() {
        let mut set = ORSet::new();

        set.add("key1".to_string());
        set.add("key2".to_string());

        assert_eq!(set.len(), 2);

        set.clear();

        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
    }

    #[test]
    fn test_merge_idempotence() {
        let mut set1 = ORSet::new();
        set1.add("key1".to_string());

        let set2 = set1.clone();

        // Merge with itself
        set1.merge(&set2);

        // Should still have just one element
        assert_eq!(set1.len(), 1);
        assert!(set1.contains(&"key1".to_string()));
    }

    #[test]
    fn test_elements_list() {
        let mut set = ORSet::new();

        set.add("key1".to_string());
        set.add("key2".to_string());
        set.add("key3".to_string());

        let elements = set.elements();
        assert_eq!(elements.len(), 3);
        assert!(elements.contains(&"key1".to_string()));
        assert!(elements.contains(&"key2".to_string()));
        assert!(elements.contains(&"key3".to_string()));
    }
}
