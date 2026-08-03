//! Vector Clock implementation for causality tracking
//!
//! Vector clocks track causality between events in a distributed system.
//! Each node maintains a logical timestamp that increments on updates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vector clock for tracking causality in distributed updates
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    /// Map of node_id -> logical timestamp
    clocks: HashMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock
    pub fn new() -> Self {
        Self {
            clocks: HashMap::new(),
        }
    }

    /// Increment the clock for a given node
    pub fn increment(&mut self, node_id: &str) {
        let counter = self.clocks.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Get the timestamp for a specific node
    pub fn get(&self, node_id: &str) -> u64 {
        self.clocks.get(node_id).copied().unwrap_or(0)
    }

    /// Check if this clock happens before another clock
    ///
    /// A happens before B if:
    /// - For all nodes, A[node] <= B[node]
    /// - For at least one node, A[node] < B[node]
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let mut strictly_less = false;

        // Check all nodes in self
        for (node, &time) in &self.clocks {
            let other_time = other.get(node);
            if time > other_time {
                return false; // self has a higher timestamp
            }
            if time < other_time {
                strictly_less = true;
            }
        }

        // Check nodes that exist in other but not in self
        for (node, &time) in &other.clocks {
            if !self.clocks.contains_key(node) && time > 0 {
                strictly_less = true;
            }
        }

        strictly_less
    }

    /// Check if two clocks are concurrent (neither happens before the other)
    pub fn is_concurrent(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self) && self != other
    }

    /// Merge two vector clocks (take the maximum for each node)
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, &time) in &other.clocks {
            self.clocks
                .entry(node.clone())
                .and_modify(|t| *t = (*t).max(time))
                .or_insert(time);
        }
    }

    /// Compare two vector clocks
    pub fn compare(&self, other: &VectorClock) -> ClockOrdering {
        if self == other {
            return ClockOrdering::Equal;
        }

        if self.happens_before(other) {
            return ClockOrdering::Before;
        }

        if other.happens_before(self) {
            return ClockOrdering::After;
        }

        ClockOrdering::Concurrent
    }

    /// Get all node IDs in this clock
    pub fn node_ids(&self) -> Vec<String> {
        self.clocks.keys().cloned().collect()
    }

    /// Get the total number of events across all nodes
    pub fn total_events(&self) -> u64 {
        self.clocks.values().sum()
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordering relationship between two vector clocks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrdering {
    /// Clocks are equal
    Equal,
    /// First clock happens before second
    Before,
    /// First clock happens after second
    After,
    /// Clocks are concurrent (no causal relationship)
    Concurrent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_increment() {
        let mut clock = VectorClock::new();

        clock.increment("node1");
        assert_eq!(clock.get("node1"), 1);

        clock.increment("node1");
        assert_eq!(clock.get("node1"), 2);

        clock.increment("node2");
        assert_eq!(clock.get("node2"), 1);
    }

    #[test]
    fn test_happens_before() {
        let mut clock1 = VectorClock::new();
        clock1.increment("node1");
        // clock1 = {node1: 1}

        let mut clock2 = VectorClock::new();
        clock2.increment("node1");
        clock2.increment("node1");
        // clock2 = {node1: 2}

        assert!(clock1.happens_before(&clock2));
        assert!(!clock2.happens_before(&clock1));
    }

    #[test]
    fn test_concurrent_clocks() {
        let mut clock1 = VectorClock::new();
        clock1.increment("node1");
        // clock1 = {node1: 1}

        let mut clock2 = VectorClock::new();
        clock2.increment("node2");
        // clock2 = {node2: 1}

        assert!(clock1.is_concurrent(&clock2));
        assert!(clock2.is_concurrent(&clock1));
        assert!(!clock1.happens_before(&clock2));
        assert!(!clock2.happens_before(&clock1));
    }

    #[test]
    fn test_merge_clocks() {
        let mut clock1 = VectorClock::new();
        clock1.increment("node1");
        clock1.increment("node2");
        // clock1 = {node1: 1, node2: 1}

        let mut clock2 = VectorClock::new();
        clock2.increment("node2");
        clock2.increment("node2");
        clock2.increment("node3");
        // clock2 = {node2: 2, node3: 1}

        clock1.merge(&clock2);
        // Expected: {node1: 1, node2: 2, node3: 1}

        assert_eq!(clock1.get("node1"), 1);
        assert_eq!(clock1.get("node2"), 2);
        assert_eq!(clock1.get("node3"), 1);
    }

    #[test]
    fn test_compare() {
        let mut clock1 = VectorClock::new();
        clock1.increment("node1");

        let mut clock2 = VectorClock::new();
        clock2.increment("node1");
        clock2.increment("node1");

        assert_eq!(clock1.compare(&clock2), ClockOrdering::Before);
        assert_eq!(clock2.compare(&clock1), ClockOrdering::After);
        assert_eq!(clock1.compare(&clock1), ClockOrdering::Equal);
    }

    #[test]
    fn test_concurrent_compare() {
        let mut clock1 = VectorClock::new();
        clock1.increment("node1");

        let mut clock2 = VectorClock::new();
        clock2.increment("node2");

        assert_eq!(clock1.compare(&clock2), ClockOrdering::Concurrent);
        assert_eq!(clock2.compare(&clock1), ClockOrdering::Concurrent);
    }

    #[test]
    fn test_total_events() {
        let mut clock = VectorClock::new();
        clock.increment("node1");
        clock.increment("node1");
        clock.increment("node2");

        assert_eq!(clock.total_events(), 3);
    }
}
