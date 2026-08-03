//! Storage provider trait
//!
//! This module provides platform-aware async traits:
//! - Native: Uses `Send + Sync` bounds for multi-threaded environments
//! - WASM: No thread safety bounds (single-threaded)

use crate::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tags for record querying
pub type Tags = HashMap<String, String>;

/// Storage record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record category (e.g., "connection", "credential")
    pub category: String,

    /// Record name/ID
    pub name: String,

    /// Record value (serialized)
    pub value: Vec<u8>,

    /// Tags for querying
    #[serde(default)]
    pub tags: Tags,
}

impl Record {
    pub fn new(category: impl Into<String>, name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            value,
            tags: HashMap::new(),
        }
    }

    pub fn with_tags(mut self, tags: Tags) -> Self {
        self.tags = tags;
        self
    }

    pub fn add_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }
}

/// Query builder for searching records
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Tag filters (AND logic)
    pub tags: HashMap<String, String>,

    /// Maximum number of results
    pub limit: Option<usize>,

    /// Skip N results
    pub skip: Option<usize>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_skip(mut self, skip: usize) -> Self {
        self.skip = Some(skip);
        self
    }
}

/// Storage provider trait for persisting records.
///
/// Implementations provide storage backends (e.g., Askar, in-memory).
///
/// # Example
///
/// ```rust,no_run
/// # use agent_core::traits::{StorageProvider, Record};
/// # use agent_core::Result;
/// # async fn example(storage: impl StorageProvider) -> Result<()> {
/// // Save a record
/// let record = Record::new("connection", "conn-123", b"data".to_vec())
///     .add_tag("state", "complete");
/// storage.save(&record).await?;
///
/// // Find by name
/// let found = storage.find("connection", "conn-123").await?;
///
/// // Query by tags
/// use agent_core::traits::Query;
/// let query = Query::new().with_tag("state", "complete");
/// let results = storage.find_all("connection", &query).await?;
/// # Ok(())
/// # }
/// ```

#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Save a record
    async fn save(&self, record: &Record) -> Result<()>;

    /// Find a record by category and name
    async fn find(&self, category: &str, name: &str) -> Result<Option<Record>>;

    /// Find all records matching a query
    async fn find_all(&self, category: &str, query: &Query) -> Result<Vec<Record>>;

    /// Update a record
    async fn update(&self, record: &Record) -> Result<()>;

    /// Delete a record
    async fn delete(&self, category: &str, name: &str) -> Result<()>;

    /// Delete all records in a category
    async fn delete_all(&self, category: &str) -> Result<()>;

    /// Count records matching a query
    async fn count(&self, category: &str, query: &Query) -> Result<usize> {
        let records = self.find_all(category, query).await?;
        Ok(records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_builder() {
        let record = Record::new("test", "id-123", b"data".to_vec())
            .add_tag("type", "connection")
            .add_tag("state", "active");

        assert_eq!(record.category, "test");
        assert_eq!(record.name, "id-123");
        assert_eq!(record.tags.len(), 2);
    }

    #[test]
    fn test_query_builder() {
        let query = Query::new()
            .with_tag("state", "active")
            .with_limit(10)
            .with_skip(5);

        assert_eq!(query.tags.get("state"), Some(&"active".to_string()));
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.skip, Some(5));
    }
}
