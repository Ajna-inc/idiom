//! DID Method Registry
//!
//! Central registry for DID resolvers with caching and storage integration.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::{
    DidDocument, DidRecord, DidRepository, DidResolver, ResolutionError, ResolutionResult, DID,
};
use crate::registry::cache::DidCache;
use agent_core::traits::StorageProvider;

/// DID Registry - manages DID method resolvers with caching
pub struct DidRegistry {
    /// Registered DID method resolvers (method_name -> resolver)
    resolvers: HashMap<String, Arc<dyn DidResolver>>,

    /// Memory cache for remote-fetched DIDs (LRU with TTL)
    cache: Arc<RwLock<DidCache>>,

    /// In-memory repository for peer DIDs  
    did_repository: Option<Arc<DidRepository>>,

    /// Optional storage for DidRecord persistence
    storage: Option<Arc<dyn StorageProvider>>,
}

impl Default for DidRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DidRegistry {
    /// Create a new DID registry
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
            cache: Arc::new(RwLock::new(DidCache::default())),
            did_repository: None,
            storage: None,
        }
    }

    /// Create a new registry with storage
    pub fn with_storage(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            resolvers: HashMap::new(),
            cache: Arc::new(RwLock::new(DidCache::default())),
            did_repository: None,
            storage: Some(storage),
        }
    }

    /// Create a new registry with DID repository
    pub fn with_did_repository(did_repository: Arc<DidRepository>) -> Self {
        Self {
            resolvers: HashMap::new(),
            cache: Arc::new(RwLock::new(DidCache::default())),
            did_repository: Some(did_repository),
            storage: None,
        }
    }

    /// Create a new registry with both DID repository and storage
    pub fn with_did_repository_and_storage(
        did_repository: Arc<DidRepository>,
        storage: Arc<dyn StorageProvider>,
    ) -> Self {
        Self {
            resolvers: HashMap::new(),
            cache: Arc::new(RwLock::new(DidCache::default())),
            did_repository: Some(did_repository),
            storage: Some(storage),
        }
    }

    /// Register a DID method resolver
    pub fn register_resolver(&mut self, resolver: Arc<dyn DidResolver>) {
        let method = resolver.method_name().to_string();
        self.resolvers.insert(method, resolver);
    }

    /// Resolve a DID to a DID Document
    ///
    /// Resolution strategy
    /// 1. Check memory cache (if method allows caching)
    /// 2. Check DidRepository for peer DIDs (in-memory)
    /// 3. Check storage for DidRecord (if storage configured)
    /// 4. Use method resolver
    /// 5. Cache result (if method allows caching)
    pub async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        let method = did.method();

        // Debug: Only log for did:ajna
        tracing::debug!(target: "did.registry", did = %did.as_str(), "resolving");

        // Get the resolver for this method
        let resolver = self
            .resolvers
            .get(method)
            .ok_or_else(|| ResolutionError::UnsupportedMethod(method.to_string()))?;

        // Check if caching is allowed for this method
        if resolver.allows_caching() {
            // 1. Try cache first
            if let Some(doc) = self.cache.write().await.get(did) {
                tracing::debug!(target: "did.registry", "found in cache");
                return Ok(doc);
            }

            // 2. Try DidRepository (in-memory cache for peer DIDs)
            if let Some(repo) = &self.did_repository {
                if let Some(record) = repo.find_by_did(did.as_str()) {
                    if let Some(doc) = record.did_document {
                        tracing::debug!(target: "did.registry", "found in DidRepository");
                        // Cache the document
                        self.cache.write().await.put(did, doc.clone());
                        return Ok(doc);
                    }
                }
            }

            // 3. Try storage if configured (persistent storage)
            if let Some(storage) = &self.storage {
                if let Ok(Some(record)) = self.find_did_record(storage.as_ref(), did).await {
                    if let Some(doc) = record.did_document {
                        tracing::debug!(target: "did.registry", "found in storage");
                        // Cache the document
                        self.cache.write().await.put(did, doc.clone());
                        return Ok(doc);
                    }
                }
            }
        }

        // 4. Resolve using the method resolver
        tracing::debug!(target: "did.registry", %method, "using method resolver");
        let document = resolver.resolve(did).await?;

        // 5. Cache if allowed
        if resolver.allows_caching() {
            self.cache.write().await.put(did, document.clone());
        }

        Ok(document)
    }

    /// Find a DidRecord in storage by DID
    async fn find_did_record(
        &self,
        storage: &dyn StorageProvider,
        did: &DID,
    ) -> agent_core::Result<Option<DidRecord>> {
        use agent_core::traits::Query;

        // Query storage for DidRecord with matching DID tag
        let query = Query::new().with_tag("did", did.as_str());

        let records = storage.find_all("DidRecord", &query).await?;

        if records.is_empty() {
            return Ok(None);
        }

        // Deserialize the first record
        let record: DidRecord = serde_json::from_slice(&records[0].value).map_err(|e| {
            agent_core::AgentError::storage(format!("Failed to deserialize DidRecord: {}", e))
        })?;

        Ok(Some(record))
    }

    /// Save a DidRecord to storage
    pub async fn save_did_record(&self, record: &DidRecord) -> agent_core::Result<()> {
        if let Some(storage) = &self.storage {
            use agent_core::traits::Record;

            let value = serde_json::to_vec(record).map_err(|e| {
                agent_core::AgentError::storage(format!("Failed to serialize DidRecord: {}", e))
            })?;

            let storage_record = Record::new("DidRecord", &record.id, value)
                .add_tag("did", &record.did)
                .add_tag("role", format!("{:?}", record.role));

            storage.save(&storage_record).await?;
        }

        Ok(())
    }

    /// Clear the cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Get the number of registered resolvers
    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::KeyDidResolver;

    #[tokio::test]
    async fn test_register_resolver() {
        let mut registry = DidRegistry::new();
        registry.register_resolver(Arc::new(KeyDidResolver::new()));

        assert_eq!(registry.resolver_count(), 1);
    }

    #[tokio::test]
    async fn test_resolve_did_key() {
        let mut registry = DidRegistry::new();
        registry.register_resolver(Arc::new(KeyDidResolver::new()));

        let did = DID::parse("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
        let doc = registry.resolve(&did).await.unwrap();

        assert_eq!(doc.id, did.as_str());
    }

    #[tokio::test]
    async fn test_unsupported_method() {
        let registry = DidRegistry::new(); // No resolvers registered

        let did = DID::parse("did:unknown:abc123").unwrap();
        let result = registry.resolve(&did).await;

        assert!(result.is_err());
        match result {
            Err(ResolutionError::UnsupportedMethod(method)) => {
                assert_eq!(method, "unknown");
            }
            _ => panic!("Expected UnsupportedMethod error"),
        }
    }
}
