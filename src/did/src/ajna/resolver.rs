//! Multi-tier DID resolution service
//!
//! This module implements the resolution algorithm
//! Resolution can operate at three verification levels:
//! - T0: Local cache only (no network verification)
//! - T1: Verified against blockchain anchor
//! - T2: Verified with complete proof chain
//!
//! ## Resolution Flow
//!
//! ```text
//! 1. Check local cache (if fresh, return with T0)
//! 2. Sync via DIDComm gossip protocol
//! 3. Verify against blockchain anchor (if required)
//! 4. Materialize CRDT state → DID Document
//! 5. Validate consistency
//! 6. Return document + verification level
//! ```

use crate::ajna::anchoring::AnchoringService;
use crate::ajna::didcomm_sync::SyncProtocol;
use crate::ajna::document::AjnaDocument;
use crate::ajna::error::{AjnaError, Result};
use crate::ajna::method::AjnaMethod;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

/// DHT provider trait for DID resolution
///
/// This trait abstracts the DHT backend, allowing the resolver to query
/// DID documents from Kademlia DHT without depending on the specific implementation.
pub trait DhtProvider: Send + Sync {
    /// Get a DID document from DHT by DID string
    ///
    /// Returns the raw JSON value if found, or None if not in DHT
    fn get_value(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + '_>>;
}

/// Verification tier for DID resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// T0: Local cache only, no network verification
    T0,
    /// T1: Verified against blockchain anchor
    T1,
    /// T2: Verified with complete proof chain
    T2,
}

impl VerificationLevel {
    /// Check if this level is at least the required level
    pub fn satisfies(&self, required: VerificationLevel) -> bool {
        *self >= required
    }
}

impl std::fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationLevel::T0 => write!(f, "T0 (local)"),
            VerificationLevel::T1 => write!(f, "T1 (anchored)"),
            VerificationLevel::T2 => write!(f, "T2 (complete proof)"),
        }
    }
}

/// Cached resolution result
#[derive(Debug, Clone)]
struct CachedResolution {
    document: AjnaDocument,
    verification_level: VerificationLevel,
    cached_at: DateTime<Utc>,
}

impl CachedResolution {
    /// Check if cache is still fresh (< 1 hour old)
    fn is_fresh(&self) -> bool {
        let age = Utc::now() - self.cached_at;
        age.num_hours() < 1
    }
}

/// Multi-tier DID resolution service
pub struct ResolutionService {
    /// Reference to DID method for local resolution
    method: Arc<AjnaMethod>,

    /// Sync protocol for gossip-based resolution
    sync_protocol: Option<Arc<RwLock<SyncProtocol>>>,

    /// DHT provider for Kademlia-based resolution
    dht_provider: Option<Arc<dyn DhtProvider>>,

    /// Anchoring service for blockchain verification
    anchoring: Option<Arc<AnchoringService>>,

    /// Resolution cache (DID -> CachedResolution)
    cache: Arc<RwLock<HashMap<String, CachedResolution>>>,

    /// Cache TTL in seconds (default: 3600 = 1 hour)
    cache_ttl_seconds: i64,
}

impl ResolutionService {
    /// Create new resolution service
    pub fn new(method: Arc<AjnaMethod>) -> Self {
        Self {
            method,
            sync_protocol: None,
            dht_provider: None,
            anchoring: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: 3600, // 1 hour
        }
    }

    /// Create resolution service with sync protocol
    pub fn with_sync(method: Arc<AjnaMethod>, sync_protocol: Arc<RwLock<SyncProtocol>>) -> Self {
        Self {
            method,
            sync_protocol: Some(sync_protocol),
            dht_provider: None,
            anchoring: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: 3600,
        }
    }

    /// Create resolution service with DHT provider
    pub fn with_dht(method: Arc<AjnaMethod>, dht: Arc<dyn DhtProvider>) -> Self {
        Self {
            method,
            sync_protocol: None,
            dht_provider: Some(dht),
            anchoring: None,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: 3600,
        }
    }

    /// Create resolution service with anchoring
    pub fn with_anchoring(method: Arc<AjnaMethod>, anchoring: Arc<AnchoringService>) -> Self {
        Self {
            method,
            sync_protocol: None,
            dht_provider: None,
            anchoring: Some(anchoring),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: 3600,
        }
    }

    /// Create resolution service with all features
    pub fn full(
        method: Arc<AjnaMethod>,
        sync_protocol: Arc<RwLock<SyncProtocol>>,
        anchoring: Arc<AnchoringService>,
    ) -> Self {
        Self {
            method,
            sync_protocol: Some(sync_protocol),
            dht_provider: None,
            anchoring: Some(anchoring),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: 3600,
        }
    }

    /// Set cache TTL in seconds
    pub fn with_cache_ttl(mut self, ttl_seconds: i64) -> Self {
        self.cache_ttl_seconds = ttl_seconds;
        self
    }

    /// Set DHT provider (builder pattern)
    pub fn set_dht(mut self, dht: Arc<dyn DhtProvider>) -> Self {
        self.dht_provider = Some(dht);
        self
    }

    /// Set DHT provider on existing instance
    pub fn set_dht_provider(&mut self, dht: Arc<dyn DhtProvider>) {
        self.dht_provider = Some(dht);
    }

    /// Resolve DID with multi-tier verification
    ///
    /// # Arguments
    ///
    /// * `did` - DID to resolve
    /// * `required_level` - Minimum verification level required
    ///
    /// # Returns
    ///
    /// Returns `(document, actual_verification_level)`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (doc, level) = resolver.resolve("did:ajna:test", VerificationLevel::T1).await?;
    /// assert!(level.satisfies(VerificationLevel::T1));
    /// ```
    pub async fn resolve(
        &self,
        did: &str,
        required_level: VerificationLevel,
    ) -> Result<(AjnaDocument, VerificationLevel)> {
        // Step 1: Check local cache
        if let Some(cached) = self.check_cache(did, required_level).await? {
            return Ok((cached.document, cached.verification_level));
        }

        // Step 2: Resolve via local method first
        let document = match self.method.resolve(did).await {
            Ok(doc) => doc,
            Err(_) => {
                // If not found locally, try gossip sync
                return self.resolve_via_sync(did, required_level).await;
            }
        };

        // Step 3: Determine verification level
        let mut verification_level = VerificationLevel::T0;

        // Try to verify against anchor if required
        if required_level >= VerificationLevel::T1 {
            if let Some(ref anchoring) = self.anchoring {
                verification_level = self.verify_against_anchor(&document, anchoring).await?;
            }
        }

        // Step 4: Validate document
        self.validate(&document)?;

        // Step 5: Check if we met the required level
        if !verification_level.satisfies(required_level) {
            return Err(AjnaError::ResolutionFailed(format!(
                "Could not achieve required verification level {} (got {})",
                required_level, verification_level
            )));
        }

        // Step 6: Cache result
        self.cache_resolution(did, document.clone(), verification_level)
            .await;

        Ok((document, verification_level))
    }

    /// Check local cache for recent resolution
    async fn check_cache(
        &self,
        did: &str,
        required_level: VerificationLevel,
    ) -> Result<Option<CachedResolution>> {
        let cache = self.cache.read().await;

        if let Some(cached) = cache.get(did) {
            // Check if cache is fresh
            if cached.is_fresh() && cached.verification_level.satisfies(required_level) {
                return Ok(Some(cached.clone()));
            }
        }

        Ok(None)
    }

    /// Resolve via DHT (Kademlia-based resolution)
    ///
    /// This replaces the gossip-based resolution with reliable DHT lookup.
    /// The DHT stores DID documents as JSON values keyed by DID string.
    /// Supports both AjnaDocument (CRDT-based) and crate::core::DidDocument formats.
    async fn resolve_via_sync(
        &self,
        did: &str,
        required_level: VerificationLevel,
    ) -> Result<(AjnaDocument, VerificationLevel)> {
        // Try DHT resolution first (more reliable than gossip)
        if let Some(ref dht) = self.dht_provider {
            if let Some(value) = dht.get_value(did).await {
                // Try to parse as AjnaDocument first (native format)
                let document = if let Ok(doc) =
                    serde_json::from_value::<AjnaDocument>(value.clone())
                {
                    doc
                } else {
                    // Fall back to crate::core::DidDocument format and convert
                    let did_core_doc: crate::core::DidDocument = serde_json::from_value(value)
                        .map_err(|e| AjnaError::ResolutionFailed(format!(
                            "Failed to parse DID document from DHT (tried both AjnaDocument and DidDocument): {}", e
                        )))?;

                    // Convert crate::core::DidDocument to AjnaDocument
                    AjnaDocument::from_did_core(&did_core_doc).map_err(|e| {
                        AjnaError::ResolutionFailed(format!(
                            "Failed to convert DidDocument to AjnaDocument: {}",
                            e
                        ))
                    })?
                };

                // Validate the document
                self.validate(&document)?;

                // DHT resolution provides T0 level (no blockchain verification)
                // If higher level required, try anchoring
                let mut verification_level = VerificationLevel::T0;

                if required_level >= VerificationLevel::T1 {
                    if let Some(ref anchoring) = self.anchoring {
                        verification_level =
                            self.verify_against_anchor(&document, anchoring).await?;
                    }
                }

                // Check if we met the required level
                if !verification_level.satisfies(required_level) {
                    return Err(AjnaError::ResolutionFailed(format!(
                        "Could not achieve required verification level {} (got {})",
                        required_level, verification_level
                    )));
                }

                // Cache the result
                self.cache_resolution(did, document.clone(), verification_level)
                    .await;

                return Ok((document, verification_level));
            }
        }

        // Fall back to gossip if DHT not available or DID not found
        if self.sync_protocol.is_some() {
            // TODO: Implement gossip fallback if needed
            // For now, gossip is deprecated in favor of DHT
        }

        Err(AjnaError::ResolutionFailed(format!(
            "DID {} not found in DHT or local storage",
            did
        )))
    }

    /// Verify document against blockchain anchor
    async fn verify_against_anchor(
        &self,
        document: &AjnaDocument,
        anchoring: &AnchoringService,
    ) -> Result<VerificationLevel> {
        // Get latest anchor for this DID
        let anchor = match anchoring.get_anchor(&document.id).await {
            Some(a) => a,
            None => {
                // No anchor found, return T0
                return Ok(VerificationLevel::T0);
            }
        };

        // Compute current merkle root from document's DAG
        // TODO: This requires access to the DAG from the document
        // For now, we'll check if the document has an anchor

        if let Some(doc_anchor) = &document.blockchain_anchor {
            // Compare anchor hashes
            if doc_anchor.merkle_root == anchor.merkle_root {
                // Document matches latest anchor
                return Ok(VerificationLevel::T1);
            }
        }

        // Document is newer than anchor or no anchor
        Ok(VerificationLevel::T0)
    }

    /// Validate document consistency
    fn validate(&self, document: &AjnaDocument) -> Result<()> {
        // Check if deactivated
        if document.is_deactivated() {
            return Err(AjnaError::DeactivatedDID);
        }

        // Check all verification method references are valid
        if let Some(ref auth) = document.authentication {
            for vm_id in auth.elements() {
                if document.get_verification_method(&vm_id).is_none() {
                    return Err(AjnaError::InvalidReference(format!(
                        "Authentication references non-existent VM: {}",
                        vm_id
                    )));
                }
            }
        }

        if let Some(ref assertion) = document.assertion_method {
            for vm_id in assertion.elements() {
                if document.get_verification_method(&vm_id).is_none() {
                    return Err(AjnaError::InvalidReference(format!(
                        "AssertionMethod references non-existent VM: {}",
                        vm_id
                    )));
                }
            }
        }

        // TODO: Additional validation
        // - Check key agreement references
        // - Check capability invocation references
        // - Check capability delegation references
        // - Validate policy structure

        Ok(())
    }

    /// Cache resolution result
    async fn cache_resolution(
        &self,
        did: &str,
        document: AjnaDocument,
        verification_level: VerificationLevel,
    ) {
        let cached = CachedResolution {
            document,
            verification_level,
            cached_at: Utc::now(),
        };

        self.cache.write().await.insert(did.to_string(), cached);
    }

    /// Clear cache for a specific DID
    pub async fn invalidate_cache(&self, did: &str) {
        self.cache.write().await.remove(did);
    }

    /// Clear entire cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let fresh_entries = cache.values().filter(|c| c.is_fresh()).count();
        let t0_entries = cache
            .values()
            .filter(|c| c.verification_level == VerificationLevel::T0)
            .count();
        let t1_entries = cache
            .values()
            .filter(|c| c.verification_level == VerificationLevel::T1)
            .count();
        let t2_entries = cache
            .values()
            .filter(|c| c.verification_level == VerificationLevel::T2)
            .count();

        CacheStats {
            total_entries,
            fresh_entries,
            t0_entries,
            t1_entries,
            t2_entries,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub fresh_entries: usize,
    pub t0_entries: usize,
    pub t1_entries: usize,
    pub t2_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::method::AjnaMethod;

    fn create_test_method() -> Arc<AjnaMethod> {
        Arc::new(AjnaMethod::new("test_node".to_string()))
    }

    #[tokio::test]
    async fn test_create_resolver() {
        let method = create_test_method();
        let resolver = ResolutionService::new(method);

        let stats = resolver.cache_stats().await;
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn test_resolve_local() {
        let method = create_test_method();
        let did = method.create(Default::default()).await.unwrap();

        let resolver = ResolutionService::new(method.clone());

        // Resolve with T0 (local only)
        let (doc, level) = resolver
            .resolve(&did.id, VerificationLevel::T0)
            .await
            .unwrap();

        assert_eq!(doc.id, did.id);
        assert_eq!(level, VerificationLevel::T0);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let method = create_test_method();
        let did = method.create(Default::default()).await.unwrap();

        let resolver = ResolutionService::new(method.clone());

        // First resolution (cache miss)
        let (doc1, _) = resolver
            .resolve(&did.id, VerificationLevel::T0)
            .await
            .unwrap();

        // Second resolution (cache hit)
        let (doc2, _) = resolver
            .resolve(&did.id, VerificationLevel::T0)
            .await
            .unwrap();

        assert_eq!(doc1.id, doc2.id);

        let stats = resolver.cache_stats().await;
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.fresh_entries, 1);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let method = create_test_method();
        let did = method.create(Default::default()).await.unwrap();

        let resolver = ResolutionService::new(method.clone());

        // Resolve and cache
        resolver
            .resolve(&did.id, VerificationLevel::T0)
            .await
            .unwrap();

        assert_eq!(resolver.cache_stats().await.total_entries, 1);

        // Invalidate cache
        resolver.invalidate_cache(&did.id).await;

        assert_eq!(resolver.cache_stats().await.total_entries, 0);
    }

    #[tokio::test]
    async fn test_verification_level_ordering() {
        assert!(VerificationLevel::T0 < VerificationLevel::T1);
        assert!(VerificationLevel::T1 < VerificationLevel::T2);

        assert!(VerificationLevel::T2.satisfies(VerificationLevel::T0));
        assert!(VerificationLevel::T2.satisfies(VerificationLevel::T1));
        assert!(VerificationLevel::T2.satisfies(VerificationLevel::T2));

        assert!(!VerificationLevel::T0.satisfies(VerificationLevel::T1));
    }

    #[tokio::test]
    async fn test_validation_deactivated() {
        let method = create_test_method();
        let did = method.create(Default::default()).await.unwrap();

        // Deactivate the DID
        method
            .deactivate(&did.id, Some("Test deactivation".to_string()))
            .await
            .unwrap();

        let resolver = ResolutionService::new(method.clone());

        // Resolution should fail for deactivated DID
        let result = resolver.resolve(&did.id, VerificationLevel::T0).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AjnaError::DeactivatedDID));
    }

    #[tokio::test]
    async fn test_resolve_nonexistent() {
        let method = create_test_method();
        let resolver = ResolutionService::new(method);

        // Try to resolve non-existent DID
        let result = resolver
            .resolve("did:ajna:nonexistent", VerificationLevel::T0)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let method = create_test_method();
        let resolver = ResolutionService::new(method.clone());

        // Create and resolve a DID
        let did1 = method.create(Default::default()).await.unwrap();
        resolver
            .resolve(&did1.id, VerificationLevel::T0)
            .await
            .unwrap();

        // Resolve the same DID again (cache hit)
        resolver
            .resolve(&did1.id, VerificationLevel::T0)
            .await
            .unwrap();

        let stats = resolver.cache_stats().await;
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.fresh_entries, 1);
        assert_eq!(stats.t0_entries, 1);
    }
}
