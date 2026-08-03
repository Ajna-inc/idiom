//! Global cache for did:peer:1 DID documents
//!
//! Since did:peer:1 resolution requires the genesis document (which we have when we create the DID),
//! we cache the DID documents we create so they can be resolved later.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;
use crate::core::DidDocument;

/// Global cache for did:peer:1 DID documents
static PEER1_CACHE: Lazy<Arc<RwLock<HashMap<String, DidDocument>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Store a did:peer:1 DID document in the global cache
pub fn store_peer1_doc(did: String, doc: DidDocument) {
    let mut cache = PEER1_CACHE.write().unwrap();
    cache.insert(did, doc);
}

/// Retrieve a did:peer:1 DID document from the global cache
pub fn get_peer1_doc(did: &str) -> Option<DidDocument> {
    let cache = PEER1_CACHE.read().unwrap();
    cache.get(did).cloned()
}
