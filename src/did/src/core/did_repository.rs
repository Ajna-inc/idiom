//! DID Repository - Storage for DID Documents
//!
//! This allows lightweight connection records while maintaining full cryptographic material

use crate::core::{DidDocument, DidDocumentKey, DidRecord, DidRole};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Callback for persisting DID records to storage
/// Sends the record to a channel for async persistence
pub type PersistSender = mpsc::UnboundedSender<DidRecord>;

/// DID Repository - In-memory storage for DID documents with optional persistence
///
/// - Stores DidRecords indexed by DID
/// - Supports lookup by DID
/// - Separates DID storage from connection storage
/// - Optional persistence callback for async storage
pub struct DidRepository {
    records: Arc<RwLock<HashMap<String, DidRecord>>>,
    /// Optional channel for sending records to be persisted
    persist_sender: Arc<RwLock<Option<PersistSender>>>,
}

impl DidRepository {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            persist_sender: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the persistence sender for async storage
    ///
    /// When set, all stored DID records will be sent to this channel
    /// for persistence to durable storage.
    pub fn set_persist_sender(&self, sender: PersistSender) {
        let mut guard = self.persist_sender.write().unwrap();
        *guard = Some(sender);
    }

    /// Send a record for persistence (non-blocking)
    fn persist_record(&self, record: &DidRecord) {
        if let Ok(guard) = self.persist_sender.read() {
            if let Some(sender) = guard.as_ref() {
                // Non-blocking send - if it fails, we still have the in-memory copy
                let _ = sender.send(record.clone());
            }
        }
    }

    /// Store a received DID document
    ///
    /// - Stores full document for peer:1
    /// - Creates a DidRecord with role=Received
    /// - Persists to durable storage if persistence is configured
    pub fn store_received_did(
        &self,
        did: String,
        did_document: Option<DidDocument>,
        keys: Vec<DidDocumentKey>,
    ) -> Result<DidRecord, String> {
        // A Received record must NEVER overwrite a Created one for the
        // same DID. The Created record carries the KMS key bindings we
        // need to pack outbound messages; a Received record has none
        // (we don't own the peer's keys). The collision is real in
        // self-connections (DM with yourself): the same repo processes
        // both roles of the exchange, so "their" DID is one of OUR
        // created DIDs — clobbering it broke every subsequent pack
        // with "Sender key not found". We avoid this by storing
        // created and received DID records separately; we keep the
        // by-DID map but make Created records win.
        {
            let records = self.records.read().unwrap();
            if let Some(existing) = records.get(&did) {
                if existing.role == DidRole::Created {
                    return Ok(existing.clone());
                }
            }
        }

        let record = DidRecord {
            id: Uuid::new_v4().to_string(),
            did: did.clone(),
            role: DidRole::Received,
            did_document,
            keys,
            created_at: Utc::now(),
            updated_at: None,
        };

        // Store in memory
        let mut records = self.records.write().unwrap();
        records.insert(did, record.clone());

        // Persist to durable storage (non-blocking)
        self.persist_record(&record);

        Ok(record)
    }

    /// Store a created DID document
    ///
    /// For DIDs created by this agent
    /// - Persists to durable storage if persistence is configured
    pub fn store_created_did(
        &self,
        did: String,
        did_document: Option<DidDocument>,
        keys: Vec<DidDocumentKey>,
    ) -> Result<DidRecord, String> {
        let record = DidRecord {
            id: Uuid::new_v4().to_string(),
            did: did.clone(),
            role: DidRole::Created,
            did_document,
            keys,
            created_at: Utc::now(),
            updated_at: None,
        };

        // Store in memory
        let mut records = self.records.write().unwrap();
        records.insert(did, record.clone());

        // Persist to durable storage (non-blocking)
        self.persist_record(&record);

        Ok(record)
    }

    /// Insert a pre-existing DID record (for loading from storage)
    ///
    /// This does NOT trigger persistence since the record already exists in storage.
    ///
    /// Created records win over Received ones for the same DID — same
    /// invariant as `store_received_did`. Storage can hold BOTH rows
    /// for one DID (they were persisted under different record ids
    /// before the overwrite guard existed), and `find_all` returns
    /// them in arbitrary order; without this check a keyless Received
    /// stub could clobber the Created record's KMS bindings on every
    /// restart.
    pub fn insert_loaded_record(&self, record: DidRecord) {
        let did = record.did.clone();
        let mut records = self.records.write().unwrap();
        if let Some(existing) = records.get(&did) {
            if existing.role == DidRole::Created && record.role == DidRole::Received {
                return;
            }
        }
        records.insert(did, record);
    }

    /// Get all stored DID records
    pub fn get_all(&self) -> Vec<DidRecord> {
        let records = self.records.read().unwrap();
        records.values().cloned().collect()
    }

    /// Find DID record by DID string
    ///
    /// Returns the stored DidRecord for the given DID
    pub fn find_by_did(&self, did: &str) -> Option<DidRecord> {
        let records = self.records.read().unwrap();
        // Debug: log for did:ajna lookups (only compute the suffixes when the
        // debug level is actually enabled). Character-based truncation keeps the
        // display UTF-8 safe (Sanskrit DIDs have multi-byte chars).
        if did.starts_with("did:ajna:")
            && tracing::enabled!(target: "did.repository", tracing::Level::DEBUG)
        {
            let stored: Vec<String> = records
                .keys()
                .filter(|k| k.starts_with("did:ajna:"))
                .map(|d| d.chars().skip(9).take(20).collect())
                .collect();
            tracing::debug!(
                target: "did.repository",
                did = %did.chars().skip(9).take(20).collect::<String>(),
                stored_count = stored.len(),
                ?stored,
                "find_by_did (did:ajna)"
            );
        }
        records.get(did).cloned()
    }
}

impl Default for DidRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_find_did() {
        let repo = DidRepository::new();

        let did = "did:peer:1abc".to_string();
        let doc = DidDocument {
            id: did.clone(),
            ..Default::default()
        };

        let result = repo.store_received_did(did.clone(), Some(doc.clone()), vec![]);

        assert!(result.is_ok());
        let stored_record = result.unwrap();
        assert_eq!(stored_record.did, did);
        assert_eq!(stored_record.role, DidRole::Received);

        let found = repo.find_by_did(&did);
        assert!(found.is_some());
        assert_eq!(found.unwrap().did, did);
    }

    #[test]
    fn test_store_created_did() {
        let repo = DidRepository::new();

        let did = "did:peer:1xyz".to_string();
        let keys = vec![DidDocumentKey::new(
            "key-1".to_string(),
            "#key-1".to_string(),
        )];

        let result = repo.store_created_did(did.clone(), None, keys.clone());

        assert!(result.is_ok());
        let stored_record = result.unwrap();
        assert_eq!(stored_record.did, did);
        assert_eq!(stored_record.role, DidRole::Created);
        assert_eq!(stored_record.keys.len(), 1);
    }
}
