//! did:ajna - A CRDT-based DID method for the Ajna blockchain
//!
//! This crate implements the did:ajna DID method, which uses CRDTs
//! (Conflict-free Replicated Data Types) for offline-first, eventually
//! consistent decentralized identity.
//!
//! ## Features
//!
//! - **CRDT-Based**: OR-Set for keys, LWW-Map for services
//! - **Vector Clocks**: Track causality for conflict resolution
//! - **Offline-First**: Works without blockchain, syncs via gossip
//! - **Eventually Consistent**: Deterministic merge semantics
//!
//! ## Architecture
//!
//! ```text
//! did:ajna Document
//! ├── id: String
//! ├── keys: ORSet<VerificationMethod>
//! ├── services: LWWMap<String, Service>
//! ├── clock: VectorClock
//! └── merkle_root: Hash
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use crate::ajna::{AjnaMethod, ORSet, LWWMap, VectorClock};
//!
//! // Create a did:ajna method
//! let ajna = AjnaMethod::new(agent);
//!
//! // Create a DID
//! let did = ajna.create(Default::default()).await?;
//!
//! // Update with CRDT operations
//! ajna.update(&did, vec![
//!     CRDTOp::AddKey(key),
//!     CRDTOp::AddService(service),
//! ]).await?;
//!
//! // Sync with peers (uses gossip protocol)
//! ajna.sync_with_peers().await?;
//! ```

pub mod anchoring;
pub mod authorization; // Authorization engine
pub mod bloom_filter; // Bloom filters for sync
pub mod crypto;
pub mod did_syntax; // DID syntax with multibase
pub mod didcomm_sync; // DIDComm sync protocol
pub mod document;
pub mod error;
pub mod lww_map;
pub mod merkle_dag;
pub mod method;
pub mod op_bundle; // Operation bundles for sync
pub mod operation_v2; // New operations
pub mod operations;
pub mod or_set;
pub mod resolver; // Multi-tier resolution
pub mod selective_disclosure;
pub mod vector_clock; // Selective disclosure with Merkle proofs

// DHT provider for Kademlia-based resolution (requires RocksDB, not available on iOS)
#[cfg(feature = "dht")]
pub mod dht_provider;

// Re-exports
pub use ::crypto::sid::{DIDKind, Network, SIDHeader, ShardId, Version, SID};
pub use anchoring::{AnchorRecord, AnchorStats, AnchoringService};
pub use authorization::{AuthorizationContext, AuthorizationEngine, AuthorizationResult};
pub use did_syntax::{AjnaDid, DID_METHOD, DID_PREFIX};
pub use document::{AjnaDocument, BlockchainAnchor, Service, VerificationMethod};
pub use error::{AjnaError, Result};
pub use lww_map::{LWWEntry, LWWMap};
pub use merkle_dag::{DagNode, Hash, MerkleDAG};
pub use method::AjnaMethod;
pub use operations::{CRDTOperation, DIDUpdate, DeltaSync, OperationBatch};
pub use or_set::ORSet;
pub use resolver::{CacheStats, DhtProvider, ResolutionService, VerificationLevel};
pub use selective_disclosure::{verify_field_proof, FieldIndex, FieldProof, MinimalDocument};
pub use vector_clock::{ClockOrdering, VectorClock};

// KademliaDhtProvider only available with dht feature (not on iOS)
#[cfg(feature = "dht")]
pub use dht_provider::KademliaDhtProvider;
