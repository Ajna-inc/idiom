//! Core service traits
//!
//! This module provides platform-aware async traits and smart pointer types:
//! - Native: Uses `Send + Sync` bounds and `Arc` for multi-threaded environments
//! - WASM: No thread safety bounds, uses `Rc` for single-threaded environment

pub mod blockchain;
pub mod smart_pointers;
pub mod storage;
pub mod transport;
pub mod wallet;

pub use blockchain::{
    AccountState, BlockchainError, BlockchainResult, BlockchainService, ConsensusStatus,
    DidRegistrationResult, FaucetResult, TransactionResult,
};
pub use smart_pointers::{StorageRef, TransportRef, WalletRef};
pub use storage::{Query, Record, StorageProvider, Tags};
pub use transport::{TransportProvider, TransportSession};
pub use wallet::{Key, KeyPurpose, KeyType, Signature, WalletProvider};
