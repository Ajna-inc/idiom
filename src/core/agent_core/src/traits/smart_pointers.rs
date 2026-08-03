//! Platform-aware smart pointer types
//!
//! This module provides type aliases for trait object pointers that work
//! across both native (multi-threaded) and WASM (single-threaded) environments.
//!
//! - Native: Uses `Arc` (thread-safe atomic reference counting)
//! - WASM: Uses `Rc` (single-threaded reference counting)
//!
//! # Usage
//!
//! ```rust,ignore
//! use agent_core::traits::{WalletRef, StorageRef, TransportRef};
//!
//! // In native code:
//! let wallet: WalletRef = Arc::new(MyWallet);
//!
//! // In WASM code:
//! let wallet: WalletRef = Rc::new(MyWallet);
//! ```

use super::{StorageProvider, TransportProvider, WalletProvider};

// Use Arc for thread-safe sharing
use std::sync::Arc;

pub type WalletRef = Arc<dyn WalletProvider>;

pub type StorageRef = Arc<dyn StorageProvider>;

pub type TransportRef = Arc<dyn TransportProvider>;
