//! Minimal multi-tenant provider wrappers ported from essi-rs.
//!
//! Only the profile-scoped Storage/Wallet providers are carried into the
//! idiom build — they namespace records and keys per tenant profile over the
//! underlying `agent_core` `StorageProvider` / `WalletProvider`.

pub mod profile_scoped_storage;
pub mod profile_scoped_wallet;

pub use profile_scoped_storage::ProfileScopedStorageProvider;
pub use profile_scoped_wallet::ProfileScopedWalletProvider;
