//! High-level module wrappers for protocol implementations
//!
//! This module provides ergonomic APIs for different protocols

#[cfg(feature = "anoncreds")]
pub mod anoncreds_module;
pub mod basic_messages;
pub mod connections;
pub mod credentials;
pub mod dids;
pub mod ecash_transfer;
pub mod mediation;
pub mod oid4vci;
pub mod oid4vp;
pub mod oob;
pub mod push_notifications;
pub mod user_profile;
pub mod wallet;
pub mod workflow;
#[cfg(feature = "anoncreds")]
pub mod workflow_actions;

#[cfg(feature = "anoncreds")]
pub use anoncreds_module::{AnonCredsConfig, AnonCredsModule};
pub use basic_messages::BasicMessagesModule;
pub use connections::ConnectionsModule;
pub use credentials::{CredentialsConfig, CredentialsModule};
pub use dids::DidModule;
pub use ecash_transfer::{
    BatchAckData, BatchTransferHandler, DidSigner, NoteReceiver, SecureKeyProvider,
    TransferDoneResult, PIURI_BATCH_ACK, PIURI_BATCH_COMMIT, PIURI_BATCH_DONE, PIURI_BATCH_REVEAL,
};
pub use mediation::{
    MediationConfig, MediationMediatorApi, MediationModule, MediationRecipientApi,
};
pub use oid4vp::Oid4vpHolderService;
pub use oob::{
    InvitationConfig, OutOfBandModule, ParsedInvitationInfo, ReceiveInvitationResult, ServiceInfo,
};
pub use push_notifications::PushNotificationsModule;
pub use user_profile::UserProfileModule;
pub use wallet::WalletModule;
pub use workflow::WorkflowModule;
