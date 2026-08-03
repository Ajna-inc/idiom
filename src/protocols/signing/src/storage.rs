//! Storage schema for signing protocol records in Askar
//!
//! Defines record categories and tag schemas for persisting
//! signing sessions, participants, and tokens.

/// Storage category for signing sessions
pub const CATEGORY_SESSION: &str = "signing_session";

/// Storage category for session participants
pub const CATEGORY_PARTICIPANT: &str = "signing_participant";

/// Storage category for authorization tokens
pub const CATEGORY_TOKEN: &str = "signing_token";

/// Storage category for monotonic counters (used by MonotonicCounterManager)
pub const CATEGORY_COUNTER: &str = "signing_counter";

/// Tag keys used across signing protocol records
pub mod tags {
    /// Session state (e.g., "proposed", "requested", "completed")
    pub const STATE: &str = "state";
    /// Coordinator DID
    pub const COORDINATOR_DID: &str = "coordinator_did";
    /// Thread ID for DIDComm correlation
    pub const THREAD_ID: &str = "thread_id";
    /// Session ID
    pub const SESSION_ID: &str = "session_id";
    /// Participant/signer DID
    pub const DID: &str = "did";
    /// Device ID for counter binding
    pub const DEVICE_ID: &str = "device_id";
    /// Whether consent was given
    pub const CONSENTED: &str = "consented";
    /// Whether signature was provided
    pub const SIGNED: &str = "signed";
    /// Token issuer DID
    pub const ISSUER: &str = "issuer";
    /// Token subject DID
    pub const SUBJECT: &str = "subject";
    /// Counter value
    pub const COUNTER: &str = "counter";
}
