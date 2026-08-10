//! Per-peer channel state and lookup tables.

pub mod manager;
pub mod persistence;
pub mod state;

pub use manager::ChannelManager;
pub use persistence::{ChannelCounterStore, PersistedCounters, SEND_RESERVATION_BATCH};
pub use state::{Channel, ChannelState};
