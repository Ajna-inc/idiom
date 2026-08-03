//! Per-peer channel state and lookup tables.

pub mod manager;
pub mod state;

pub use manager::ChannelManager;
pub use state::{Channel, ChannelState};
