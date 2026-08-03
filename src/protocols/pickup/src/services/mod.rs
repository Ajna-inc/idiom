//! Services for Message Pickup Protocol V2

mod pickup_mediator;
mod pickup_recipient;

pub use pickup_mediator::PickupMediatorService;
pub use pickup_recipient::{DeliveredMessage, PickupRecipientService, PickupStatus};
