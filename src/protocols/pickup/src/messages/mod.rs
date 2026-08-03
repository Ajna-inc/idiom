//! Message Pickup Protocol V2 messages (RFC 0685)

mod delivery;
mod delivery_request;
mod live_delivery_change;
mod messages_received;
mod status;
mod status_request;

pub use delivery::MessageDeliveryMessage;
pub use delivery_request::DeliveryRequestMessage;
pub use live_delivery_change::LiveDeliveryChangeMessage;
pub use messages_received::MessagesReceivedMessage;
pub use status::StatusMessage;
pub use status_request::StatusRequestMessage;

/// Protocol base URI
pub const PROTOCOL_URI: &str = "https://didcomm.org/messagepickup/2.0";

/// All message types for this protocol
pub mod types {
    pub const STATUS_REQUEST: &str = "https://didcomm.org/messagepickup/2.0/status-request";
    pub const STATUS: &str = "https://didcomm.org/messagepickup/2.0/status";
    pub const DELIVERY_REQUEST: &str = "https://didcomm.org/messagepickup/2.0/delivery-request";
    pub const DELIVERY: &str = "https://didcomm.org/messagepickup/2.0/delivery";
    pub const MESSAGES_RECEIVED: &str = "https://didcomm.org/messagepickup/2.0/messages-received";
    pub const LIVE_DELIVERY_CHANGE: &str =
        "https://didcomm.org/messagepickup/2.0/live-delivery-change";
}
