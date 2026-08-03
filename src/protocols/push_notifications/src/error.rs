use thiserror::Error;

#[derive(Debug, Error)]
pub enum PushNotificationError {
    #[error("Device registration not found for connection: {0}")]
    NotFound(String),

    #[error("Invalid device platform: {0}")]
    InvalidPlatform(String),

    #[error("Mismatched fields: device_token and device_platform must both be set or both null")]
    MismatchedFields,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Push delivery error: {0}")]
    Delivery(String),
}

pub type Result<T> = std::result::Result<T, PushNotificationError>;
