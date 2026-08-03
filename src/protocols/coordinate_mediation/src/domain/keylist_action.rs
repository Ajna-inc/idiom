use serde::{Deserialize, Serialize};
use std::fmt;

/// Action to perform on a keylist entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeylistAction {
    /// Add a key to the keylist
    Add,
    /// Remove a key from the keylist
    Remove,
}

impl fmt::Display for KeylistAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Remove => write!(f, "remove"),
        }
    }
}

/// Result of a keylist update operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeylistResult {
    /// Operation succeeded
    Success,
    /// Client error (invalid request)
    ClientError,
    /// Server error (mediator failure)
    ServerError,
    /// No change was made
    NoChange,
}

impl fmt::Display for KeylistResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::ClientError => write!(f, "client_error"),
            Self::ServerError => write!(f, "server_error"),
            Self::NoChange => write!(f, "no_change"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_display() {
        assert_eq!(KeylistAction::Add.to_string(), "add");
        assert_eq!(KeylistAction::Remove.to_string(), "remove");
    }

    #[test]
    fn test_result_display() {
        assert_eq!(KeylistResult::Success.to_string(), "success");
        assert_eq!(KeylistResult::ClientError.to_string(), "client_error");
        assert_eq!(KeylistResult::ServerError.to_string(), "server_error");
        assert_eq!(KeylistResult::NoChange.to_string(), "no_change");
    }

    #[test]
    fn test_action_serialization() {
        let action = KeylistAction::Add;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"add\"");

        let action = KeylistAction::Remove;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"remove\"");
    }

    #[test]
    fn test_result_serialization() {
        let result = KeylistResult::Success;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"success\"");

        let result = KeylistResult::ClientError;
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, "\"client_error\"");
    }
}
