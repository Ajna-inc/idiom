//! Basic Messages Protocol Message Types

mod basic_message;
pub mod delete_message;
pub mod edit_message;

pub use basic_message::{BasicMessage, L10n, Thread, BASIC_MESSAGE_TYPE};
pub use delete_message::{DeleteMessage, DELETE_MESSAGE_TYPE};
pub use edit_message::{EditMessage, EDIT_MESSAGE_TYPE};
