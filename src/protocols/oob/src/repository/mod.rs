// Repository module - will be implemented in the next step
// This will include OutOfBandRecord and OutOfBandRepository

pub mod oob_record;
pub mod oob_repository;

pub use oob_record::{InlineServiceKey, OutOfBandRecord, OutOfBandTags};
pub use oob_repository::OutOfBandRepository;
