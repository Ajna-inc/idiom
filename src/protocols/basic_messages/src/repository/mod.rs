//! Basic Messages Repository

mod basic_message_record;
mod basic_message_repository;
mod storage_backed_repository;

pub use basic_message_record::{BasicMessageRecord, BasicMessageRole, BasicMessageTags};
pub use basic_message_repository::{
    BasicMessageError, BasicMessageQuery, BasicMessageRepository, BasicMessageRepositoryTrait,
    Result,
};
pub use storage_backed_repository::StorageBackedBasicMessageRepository;
