//! Repository module for Message Pickup Protocol V2

mod message_queue;
mod storage_backed_message_queue;

pub use message_queue::{InMemoryMessageQueueRepository, MessageQueueRepositoryTrait};
pub use storage_backed_message_queue::StorageBackedMessageQueueRepository;
