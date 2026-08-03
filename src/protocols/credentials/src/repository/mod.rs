// Credential exchange repository

mod credential_exchange;
mod storage_backed;

pub use credential_exchange::{
    CredentialExchangeRecord, CredentialExchangeRepository, CredentialExchangeRepositoryTrait,
};
pub use storage_backed::StorageBackedCredentialExchangeRepository;
