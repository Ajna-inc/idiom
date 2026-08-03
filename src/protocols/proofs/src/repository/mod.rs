// Proof exchange repository

mod proof_exchange;
mod proof_exchange_repository;
mod storage_backed;

pub use proof_exchange::ProofExchangeRecord;
pub use proof_exchange_repository::{ProofExchangeRepository, ProofExchangeRepositoryTrait};
pub use storage_backed::StorageBackedProofExchangeRepository;
