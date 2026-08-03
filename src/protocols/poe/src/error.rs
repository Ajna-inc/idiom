//! PoE canonical errors. `code()` returns the wire code for `problem-report`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoeError {
    #[error("program not supported: {0}")]
    ProgramNotSupported(String),
    #[error("inputs invalid: {0}")]
    InputsInvalid(String),
    #[error("expired challenge")]
    ExpiredChallenge,
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    #[error("vk unknown: {0}")]
    VkUnknown(String),
    #[error("params unknown: {0}")]
    ParamsUnknown(String),
    #[error("context mismatch")]
    ContextMismatch,
    #[error("artifact too large: {0} bytes")]
    TooLarge(usize),
    #[error("rate limited")]
    RateLimited,
    #[error("attester unavailable")]
    AttesterUnavailable,
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl PoeError {
    /// Canonical PoE error code for a `problem-report`.
    pub fn code(&self) -> &'static str {
        match self {
            PoeError::ProgramNotSupported(_) => "program_not_supported",
            PoeError::InputsInvalid(_) => "inputs_invalid",
            PoeError::ExpiredChallenge => "expired_challenge",
            PoeError::PolicyViolation(_) => "policy_violation",
            PoeError::InvalidProof(_) => "invalid_proof",
            PoeError::VkUnknown(_) => "vk_unknown",
            PoeError::ParamsUnknown(_) => "params_unknown",
            PoeError::ContextMismatch => "context_mismatch",
            PoeError::TooLarge(_) => "too_large",
            PoeError::RateLimited => "rate_limited",
            PoeError::AttesterUnavailable => "attester_unavailable",
            PoeError::Serialization(_) | PoeError::Internal(_) => "internal_error",
        }
    }
}

pub type Result<T> = std::result::Result<T, PoeError>;
