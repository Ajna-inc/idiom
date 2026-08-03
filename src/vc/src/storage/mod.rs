pub mod credential_record;
pub mod credential_repository;
pub mod presentation_record;

// Re-export commonly used types
pub use credential_record::{
    CredentialData, CredentialMetadata, CredentialRecord, CREDENTIAL_CATEGORY,
};

pub use credential_repository::{CredentialQuery, CredentialRepository, CredentialStore};

pub use presentation_record::{
    PresentationData, PresentationMetadata, PresentationRecord, PRESENTATION_CATEGORY,
};
