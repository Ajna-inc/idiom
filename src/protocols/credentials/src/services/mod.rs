// Credential exchange services

// AnonCreds exchange service (CL signatures) — feature-gated.
#[cfg(feature = "anoncreds")]
mod credential_service;
#[cfg(feature = "anoncreds")]
pub use credential_service::CredentialExchangeService;

// W3C / JWT-VC / SD-JWT exchange service — always available (no CL signatures).
mod w3c_credential_service;
pub use w3c_credential_service::{
    W3cCredentialExchangeService, W3cCredentialExchangeServiceBuilder,
};
