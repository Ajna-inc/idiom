// AnonCreds Issue-Credential handlers — feature-gated (depend on the
// AnonCreds `CredentialExchangeService`).
#[cfg(feature = "anoncreds")]
mod ack_handler;
#[cfg(feature = "anoncreds")]
mod issue_handler;
#[cfg(feature = "anoncreds")]
mod offer_handler;
#[cfg(feature = "anoncreds")]
mod problem_report_handler;
#[cfg(feature = "anoncreds")]
mod propose_handler;
#[cfg(feature = "anoncreds")]
mod request_handler;

#[cfg(feature = "anoncreds")]
pub use ack_handler::CredentialAckHandler;
#[cfg(feature = "anoncreds")]
pub use issue_handler::IssueCredentialHandler;
#[cfg(feature = "anoncreds")]
pub use offer_handler::OfferCredentialHandler;
#[cfg(feature = "anoncreds")]
pub use problem_report_handler::ProblemReportHandler;
#[cfg(feature = "anoncreds")]
pub use propose_handler::ProposeCredentialHandler;
#[cfg(feature = "anoncreds")]
pub use request_handler::RequestCredentialHandler;

// W3C / JWT-VC / SD-JWT handlers — always available.
mod w3c_handlers;
pub use w3c_handlers::{
    W3cIssueCredentialHandler, W3cOfferCredentialHandler, W3cRequestCredentialHandler,
};
