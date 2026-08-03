/// AnonCreds format service for vc_formats
///
/// Bridges the W3C VC API (CredentialFormatService) with AnonCreds operations.
/// AnonCreds has a fundamentally different credential model from W3C VCs,
/// so this service translates between the two using the `additional` HashMap
/// in SignCredentialOptions/VerifyCredentialOptions for AnonCreds-specific data.
mod format_service;

pub use format_service::AnonCredsFormatService;
