//! Protocol identifier URIs for the DIDComm Signing Protocol 1.0

/// Base protocol URI
pub const PROTOCOL_URI: &str = "https://didcomm.org/signing/1.0";

/// Propose signing - capability discovery (optional first step)
pub const PIURI_PROPOSE_SIGNING: &str = "https://didcomm.org/signing/1.0/propose-signing";

/// Request signing - initiate a signing session
pub const PIURI_REQUEST_SIGNING: &str = "https://didcomm.org/signing/1.0/request-signing";

/// Consent - signer agrees to participate with key binding proof
pub const PIURI_CONSENT: &str = "https://didcomm.org/signing/1.0/consent";

/// Partial signature - signer submits their signature/share
pub const PIURI_PARTIAL_SIGNATURE: &str = "https://didcomm.org/signing/1.0/partial-signature";

/// Combine - aggregation status from coordinator
pub const PIURI_COMBINE: &str = "https://didcomm.org/signing/1.0/combine";

/// Provide artifacts - deliver signed outputs or sealed secrets
pub const PIURI_PROVIDE_ARTIFACTS: &str = "https://didcomm.org/signing/1.0/provide-artifacts";

/// Issue token - deliver authorization token with sealed secret
pub const PIURI_ISSUE_TOKEN: &str = "https://didcomm.org/signing/1.0/issue-token";

/// Ack - receipt acknowledgment
pub const PIURI_ACK: &str = "https://didcomm.org/signing/1.0/ack";

/// Decline - signer or coordinator declines the signing request
pub const PIURI_DECLINE: &str = "https://didcomm.org/signing/1.0/decline";

/// Problem report - error notification
pub const PIURI_PROBLEM_REPORT: &str = "https://didcomm.org/signing/1.0/problem-report";

/// All supported message types for handler registration
pub const SUPPORTED_TYPES: &[&str] = &[
    PIURI_PROPOSE_SIGNING,
    PIURI_REQUEST_SIGNING,
    PIURI_CONSENT,
    PIURI_PARTIAL_SIGNATURE,
    PIURI_COMBINE,
    PIURI_PROVIDE_ARTIFACTS,
    PIURI_ISSUE_TOKEN,
    PIURI_ACK,
    PIURI_DECLINE,
    PIURI_PROBLEM_REPORT,
];
