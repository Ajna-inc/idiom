pub mod credential;
pub mod presentation;

// Re-export commonly used types
pub use credential::{
    CredentialContext, CredentialSchema, CredentialStatus, CredentialSubject,
    CredentialSubjectObject, Issuer, IssuerObject, OneOrMany, Proof, W3cCredential,
    W3cV2Credential,
};

pub use presentation::{
    DescriptorMapping, PresentationSubmission, VerifiableCredential, W3cPresentation,
    W3cV2Presentation,
};
