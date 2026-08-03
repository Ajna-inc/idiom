pub mod error;
pub mod models;
pub mod traits;

// Re-export commonly used types
pub use error::{CredentialError, Result};

pub use models::{
    CredentialContext, CredentialSchema, CredentialStatus, CredentialSubject,
    CredentialSubjectObject, DescriptorMapping, Issuer, IssuerObject, OneOrMany,
    PresentationSubmission, Proof, VerifiableCredential, W3cCredential, W3cPresentation,
    W3cV2Credential, W3cV2Presentation,
};

pub use traits::{
    CredentialData, CredentialFormat, CredentialFormatService, DocumentSigner, JwtSigner,
    KeyResolver, KeyType, ProofPurpose, SignCredentialOptions, SignatureAlgorithm, SigningKey,
    VerificationMethod, VerificationResult, VerifyCredentialOptions,
};
