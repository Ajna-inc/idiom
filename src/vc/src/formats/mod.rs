#[cfg(feature = "anoncreds")]
pub mod anoncreds;
pub mod format_transformer;
pub mod jsonld_vc;
pub mod jwt_vc;
pub mod mdoc;
pub mod sd_jwt;
pub mod status_list;

pub use status_list::{
    check_status as check_credential_status, decode_status_list as decode_status_list_bits,
    extract_credential_status, read_status_bit, CredentialStatusEntry, StatusListError,
    StatusListIndex, StatusVerdict,
};

// Re-export JWT-VC types
pub use jwt_vc::{
    EnhancedJwtVcService, EnhancedJwtVcServiceV2, JwtVcPayload, JwtVcService, JwtVcTransformer,
    JwtVpPayload, WalletBackedJwtVcService, WalletJwtSigner,
};

// Re-export JSON-LD VC types
pub use jsonld_vc::{
    ContextLoader, DocumentLoader, Ed25519Signature2018Suite, Ed25519Signature2020Suite,
    JsonLdVcService, ProofOptions, ProofPurpose, SignatureSuite,
};

// Re-export SD-JWT types
pub use sd_jwt::{
    CompactSdJwt, Disclosure, DisclosureFrame, DisclosureProcessor, KeyBindingJwt, SdJwtClaims,
    SdJwtError, SdJwtHasher, SdJwtHolder, SdJwtIssuer, SdJwtService, SdJwtVc, SdJwtVerifier,
};

// Re-export mDoc types
pub use mdoc::disclosure::{
    DisclosureProcessor as MdocDisclosureProcessor, DisclosureRequest, DocRequest,
};
pub use mdoc::{
    DeviceAuth, DeviceKeyInfo, IssuerAuth, IssuerSignedItem, MDoc, MdocEncoder, MdocService,
    MobileSecurityObject, DOCTYPE_MDL, NAMESPACE_MDL,
};

// Re-export AnonCreds format service
#[cfg(feature = "anoncreds")]
pub use anoncreds::AnonCredsFormatService;

// Re-export format transformer
pub use format_transformer::{FormatTransformer, TransformError};
