pub use anoncreds::data_types::cred_def::{
    CredentialDefinition, CredentialDefinitionData, CredentialDefinitionPrivate, SignatureType,
};
pub use anoncreds::data_types::credential::{AttributeValues, Credential, CredentialValues};
/// Re-exports and wrapper types for AnonCreds data types
// Core identifier types
pub use anoncreds::data_types::issuer_id::IssuerId;
pub use anoncreds::data_types::link_secret::LinkSecret;
pub use anoncreds::data_types::nonce::Nonce;
pub use anoncreds::data_types::pres_request::{
    AttributeInfo, NonRevokedInterval, PredicateInfo, PredicateTypes, PresentationRequest,
    PresentationRequestPayload,
};
pub use anoncreds::data_types::presentation::{
    Identifier, Presentation, RequestedProof, RevealedAttributeInfo,
};
pub use anoncreds::data_types::schema::{AttributeNames, Schema};

// Credential offer/request types
pub use anoncreds::data_types::cred_def::CredentialKeyCorrectnessProof;
pub use anoncreds::data_types::cred_offer::CredentialOffer;
pub use anoncreds::data_types::cred_request::{CredentialRequest, CredentialRequestMetadata};

// Schema/CredDef identifiers
pub use anoncreds::data_types::cred_def::CredentialDefinitionId;
pub use anoncreds::data_types::schema::SchemaId;

// Service types (builders)
pub use anoncreds::types::{CredentialDefinitionConfig, MakeCredentialValues, PresentCredentials};

use serde::{Deserialize, Serialize};

use crate::error::AnonCredsError;

/// Result of registering a schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaRegistration {
    pub schema_id: String,
    pub schema: Schema,
}

/// Result of registering a credential definition
#[derive(Debug, Serialize, Deserialize)]
pub struct CredDefRegistration {
    pub cred_def_id: String,
    pub credential_definition: CredentialDefinition,
}

/// Stored credential with metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub credential: Credential,
    pub schema_id: String,
    pub cred_def_id: String,
    pub attributes: std::collections::HashMap<String, String>,
}

/// Clone a CredentialDefinition via serialization (it doesn't impl Clone)
pub fn clone_cred_def(
    cred_def: &CredentialDefinition,
) -> Result<CredentialDefinition, AnonCredsError> {
    let json = serde_json::to_value(cred_def)
        .map_err(|e| AnonCredsError::AnoncredsLib(format!("Serialize cred_def: {}", e)))?;
    serde_json::from_value(json)
        .map_err(|e| AnonCredsError::AnoncredsLib(format!("Deserialize cred_def: {}", e)))
}

/// Clone a Credential via serialization (it doesn't impl Clone)
pub fn clone_credential(credential: &Credential) -> Result<Credential, AnonCredsError> {
    let json = serde_json::to_value(credential)
        .map_err(|e| AnonCredsError::AnoncredsLib(format!("Serialize credential: {}", e)))?;
    serde_json::from_value(json)
        .map_err(|e| AnonCredsError::AnoncredsLib(format!("Deserialize credential: {}", e)))
}
