//! AnonCreds revocation support — minimal wrapper around `anoncreds-rs`.
//!
//! Exposes the upstream revocation primitives (RevocationRegistryDefinition,
//! RevocationStatusList, CredentialRevocationState) plus convenience helpers
//! so callers can:
//!
//! - issue credentials with `rev_reg_id` + `cred_rev_index`
//! - revoke (and un-revoke) credentials by index
//! - update a holder's revocation state against the latest status list
//! - verify a presentation containing non-revocation proofs
//!
//! Tails files are written to a directory chosen by the caller; the location
//! ends up embedded in the `RevocationRegistryDefinition` so holders can
//! download them when computing witnesses.

pub use anoncreds::data_types::cred_def::CredentialDefinitionId;
pub use anoncreds::data_types::rev_reg_def::{
    RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionId,
    RevocationRegistryDefinitionPrivate,
};
pub use anoncreds::data_types::rev_status_list::RevocationStatusList;
pub use anoncreds::tails::TailsFileWriter;
pub use anoncreds::types::{CredentialRevocationConfig, CredentialRevocationState};

use crate::error::{AnonCredsError, Result};

/// Build a fresh `RevocationRegistryDefinition` + private key pair under
/// `tails_dir`. The default `RegistryType::CL_ACCUM` is used — the only type
/// `anoncreds-rs` supports.
pub fn create_revocation_registry_def(
    cred_def: &anoncreds::data_types::cred_def::CredentialDefinition,
    cred_def_id: CredentialDefinitionId,
    tag: &str,
    max_cred_num: u32,
    tails_dir: Option<&str>,
) -> Result<(
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
)> {
    let mut tails_writer = TailsFileWriter::new(tails_dir.map(|s| s.to_string()));
    anoncreds::issuer::create_revocation_registry_def(
        cred_def,
        cred_def_id,
        tag,
        RegistryType::CL_ACCUM,
        max_cred_num,
        &mut tails_writer,
    )
    .map_err(|e| AnonCredsError::AnoncredsLib(format!("create_revocation_registry_def: {}", e)))
}

/// Build the initial status list for a freshly-created registry. With
/// `issuance_by_default = false`, every credential index is *revoked* until
/// issuance updates it to non-revoked (the default behaviour upstream).
pub fn create_initial_status_list(
    cred_def: &anoncreds::data_types::cred_def::CredentialDefinition,
    rev_reg_def_id: RevocationRegistryDefinitionId,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    issuance_by_default: bool,
    timestamp: Option<u64>,
) -> Result<RevocationStatusList> {
    anoncreds::issuer::create_revocation_status_list(
        cred_def,
        rev_reg_def_id,
        rev_reg_def,
        rev_reg_priv,
        issuance_by_default,
        timestamp,
    )
    .map_err(|e| AnonCredsError::AnoncredsLib(format!("create_revocation_status_list: {}", e)))
}

/// Apply (un)issuance / revocation to a status list and bump its timestamp.
///
/// `issued` and `revoked` are sets of `cred_rev_index` values; `timestamp`
/// is recorded on the new list so verifiers can pick the right snapshot for
/// a non-revoked interval.
pub fn update_status_list(
    cred_def: &anoncreds::data_types::cred_def::CredentialDefinition,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    current_list: &RevocationStatusList,
    timestamp: Option<u64>,
    issued: Option<std::collections::BTreeSet<u32>>,
    revoked: Option<std::collections::BTreeSet<u32>>,
) -> Result<RevocationStatusList> {
    anoncreds::issuer::update_revocation_status_list(
        cred_def,
        rev_reg_def,
        rev_reg_priv,
        current_list,
        issued,
        revoked,
        timestamp,
    )
    .map_err(|e| AnonCredsError::AnoncredsLib(format!("update_revocation_status_list: {}", e)))
}

/// Bump the timestamp on a status list without changing its accumulator.
/// Cheaper than a full update when no credentials were issued or revoked.
pub fn update_status_list_timestamp_only(
    timestamp: u64,
    current_list: &RevocationStatusList,
) -> RevocationStatusList {
    anoncreds::issuer::update_revocation_status_list_timestamp_only(timestamp, current_list)
}

/// Compute (or refresh) the holder-side revocation state needed to include
/// an NRP for a credential. Pass the previous state when refreshing so the
/// witness can update incrementally.
pub fn create_or_update_revocation_state(
    tails_location: &str,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_status_list: &RevocationStatusList,
    cred_rev_index: u32,
    prev_state: Option<&CredentialRevocationState>,
    prev_status_list: Option<&RevocationStatusList>,
) -> Result<CredentialRevocationState> {
    anoncreds::prover::create_or_update_revocation_state(
        tails_location,
        rev_reg_def,
        rev_status_list,
        cred_rev_index,
        prev_state,
        prev_status_list,
    )
    .map_err(|e| AnonCredsError::AnoncredsLib(format!("create_or_update_revocation_state: {}", e)))
}
