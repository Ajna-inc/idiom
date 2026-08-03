//! Direct anoncreds-rs flow for non-revocation proofs — no wrapper layer.
//!
//! Mirrors anoncreds_demos.rs's `anoncreds_with_revocation_works_for_single_credential`
//! line-for-line to confirm the upstream library can verify an NRP under our
//! dependency pin. Once this passes, we can re-introduce the service layer
//! and diff for whatever it does differently.

use std::collections::HashMap;

use anoncreds::data_types::cred_def::CredentialDefinitionId;
use anoncreds::data_types::rev_reg_def::{
    RevocationRegistryDefinition, RevocationRegistryDefinitionId,
};
use anoncreds::data_types::rev_status_list::RevocationStatusList;
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::issuer;
use anoncreds::prover;
use anoncreds::tails::TailsFileWriter;
use anoncreds::types::{
    CredentialDefinitionConfig, CredentialRevocationConfig, MakeCredentialValues,
    PresentCredentials, PresentationRequest, RegistryType, SignatureType,
};
use anoncreds::verifier;

const ISSUER_ID: &str = "did:example:issuer";
const SCHEMA_ID: &str = "did:example:issuer/schema/1.0";
const CRED_DEF_ID: &str = "did:example:issuer/cred-def/1";
const REV_REG_DEF_ID: &str = "did:example:issuer/rev-reg/1";
const REV_IDX: u32 = 1;

#[test]
fn direct_anoncreds_rs_nrp_flow() {
    // 1. Schema + cred_def (support_revocation = true).
    let schema = issuer::create_schema(
        "RevocableCred",
        "1.0",
        ISSUER_ID.try_into().unwrap(),
        vec!["name".to_string(), "age".to_string()].into(),
    )
    .unwrap();
    let (cred_def, cred_def_priv, key_correctness_proof) = issuer::create_credential_definition(
        SCHEMA_ID.try_into().unwrap(),
        &schema,
        ISSUER_ID.try_into().unwrap(),
        "default",
        SignatureType::CL,
        CredentialDefinitionConfig {
            support_revocation: true,
        },
    )
    .unwrap();

    // 2. Rev reg + initial status list at t=12.
    let mut tf = TailsFileWriter::new(None);
    let (rev_reg_def, rev_reg_def_priv) = issuer::create_revocation_registry_def(
        &cred_def,
        CRED_DEF_ID.try_into().unwrap(),
        "default",
        RegistryType::CL_ACCUM,
        10,
        &mut tf,
    )
    .unwrap();
    let time_initial: u64 = 12;
    let initial_status_list = issuer::create_revocation_status_list(
        &cred_def,
        REV_REG_DEF_ID.try_into().unwrap(),
        &rev_reg_def,
        &rev_reg_def_priv,
        true, // issuance_by_default
        Some(time_initial),
    )
    .unwrap();

    // 3. Offer → request.
    let offer = issuer::create_credential_offer(
        SchemaId::new_unchecked(SCHEMA_ID),
        CredentialDefinitionId::new_unchecked(CRED_DEF_ID),
        &key_correctness_proof,
    )
    .unwrap();

    let link_secret = prover::create_link_secret().unwrap();
    let (cred_request, cred_request_metadata) = prover::create_credential_request(
        Some("entropy"),
        None,
        &cred_def,
        &link_secret,
        "default-id",
        &offer,
    )
    .unwrap();

    // 4. Issuer issues a credential against the initial status list.
    let mut values = MakeCredentialValues::default();
    values.add_raw("name", "Alice").unwrap();
    values.add_raw("age", "30").unwrap();

    let revocation_config = CredentialRevocationConfig {
        reg_def: &rev_reg_def,
        reg_def_private: &rev_reg_def_priv,
        registry_idx: REV_IDX,
        status_list: &initial_status_list,
    };
    let mut credential = issuer::create_credential(
        &cred_def,
        &cred_def_priv,
        &offer,
        &cred_request,
        values.into(),
        Some(revocation_config),
    )
    .unwrap();

    // 5. Issuer publishes a new status list at t=13 with this index issued.
    let time_after_issue: u64 = 13;
    let mut issued_set = std::collections::BTreeSet::new();
    issued_set.insert(REV_IDX);
    let issued_status_list = issuer::update_revocation_status_list(
        &cred_def,
        &rev_reg_def,
        &rev_reg_def_priv,
        &initial_status_list,
        Some(issued_set),
        None,
        Some(time_after_issue),
    )
    .unwrap();

    // 6. Holder processes the credential.
    prover::process_credential(
        &mut credential,
        &cred_request_metadata,
        &link_secret,
        &cred_def,
        Some(&rev_reg_def),
    )
    .unwrap();

    // 7. Verifier builds a proof request that requires NRP.
    let pres_req: PresentationRequest = serde_json::from_value(serde_json::json!({
        "nonce": verifier::generate_nonce().unwrap().to_string(),
        "name": "test-presentation",
        "version": "1.0",
        "requested_attributes": {
            "name_attr": {
                "name": "name",
                "non_revoked": {"from": 10, "to": 200}
            }
        },
        "requested_predicates": {}
    }))
    .unwrap();

    // 8. Holder builds rev_state from initial list, presents with t=13.
    let rev_state = prover::create_or_update_revocation_state(
        &rev_reg_def.value.tails_location,
        &rev_reg_def,
        &initial_status_list,
        REV_IDX,
        None,
        None,
    )
    .unwrap();

    let mut present_creds = PresentCredentials::default();
    {
        let mut add =
            present_creds.add_credential(&credential, Some(time_after_issue), Some(&rev_state));
        add.add_requested_attribute("name_attr".to_string(), true);
    }

    let mut schemas: HashMap<SchemaId, Schema> = HashMap::new();
    schemas.insert(SchemaId::new_unchecked(SCHEMA_ID), schema.clone());
    let mut cred_defs = HashMap::new();
    cred_defs.insert(CredentialDefinitionId::new_unchecked(CRED_DEF_ID), cred_def);

    let presentation = prover::create_presentation(
        &pres_req,
        present_creds,
        None,
        &link_secret,
        &schemas,
        &cred_defs,
    )
    .unwrap();

    // 9. Verify against the issued (t=13) status list.
    let mut rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> =
        HashMap::new();
    rev_reg_defs.insert(
        RevocationRegistryDefinitionId::new_unchecked(REV_REG_DEF_ID),
        rev_reg_def.clone(),
    );

    let rev_status_lists: Vec<RevocationStatusList> = vec![issued_status_list];

    let valid = verifier::verify_presentation(
        &presentation,
        &pres_req,
        &schemas,
        &cred_defs,
        Some(&rev_reg_defs),
        Some(rev_status_lists),
        None,
    )
    .expect("verify_presentation completed");

    assert!(valid, "direct anoncreds-rs NRP flow must verify");
}
