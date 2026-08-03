//! End-to-end AnonCreds revocation tests.
//!
//! Covers the issuer-side revocation toolkit (`update_status_list`) and
//! the holder/verifier dance for non-revocation proofs: issue → present
//! with NRP → verify; revoke → re-present → verification rejects.

use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::*;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService, InMemoryRegistry,
};

async fn setup() -> (
    Arc<InMemoryRegistry>,
    AnonCredsIssuerService,
    AnonCredsHolderService,
    AnonCredsVerifierService,
    tempfile::TempDir,
    String, // schema_id
    String, // cred_def_id
) {
    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());
    let tails_dir = tempfile::tempdir().expect("tails dir");

    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "ParityRevocable",
            "1.0",
            vec!["name".into(), "age".into()],
        )
        .await
        .unwrap();
    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", true)
        .await
        .unwrap();

    (
        registry,
        issuer,
        holder,
        verifier,
        tails_dir,
        schema.schema_id,
        cred_def.cred_def_id,
    )
}

#[tokio::test]
async fn issue_and_verify_with_nrp_succeeds() {
    let (_registry, issuer, holder, verifier, tails_dir, schema_id, cred_def_id) = setup().await;
    let tails_path = tails_dir.path().to_string_lossy().to_string();
    let (rev_reg_id, rev_reg_def, rev_reg_priv, _initial) = issuer
        .create_revocation_registry(&cred_def_id, "parity", 5, Some(&tails_path))
        .await
        .unwrap();

    let offer = issuer
        .create_credential_offer(&schema_id, &cred_def_id)
        .await
        .unwrap();
    let thread_id = "thread-1";
    let req = holder
        .create_credential_request(thread_id, &offer, &cred_def_id, "entropy")
        .await
        .unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".into(), "Bob".into());
    attrs.insert("age".into(), "40".into());
    let cred_rev_index = 1;
    let (mut cred, _) = issuer
        .create_credential_with_revocation(
            &cred_def_id,
            &offer,
            &req,
            attrs,
            &rev_reg_id,
            &rev_reg_def,
            &rev_reg_priv,
            cred_rev_index,
        )
        .await
        .unwrap();
    let credential_id = holder
        .process_credential(thread_id, &mut cred, &cred_def_id)
        .await
        .unwrap();
    holder
        .set_cred_rev_index(&credential_id, cred_rev_index)
        .await
        .unwrap();

    let mut requested_attrs = HashMap::new();
    requested_attrs.insert(
        "name_attr".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: Some(NonRevokedInterval {
                from: Some(1),
                to: Some(9_999_999_999),
            }),
        },
    );
    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "parity-presentation",
        "1.0",
        requested_attrs,
        HashMap::new(),
    )
    .unwrap();

    let rev_ctx = holder
        .build_revocation_state(&credential_id, None)
        .await
        .unwrap();
    let mut credential_map = HashMap::new();
    credential_map.insert("name_attr".to_string(), (credential_id.clone(), true));
    let mut rev_contexts = HashMap::new();
    rev_contexts.insert(credential_id.clone(), rev_ctx);

    let presentation = holder
        .create_presentation_with_revocation(&pres_request, &credential_map, None, &rev_contexts)
        .await
        .unwrap();
    let valid = verifier
        .verify_presentation_with_revocation(&presentation, &pres_request)
        .await
        .unwrap();
    assert!(valid, "NRP-bearing presentation must verify");
}

#[tokio::test]
async fn revoking_a_credential_then_re_verifying_fails() {
    let (_registry, issuer, holder, verifier, tails_dir, schema_id, cred_def_id) = setup().await;
    let tails_path = tails_dir.path().to_string_lossy().to_string();
    let (rev_reg_id, rev_reg_def, rev_reg_priv, _initial) = issuer
        .create_revocation_registry(&cred_def_id, "parity", 5, Some(&tails_path))
        .await
        .unwrap();

    let offer = issuer
        .create_credential_offer(&schema_id, &cred_def_id)
        .await
        .unwrap();
    let thread_id = "thread-2";
    let req = holder
        .create_credential_request(thread_id, &offer, &cred_def_id, "entropy")
        .await
        .unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".into(), "Carol".into());
    attrs.insert("age".into(), "29".into());
    let cred_rev_index = 2;
    let (mut cred, _) = issuer
        .create_credential_with_revocation(
            &cred_def_id,
            &offer,
            &req,
            attrs,
            &rev_reg_id,
            &rev_reg_def,
            &rev_reg_priv,
            cred_rev_index,
        )
        .await
        .unwrap();
    let credential_id = holder
        .process_credential(thread_id, &mut cred, &cred_def_id)
        .await
        .unwrap();
    holder
        .set_cred_rev_index(&credential_id, cred_rev_index)
        .await
        .unwrap();

    // Issuer revokes this credential index.
    let mut revoked = std::collections::BTreeSet::new();
    revoked.insert(cred_rev_index);
    issuer
        .update_status_list(
            &rev_reg_id,
            &rev_reg_def,
            &rev_reg_priv,
            &cred_def_id,
            None,
            None,
            Some(revoked),
        )
        .await
        .unwrap();

    // Holder refreshes state and builds presentation; verification must fail.
    let rev_ctx = holder
        .build_revocation_state(&credential_id, None)
        .await
        .unwrap();
    let mut credential_map = HashMap::new();
    credential_map.insert("name_attr".to_string(), (credential_id.clone(), true));
    let mut rev_contexts = HashMap::new();
    rev_contexts.insert(credential_id.clone(), rev_ctx);

    let mut requested_attrs = HashMap::new();
    requested_attrs.insert(
        "name_attr".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: Some(NonRevokedInterval {
                from: Some(1),
                to: Some(9_999_999_999),
            }),
        },
    );
    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "parity-post-revoke",
        "1.0",
        requested_attrs,
        HashMap::new(),
    )
    .unwrap();

    let presentation_attempt = holder
        .create_presentation_with_revocation(&pres_request, &credential_map, None, &rev_contexts)
        .await;

    match presentation_attempt {
        Ok(p) => {
            let valid = verifier
                .verify_presentation_with_revocation(&p, &pres_request)
                .await
                .unwrap_or(false);
            assert!(
                !valid,
                "verification must fail once the credential is revoked"
            );
        }
        Err(_) => {
            // anoncreds-rs may refuse to build a witness for a revoked
            // credential — that's also acceptable behaviour.
        }
    }
}
