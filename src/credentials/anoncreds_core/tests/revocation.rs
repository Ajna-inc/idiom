//! End-to-end test for AnonCreds revocation:
//!
//! Schema → CredDef(supports_revocation) → RevReg → Offer → Request → Issue
//! → ProcessCredential → BuildRevocationState → PresentWithNRP → VerifyWithRevocation

use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::*;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService, InMemoryRegistry,
};

#[tokio::test]
async fn test_full_revocation_flow() {
    // Tails are written to a per-test tempdir so multiple test runs don't
    // collide.
    let tails_dir = tempfile::tempdir().expect("create tempdir");
    let tails_path = tails_dir.path().to_string_lossy().to_string();

    let registry = Arc::new(InMemoryRegistry::new());
    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());

    // 1. Schema + CredDef (with revocation enabled).
    let schema_reg = issuer
        .create_schema(
            "did:example:issuer",
            "RevocableCredential",
            "1.0",
            vec!["name".to_string(), "age".to_string()],
        )
        .await
        .expect("create schema");

    let cred_def_reg = issuer
        .create_credential_definition(
            "did:example:issuer",
            &schema_reg.schema_id,
            "default",
            true, // support_revocation
        )
        .await
        .expect("create cred def");

    // 2. Issuer creates a revocation registry holding up to 10 credentials.
    let (rev_reg_id, rev_reg_def, rev_reg_priv, _initial_status) = issuer
        .create_revocation_registry(&cred_def_reg.cred_def_id, "default", 10, Some(&tails_path))
        .await
        .expect("create revocation registry");

    // 3. Offer → Request.
    let cred_offer = issuer
        .create_credential_offer(&schema_reg.schema_id, &cred_def_reg.cred_def_id)
        .await
        .expect("offer");

    let thread_id = "rev-thread-1";
    let cred_request = holder
        .create_credential_request(
            thread_id,
            &cred_offer,
            &cred_def_reg.cred_def_id,
            "holder-entropy",
        )
        .await
        .expect("request");

    // 4. Issue with revocation — credential occupies slot index 1 in the
    //    registry (0 is reserved by anoncreds-rs).
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), "Alice".to_string());
    attrs.insert("age".to_string(), "30".to_string());

    let cred_rev_index: u32 = 1;
    let (mut credential, _status_after_issue) = issuer
        .create_credential_with_revocation(
            &cred_def_reg.cred_def_id,
            &cred_offer,
            &cred_request,
            attrs,
            &rev_reg_id,
            &rev_reg_def,
            &rev_reg_priv,
            cred_rev_index,
        )
        .await
        .expect("issue with revocation");

    // 5. Holder processes the credential and records the accumulator index.
    let credential_id = holder
        .process_credential(thread_id, &mut credential, &cred_def_reg.cred_def_id)
        .await
        .expect("process credential");
    holder
        .set_cred_rev_index(&credential_id, cred_rev_index)
        .await
        .expect("set cred_rev_index");

    // 6. Verifier builds a proof request requiring non-revocation at "now".
    //    Use a sane far-future cap (year 2286).
    let far_future: u64 = 9_999_999_999;
    let mut requested_attrs = HashMap::new();
    requested_attrs.insert(
        "name_attr".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: Some(NonRevokedInterval {
                from: Some(1),
                to: Some(far_future),
            }),
        },
    );
    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "revocable-presentation",
        "1.0",
        requested_attrs,
        HashMap::new(),
    )
    .expect("presentation request");

    // 7. Holder builds revocation state and creates an NRP-bearing presentation.
    let rev_ctx = holder
        .build_revocation_state(&credential_id, None)
        .await
        .expect("build revocation state");

    let mut credential_map = HashMap::new();
    credential_map.insert("name_attr".to_string(), (credential_id.clone(), true));

    let mut rev_contexts = HashMap::new();
    rev_contexts.insert(credential_id.clone(), rev_ctx);

    let presentation = holder
        .create_presentation_with_revocation(&pres_request, &credential_map, None, &rev_contexts)
        .await
        .expect("create presentation with NRP");

    // 8. Verifier checks the presentation against the registry (which fetches
    //    rev_reg_def + status list automatically).
    let valid = verifier
        .verify_presentation_with_revocation(&presentation, &pres_request)
        .await
        .expect("verify with revocation");
    assert!(valid, "presentation with NRP should verify");

    // 9. Issuer revokes the credential and publishes a new status list.
    let mut revoked = std::collections::BTreeSet::new();
    revoked.insert(cred_rev_index);
    issuer
        .update_status_list(
            &rev_reg_id,
            &rev_reg_def,
            &rev_reg_priv,
            &cred_def_reg.cred_def_id,
            None,
            None,
            Some(revoked),
        )
        .await
        .expect("publish revocation");

    // 10. Holder refreshes its revocation state against the new list and
    //     builds a fresh presentation — verification should now FAIL because
    //     the credential is revoked.
    let new_rev_ctx = holder
        .build_revocation_state(&credential_id, None)
        .await
        .expect("rebuild revocation state");
    rev_contexts.insert(credential_id.clone(), new_rev_ctx);

    let presentation_after_revoke = holder
        .create_presentation_with_revocation(&pres_request, &credential_map, None, &rev_contexts)
        .await;

    match presentation_after_revoke {
        Ok(p) => {
            // The library may still build the presentation; verification has
            // to reject it.
            let valid = verifier
                .verify_presentation_with_revocation(&p, &pres_request)
                .await
                .unwrap_or(false);
            assert!(!valid, "verification should fail after revocation");
        }
        Err(_) => {
            // Alternatively the library may refuse to build a witness for a
            // revoked credential — that is also acceptable.
        }
    }
}
