/// Full AnonCreds flow integration test:
/// Schema → CredDef → Offer → Request → Issue → Process → PresentationRequest → Present → Verify
use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::*;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService, InMemoryRegistry,
};

#[tokio::test]
async fn test_full_issuance_and_verification_flow() {
    let registry = Arc::new(InMemoryRegistry::new());

    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());

    // 1. Issuer: create schema
    let schema_reg = issuer
        .create_schema(
            "did:example:issuer",
            "IdentityCredential",
            "1.0",
            vec!["name".to_string(), "age".to_string(), "country".to_string()],
        )
        .await
        .unwrap();

    println!("Schema ID: {}", schema_reg.schema_id);

    // 2. Issuer: create credential definition
    let cred_def_reg = issuer
        .create_credential_definition(
            "did:example:issuer",
            &schema_reg.schema_id,
            "default",
            false,
        )
        .await
        .unwrap();

    println!("CredDef ID: {}", cred_def_reg.cred_def_id);

    // 3. Issuer: create credential offer
    let cred_offer = issuer
        .create_credential_offer(&schema_reg.schema_id, &cred_def_reg.cred_def_id)
        .await
        .unwrap();

    // 4. Holder: create credential request
    let thread_id = "thread-123";
    let cred_request = holder
        .create_credential_request(
            thread_id,
            &cred_offer,
            &cred_def_reg.cred_def_id,
            "holder-entropy-12345",
        )
        .await
        .unwrap();

    // 5. Issuer: issue credential
    let mut attributes = HashMap::new();
    attributes.insert("name".to_string(), "Alice".to_string());
    attributes.insert("age".to_string(), "30".to_string());
    attributes.insert("country".to_string(), "US".to_string());

    let mut credential = issuer
        .create_credential(
            &cred_def_reg.cred_def_id,
            &cred_offer,
            &cred_request,
            attributes,
        )
        .await
        .unwrap();

    // 6. Holder: process credential
    let credential_id = holder
        .process_credential(thread_id, &mut credential, &cred_def_reg.cred_def_id)
        .await
        .unwrap();

    println!("Stored credential ID: {}", credential_id);

    // Verify credential is stored
    let stored_attrs = holder
        .get_credential_attributes(&credential_id)
        .await
        .unwrap();
    assert_eq!(stored_attrs.get("name").unwrap(), "Alice");
    assert_eq!(stored_attrs.get("age").unwrap(), "30");

    // 7. Verifier: create presentation request
    let mut requested_attributes = HashMap::new();
    requested_attributes.insert(
        "attr1_referent".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: None,
        },
    );
    requested_attributes.insert(
        "attr2_referent".to_string(),
        AttributeInfo {
            name: Some("country".to_string()),
            names: None,
            restrictions: None,
            non_revoked: None,
        },
    );

    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "identity-proof",
        "1.0",
        requested_attributes,
        HashMap::new(), // no predicates
    )
    .unwrap();

    // 8. Holder: find matching credentials
    let matching = holder
        .find_credentials_for_request(&pres_request)
        .await
        .unwrap();
    assert!(matching
        .get("attr1_referent")
        .unwrap()
        .contains(&credential_id));
    assert!(matching
        .get("attr2_referent")
        .unwrap()
        .contains(&credential_id));

    // 9. Holder: create presentation
    let mut credential_map = HashMap::new();
    credential_map.insert("attr1_referent".to_string(), (credential_id.clone(), true)); // revealed
    credential_map.insert("attr2_referent".to_string(), (credential_id.clone(), true)); // revealed

    let presentation = holder
        .create_presentation(&pres_request, &credential_map, None)
        .await
        .unwrap();

    // 10. Verifier: verify presentation
    let valid = verifier
        .verify_presentation(&presentation, &pres_request)
        .await
        .unwrap();
    assert!(valid, "Presentation should be valid");

    // 11. Extract revealed attributes
    let revealed = AnonCredsVerifierService::extract_revealed_attributes(&presentation);
    assert_eq!(revealed.get("attr1_referent").unwrap(), "Alice");
    assert_eq!(revealed.get("attr2_referent").unwrap(), "US");

    println!("Full AnonCreds flow completed successfully!");
}

#[tokio::test]
async fn test_predicate_proof() {
    let registry = Arc::new(InMemoryRegistry::new());

    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());

    // Setup: schema + cred def + issue credential
    let schema_reg = issuer
        .create_schema(
            "did:example:issuer",
            "AgeCredential",
            "1.0",
            vec!["name".to_string(), "age".to_string()],
        )
        .await
        .unwrap();

    let cred_def_reg = issuer
        .create_credential_definition(
            "did:example:issuer",
            &schema_reg.schema_id,
            "default",
            false,
        )
        .await
        .unwrap();

    let cred_offer = issuer
        .create_credential_offer(&schema_reg.schema_id, &cred_def_reg.cred_def_id)
        .await
        .unwrap();

    let thread_id = "thread-pred-456";
    let cred_request = holder
        .create_credential_request(
            thread_id,
            &cred_offer,
            &cred_def_reg.cred_def_id,
            "holder-entropy-pred",
        )
        .await
        .unwrap();

    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), "Bob".to_string());
    attrs.insert("age".to_string(), "25".to_string());

    let mut credential = issuer
        .create_credential(&cred_def_reg.cred_def_id, &cred_offer, &cred_request, attrs)
        .await
        .unwrap();

    let credential_id = holder
        .process_credential(thread_id, &mut credential, &cred_def_reg.cred_def_id)
        .await
        .unwrap();

    // Create a proof request with a predicate: age >= 18
    let mut requested_predicates = HashMap::new();
    requested_predicates.insert(
        "pred1_referent".to_string(),
        PredicateInfo {
            name: "age".to_string(),
            p_type: PredicateTypes::GE,
            p_value: 18,
            restrictions: None,
            non_revoked: None,
        },
    );

    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "age-proof",
        "1.0",
        HashMap::new(), // no revealed attributes
        requested_predicates,
    )
    .unwrap();

    // Holder: create presentation with predicate
    let mut credential_map = HashMap::new();
    credential_map.insert("pred1_referent".to_string(), (credential_id.clone(), false));

    let presentation = holder
        .create_presentation(&pres_request, &credential_map, None)
        .await
        .unwrap();

    // Verify: should prove age >= 18 without revealing actual age
    let valid = verifier
        .verify_presentation(&presentation, &pres_request)
        .await
        .unwrap();
    assert!(valid, "Predicate proof should be valid");

    println!("Predicate proof (age >= 18) verified successfully!");
}
