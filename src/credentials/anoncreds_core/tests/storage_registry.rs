//! Persistence test for `StorageBackedRegistry`. Confirms schemas, cred
//! defs, revocation registry definitions, and status lists round-trip
//! through `StorageProvider` and resolve correctly at-or-before a given
//! timestamp.

use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::*;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsRegistry, AnonCredsVerifierService,
    StorageBackedRegistry,
};
use storage::memory::MemoryStorage;

#[tokio::test]
async fn schema_and_cred_def_round_trip_through_storage() {
    let storage = Arc::new(MemoryStorage::new());
    let registry: Arc<dyn AnonCredsRegistry> =
        Arc::new(StorageBackedRegistry::new(storage.clone()));
    let issuer = AnonCredsIssuerService::new(registry.clone());

    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "StorageTestSchema",
            "1.0",
            vec!["name".into()],
        )
        .await
        .unwrap();

    // Fetch via a second registry handle pointed at the same storage —
    // simulates a different process resolving the schema later.
    let registry2: Arc<dyn AnonCredsRegistry> =
        Arc::new(StorageBackedRegistry::new(storage.clone()));
    let resolved = registry2.get_schema(&schema.schema_id).await.unwrap();
    assert_eq!(resolved.name, "StorageTestSchema");

    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", true)
        .await
        .unwrap();
    let resolved_def = registry2
        .get_credential_definition(&cred_def.cred_def_id)
        .await
        .unwrap();
    assert_eq!(resolved_def.tag, "default");
}

#[tokio::test]
async fn revocation_status_lists_resolve_at_timestamp() {
    let storage = Arc::new(MemoryStorage::new());
    let registry: Arc<dyn AnonCredsRegistry> =
        Arc::new(StorageBackedRegistry::new(storage.clone()));
    let issuer = AnonCredsIssuerService::new(registry.clone());

    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "RevocationStorage",
            "1.0",
            vec!["age".into()],
        )
        .await
        .unwrap();
    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", true)
        .await
        .unwrap();

    let tails_dir = tempfile::tempdir().unwrap();
    let (rev_reg_id, rev_reg_def, _rev_reg_priv, _initial_status) = issuer
        .create_revocation_registry(
            &cred_def.cred_def_id,
            "default",
            5,
            Some(tails_dir.path().to_str().unwrap()),
        )
        .await
        .unwrap();
    assert!(rev_reg_id.contains(":4:"));

    // Resolve rev_reg_def via a second registry handle (cold cache).
    let registry2: Arc<dyn AnonCredsRegistry> =
        Arc::new(StorageBackedRegistry::new(storage.clone()));
    let resolved_def = registry2
        .get_revocation_registry_def(&rev_reg_id)
        .await
        .unwrap();
    assert_eq!(resolved_def.tag, rev_reg_def.tag);

    // The initial status list was registered with the current timestamp;
    // ensure get_revocation_status_list returns it.
    let latest = registry2
        .get_revocation_status_list(&rev_reg_id, None)
        .await
        .unwrap();
    let latest_ts = serde_json::to_value(&latest)
        .unwrap()
        .get("timestamp")
        .and_then(|t| t.as_u64())
        .unwrap();
    assert!(latest_ts > 0);

    // Asking for an earlier timestamp before any list existed should error.
    let too_old = registry2
        .get_revocation_status_list(&rev_reg_id, Some(1))
        .await;
    assert!(too_old.is_err());
}

#[tokio::test]
async fn full_anoncreds_flow_through_storage_registry() {
    let storage = Arc::new(MemoryStorage::new());
    let registry: Arc<dyn AnonCredsRegistry> =
        Arc::new(StorageBackedRegistry::new(storage.clone()));

    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());

    let schema = issuer
        .create_schema(
            "did:example:issuer",
            "StorageFlow",
            "1.0",
            vec!["name".into()],
        )
        .await
        .unwrap();
    let cred_def = issuer
        .create_credential_definition("did:example:issuer", &schema.schema_id, "default", false)
        .await
        .unwrap();

    let offer = issuer
        .create_credential_offer(&schema.schema_id, &cred_def.cred_def_id)
        .await
        .unwrap();
    let thread_id = "thread-storage";
    let req = holder
        .create_credential_request(thread_id, &offer, &cred_def.cred_def_id, "entropy")
        .await
        .unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), "Dave".to_string());
    let mut cred = issuer
        .create_credential(&cred_def.cred_def_id, &offer, &req, attrs)
        .await
        .unwrap();
    let credential_id = holder
        .process_credential(thread_id, &mut cred, &cred_def.cred_def_id)
        .await
        .unwrap();

    let mut requested_attrs = HashMap::new();
    requested_attrs.insert(
        "name_attr".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: None,
        },
    );
    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "storage-flow",
        "1.0",
        requested_attrs,
        HashMap::new(),
    )
    .unwrap();

    let mut credential_map = HashMap::new();
    credential_map.insert("name_attr".to_string(), (credential_id, true));

    let presentation = holder
        .create_presentation(&pres_request, &credential_map, None)
        .await
        .unwrap();
    let valid = verifier
        .verify_presentation(&presentation, &pres_request)
        .await
        .unwrap();
    assert!(
        valid,
        "non-revocable presentation must verify against storage-backed registry"
    );
}
