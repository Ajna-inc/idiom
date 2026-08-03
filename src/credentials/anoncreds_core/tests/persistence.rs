/// Persistence round-trip tests for AnonCreds services.
///
/// Each test simulates a restart by creating a new service instance
/// with the same storage backend and verifying data survives.
use std::collections::HashMap;
use std::sync::Arc;

use agent_core::traits::StorageProvider;
use anoncreds_core::types::*;
use anoncreds_core::{
    AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService, InMemoryRegistry,
    StorageBackedAnonCredsStore,
};
use storage::memory::MemoryStorage;

/// Helper: create a StorageBackedAnonCredsStore from a shared MemoryStorage
fn make_store(storage: &Arc<MemoryStorage>) -> Arc<StorageBackedAnonCredsStore> {
    Arc::new(StorageBackedAnonCredsStore::new(
        storage.clone() as Arc<dyn StorageProvider>
    ))
}

#[tokio::test]
async fn test_link_secret_persistence() {
    let storage = Arc::new(MemoryStorage::new());
    let registry = Arc::new(InMemoryRegistry::new());

    // First session: create link secret
    {
        let store = make_store(&storage);
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);
        holder.ensure_link_secret().await.unwrap();
    }

    // Second session (simulated restart): link secret should load from storage
    {
        let store = make_store(&storage);
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);
        // Should not fail — link secret loads from storage
        holder.ensure_link_secret().await.unwrap();
    }
}

#[tokio::test]
async fn test_credential_persistence() {
    let storage = Arc::new(MemoryStorage::new());
    let registry = Arc::new(InMemoryRegistry::new());

    let credential_id;

    // First session: issue and store a credential
    {
        let store = make_store(&storage);
        let issuer = AnonCredsIssuerService::new_with_store(registry.clone(), store.clone());
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);

        let schema_reg = issuer
            .create_schema(
                "did:example:issuer",
                "PersistenceTestSchema",
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

        let thread_id = "persist-thread-1";
        let cred_request = holder
            .create_credential_request(
                thread_id,
                &cred_offer,
                &cred_def_reg.cred_def_id,
                "holder-entropy-persist",
            )
            .await
            .unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), "Alice".to_string());
        attrs.insert("age".to_string(), "30".to_string());

        let mut credential = issuer
            .create_credential(&cred_def_reg.cred_def_id, &cred_offer, &cred_request, attrs)
            .await
            .unwrap();

        credential_id = holder
            .process_credential(thread_id, &mut credential, &cred_def_reg.cred_def_id)
            .await
            .unwrap();
    }

    // Second session: credential should load from storage
    {
        let store = make_store(&storage);
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);

        let attrs = holder
            .get_credential_attributes(&credential_id)
            .await
            .unwrap();
        assert_eq!(attrs.get("name").unwrap(), "Alice");
        assert_eq!(attrs.get("age").unwrap(), "30");

        let all_creds = holder.list_credentials().await.unwrap();
        assert_eq!(all_creds.len(), 1);
        assert_eq!(all_creds[0].0, credential_id);
    }
}

#[tokio::test]
async fn test_issuer_private_key_persistence() {
    let storage = Arc::new(MemoryStorage::new());
    let registry = Arc::new(InMemoryRegistry::new());

    let schema_id;
    let cred_def_id;

    // First session: create schema + cred def (stores private keys)
    {
        let store = make_store(&storage);
        let issuer = AnonCredsIssuerService::new_with_store(registry.clone(), store);

        let schema_reg = issuer
            .create_schema(
                "did:example:issuer",
                "KeyPersistSchema",
                "1.0",
                vec!["field1".to_string()],
            )
            .await
            .unwrap();
        schema_id = schema_reg.schema_id;

        let cred_def_reg = issuer
            .create_credential_definition("did:example:issuer", &schema_id, "default", false)
            .await
            .unwrap();
        cred_def_id = cred_def_reg.cred_def_id;
    }

    // Second session: issuer should be able to create offers and issue credentials
    // using the private keys loaded from storage
    {
        let store = make_store(&storage);
        let issuer = AnonCredsIssuerService::new_with_store(registry.clone(), store.clone());
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);

        // create_credential_offer needs the key correctness proof from storage
        let cred_offer = issuer
            .create_credential_offer(&schema_id, &cred_def_id)
            .await
            .unwrap();

        let thread_id = "persist-key-thread";
        let cred_request = holder
            .create_credential_request(thread_id, &cred_offer, &cred_def_id, "holder-entropy-key")
            .await
            .unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("field1".to_string(), "value1".to_string());

        // create_credential needs the cred def private key from storage
        let credential = issuer
            .create_credential(&cred_def_id, &cred_offer, &cred_request, attrs)
            .await;

        assert!(
            credential.is_ok(),
            "Should issue credential with persisted private keys"
        );
    }
}

#[tokio::test]
async fn test_full_flow_with_persistence_restart() {
    let storage = Arc::new(MemoryStorage::new());
    let registry = Arc::new(InMemoryRegistry::new());

    let schema_id;
    let cred_def_id;
    let credential_id;

    // Session 1: Setup schema + cred def + issue credential
    {
        let store = make_store(&storage);
        let issuer = AnonCredsIssuerService::new_with_store(registry.clone(), store.clone());
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);

        let schema_reg = issuer
            .create_schema(
                "did:example:issuer",
                "FullFlowSchema",
                "1.0",
                vec!["name".to_string(), "age".to_string()],
            )
            .await
            .unwrap();
        schema_id = schema_reg.schema_id;

        let cred_def_reg = issuer
            .create_credential_definition("did:example:issuer", &schema_id, "default", false)
            .await
            .unwrap();
        cred_def_id = cred_def_reg.cred_def_id;

        let cred_offer = issuer
            .create_credential_offer(&schema_id, &cred_def_id)
            .await
            .unwrap();
        let thread_id = "full-flow-thread";
        let cred_request = holder
            .create_credential_request(thread_id, &cred_offer, &cred_def_id, "entropy-full")
            .await
            .unwrap();

        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), "Bob".to_string());
        attrs.insert("age".to_string(), "25".to_string());

        let mut credential = issuer
            .create_credential(&cred_def_id, &cred_offer, &cred_request, attrs)
            .await
            .unwrap();

        credential_id = holder
            .process_credential(thread_id, &mut credential, &cred_def_id)
            .await
            .unwrap();
    }

    // Session 2: Verify holder can present and verifier can verify
    {
        let store = make_store(&storage);
        let holder = AnonCredsHolderService::new_with_store(registry.clone(), store);
        let verifier = AnonCredsVerifierService::new(registry.clone());

        // Verify credential survived restart
        let attrs = holder
            .get_credential_attributes(&credential_id)
            .await
            .unwrap();
        assert_eq!(attrs.get("name").unwrap(), "Bob");

        // Create proof request
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

        let pres_request = AnonCredsVerifierService::create_presentation_request(
            "restart-proof",
            "1.0",
            requested_attributes,
            HashMap::new(),
        )
        .unwrap();

        // Find matching credentials (loaded from storage)
        let matching = holder
            .find_credentials_for_request(&pres_request)
            .await
            .unwrap();
        assert!(matching
            .get("attr1_referent")
            .unwrap()
            .contains(&credential_id));

        // Create presentation
        let mut credential_map = HashMap::new();
        credential_map.insert("attr1_referent".to_string(), (credential_id.clone(), true));

        let presentation = holder
            .create_presentation(&pres_request, &credential_map, None)
            .await
            .unwrap();

        // Verify
        let valid = verifier
            .verify_presentation(&presentation, &pres_request)
            .await
            .unwrap();
        assert!(valid, "Presentation should be valid after restart");

        let revealed = AnonCredsVerifierService::extract_revealed_attributes(&presentation);
        assert_eq!(revealed.get("attr1_referent").unwrap(), "Bob");
    }
}
