//! Live end-to-end AnonCreds flow anchored on the real Kanon Besu chain.
//!
//! Skipped unless `KANON_LIVE=1`. Requires (from digicred deploy/.env):
//!   KANON_RPC_URL, KANON_ADDRESS_BOOK, KANON_ORG_ID, KANON_OPERATOR_KEY
//!
//! Run: `KANON_LIVE=1 <env> cargo test -p registry_kanon --features besu \
//!        --test live_kanon -- --nocapture`
#![cfg(feature = "besu")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agent_core::traits::{Query, Record, StorageProvider};
use anoncreds_core::registry::AnonCredsRegistry;
use anoncreds_core::types::AttributeInfo;
use anoncreds_core::{AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService};
use registry_kanon::chain_alloy::AlloyKanonChain;
use registry_kanon::{KanonConfig, KanonRegistry};

// Minimal in-memory StorageProvider for the Layer-2 sidecar.
#[derive(Default)]
struct MemStore(std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>);

#[async_trait::async_trait]
impl StorageProvider for MemStore {
    async fn save(&self, r: &Record) -> agent_core::Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert((r.category.clone(), r.name.clone()), r.value.clone());
        Ok(())
    }
    async fn find(&self, category: &str, name: &str) -> agent_core::Result<Option<Record>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(category.to_string(), name.to_string()))
            .map(|v| Record::new(category, name, v.clone())))
    }
    async fn find_all(&self, _c: &str, _q: &Query) -> agent_core::Result<Vec<Record>> {
        Ok(vec![])
    }
    async fn update(&self, r: &Record) -> agent_core::Result<()> {
        self.save(r).await
    }
    async fn delete(&self, category: &str, name: &str) -> agent_core::Result<()> {
        self.0
            .lock()
            .unwrap()
            .remove(&(category.to_string(), name.to_string()));
        Ok(())
    }
    async fn delete_all(&self, _c: &str) -> agent_core::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn live_anoncreds_flow_on_besu() {
    if std::env::var("KANON_LIVE").ok().as_deref() != Some("1") {
        eprintln!("skipping live_anoncreds_flow_on_besu (set KANON_LIVE=1 to run)");
        return;
    }

    let rpc = std::env::var("KANON_RPC_URL").unwrap_or_else(|_| "https://besu.essi.studio".into());
    let org_hex = std::env::var("KANON_ORG_ID").expect("KANON_ORG_ID");
    let key = std::env::var("KANON_OPERATOR_KEY").expect("KANON_OPERATOR_KEY");
    let issuer_did = format!("did:kanon:org:{org_hex}");

    let mut config = KanonConfig::besu_readonly(&rpc)
        .with_issuer(&issuer_did)
        .with_operator_key(&key);
    if let Ok(book) = std::env::var("KANON_ADDRESS_BOOK") {
        config.address_book = book;
    }

    let chain = Arc::new(
        AlloyKanonChain::connect(&config)
            .await
            .expect("connect to Besu"),
    );
    println!("connected; registries: {:?}", chain.addresses());
    println!("operator: {:?}", chain.signer_address());

    let registry: Arc<dyn AnonCredsRegistry> = Arc::new(KanonRegistry::new(
        chain,
        Arc::new(MemStore::default()),
        config,
    ));
    let issuer = AnonCredsIssuerService::new(registry.clone());
    let holder = AnonCredsHolderService::new(registry.clone());
    let verifier = AnonCredsVerifierService::new(registry.clone());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. schema -> on-chain
    let schema = issuer
        .create_schema(
            &issuer_did,
            &format!("essi_e2e_{ts}"),
            "1.0",
            vec!["name".into(), "age".into()],
        )
        .await
        .expect("create_schema (on-chain)");
    println!("schema: {}", schema.schema_id);

    // 2. cred-def -> on-chain (CL key stored as data: URI)
    let cred_def = issuer
        .create_credential_definition(&issuer_did, &schema.schema_id, "default", false)
        .await
        .expect("create_credential_definition (on-chain)");
    println!("cred_def: {}", cred_def.cred_def_id);

    // Resolve both back from the chain.
    registry
        .get_schema(&schema.schema_id)
        .await
        .expect("get_schema on-chain");
    registry
        .get_credential_definition(&cred_def.cred_def_id)
        .await
        .expect("get_credential_definition on-chain");
    println!("resolved schema + cred-def from chain OK");

    // 3-6. offer -> request -> issue -> store
    let offer = issuer
        .create_credential_offer(&schema.schema_id, &cred_def.cred_def_id)
        .await
        .unwrap();
    let thread_id = "kanon-live-thread";
    let request = holder
        .create_credential_request(thread_id, &offer, &cred_def.cred_def_id, "entropy-live")
        .await
        .unwrap();
    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), "Alice".to_string());
    attrs.insert("age".to_string(), "30".to_string());
    let mut credential = issuer
        .create_credential(&cred_def.cred_def_id, &offer, &request, attrs)
        .await
        .unwrap();
    let credential_id = holder
        .process_credential(thread_id, &mut credential, &cred_def.cred_def_id)
        .await
        .unwrap();

    // 7-10. proof request -> present -> verify (schema+cred-def resolved from chain)
    let mut requested = HashMap::new();
    requested.insert(
        "attr1_referent".to_string(),
        AttributeInfo {
            name: Some("name".to_string()),
            names: None,
            restrictions: None,
            non_revoked: None,
        },
    );
    let pres_request = AnonCredsVerifierService::create_presentation_request(
        "kanon-live-proof",
        "1.0",
        requested,
        HashMap::new(),
    )
    .unwrap();
    let mut cred_map = HashMap::new();
    cred_map.insert("attr1_referent".to_string(), (credential_id.clone(), true));
    let presentation = holder
        .create_presentation(&pres_request, &cred_map, None)
        .await
        .unwrap();

    let valid = verifier
        .verify_presentation(&presentation, &pres_request)
        .await
        .expect("verify");
    assert!(valid, "live AnonCreds presentation should verify");
    let revealed = AnonCredsVerifierService::extract_revealed_attributes(&presentation);
    assert_eq!(revealed.get("attr1_referent").unwrap(), "Alice");
    println!("LIVE AnonCreds flow verified on Besu — revealed name = Alice");
}
