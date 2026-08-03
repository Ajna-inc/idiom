//! # registry_kanon
//!
//! A did:kanon AnonCreds registry for essi-rs. Implements
//! [`anoncreds_core::AnonCredsRegistry`] over the Kanon Besu contracts
//! (chain 1947), porting the reference `aca-py-did-kanon` plugin so essi-rs
//! can resolve and publish the same on-chain schemas, credential definitions,
//! and revocation status that DigiCred's existing credentials are anchored to.
//!
//! ## Injection
//!
//! [`KanonRegistry`] drops straight into the AnonCreds module — no changes to
//! the issuer/holder/verifier or credential/proof exchange services:
//!
//! ```ignore
//! let chain = Arc::new(AlloyKanonChain::connect(&config).await?); // feature "besu"
//! let kanon = Arc::new(KanonRegistry::new(chain, storage.clone(), config));
//! let anoncreds = AnonCredsModule::with_registry_and_storage(cfg, kanon, storage);
//! ```
//!
//! ## Running many registries at once
//!
//! [`MultiRegistry`] composes several registries (did:kanon + did:web +
//! did:ajna + in-memory), dispatching by `supports_identifier` — it is itself
//! an `AnonCredsRegistry`, so it injects the same way.
//!
//! ## Two-layer persistence
//!
//! - **Layer 1 (authoritative, shared):** the Besu chain via [`chain::KanonChain`].
//!   Schemas/cred-defs as `data:` URIs + keccak anchors; per-credential
//!   revocation in `AnonCredsStatusRegistry` / `MerkleStateRegistry`.
//! - **Layer 2 (local sidecar):** [`state::KanonState`] over the wallet's
//!   `StorageProvider` — rev-reg metadata, `cred_rev_id -> kanon_cred_id`
//!   index, and body caches the chain doesn't hold.

pub mod babyjub;
pub mod blake512;
pub mod chain;
pub mod config;
pub mod eddsa;
pub mod encoding;
pub mod error;
pub mod ids;
pub mod leaf;
pub mod merkle;
pub mod multi;
pub mod poseidon;
pub mod registry;
pub mod state;
pub mod zk;

#[cfg(feature = "besu")]
pub mod chain_alloy;
#[cfg(feature = "besu")]
pub use chain_alloy::AlloyKanonChain;

pub use chain::KanonChain;
pub use config::{KanonConfig, TIER_ALL, TIER_ONE_TIME, TIER_ZK_SNARK};
pub use error::{KanonError, Result};
pub use multi::MultiRegistry;
pub use registry::KanonRegistry;
pub use zk::{ActiveLeaf, ModeBPrep, NoZk, PoseidonZk, RevokeRoots, ZkProvisioner};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mock::MockKanonChain;
    use anoncreds_core::registry::AnonCredsRegistry;
    use anoncreds_core::InMemoryRegistry;
    use std::sync::Arc;

    // Minimal in-memory StorageProvider for the sidecar in tests.
    #[derive(Default)]
    struct MemStore(std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>);

    #[async_trait::async_trait]
    impl agent_core::traits::StorageProvider for MemStore {
        async fn save(&self, r: &agent_core::traits::Record) -> agent_core::error::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert((r.category.clone(), r.name.clone()), r.value.clone());
            Ok(())
        }
        async fn find(
            &self,
            category: &str,
            name: &str,
        ) -> agent_core::error::Result<Option<agent_core::traits::Record>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(category.to_string(), name.to_string()))
                .map(|v| agent_core::traits::Record::new(category, name, v.clone())))
        }
        async fn find_all(
            &self,
            _category: &str,
            _query: &agent_core::traits::Query,
        ) -> agent_core::error::Result<Vec<agent_core::traits::Record>> {
            Ok(vec![])
        }
        async fn update(&self, r: &agent_core::traits::Record) -> agent_core::error::Result<()> {
            self.save(r).await
        }
        async fn delete(&self, category: &str, name: &str) -> agent_core::error::Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(&(category.to_string(), name.to_string()));
            Ok(())
        }
        async fn delete_all(&self, _category: &str) -> agent_core::error::Result<()> {
            Ok(())
        }
    }

    const ORG_DID: &str =
        "did:kanon:org:0xa479b0a8c0152ccb4f56efcdbca2d9790dc53f4e5475e5c205f769775c7c3a16";

    fn kanon() -> KanonRegistry {
        KanonRegistry::new(
            Arc::new(MockKanonChain::new()),
            Arc::new(MemStore::default()),
            KanonConfig::besu_readonly("http://localhost:8545").with_issuer(ORG_DID),
        )
    }

    #[tokio::test]
    async fn schema_round_trip() {
        let reg = kanon();
        let schema: anoncreds_core::types::Schema = serde_json::from_value(serde_json::json!({
            "issuerId": ORG_DID,
            "name": "Passport",
            "version": "1.0",
            "attrNames": ["givenName", "familyName", "dob"],
        }))
        .unwrap();

        let reg_result = reg.register_schema(ORG_DID, &schema).await.unwrap();
        assert_eq!(
            reg_result.schema_id,
            format!("{ORG_DID}/anoncreds/v0/SCHEMA/Passport/1.0")
        );

        let fetched = reg.get_schema(&reg_result.schema_id).await.unwrap();
        let v = serde_json::to_value(&fetched).unwrap();
        assert_eq!(v["name"], "Passport");
        assert_eq!(v["version"], "1.0");
    }

    #[tokio::test]
    async fn multi_registry_routes_by_method() {
        let reg = MultiRegistry::new()
            .with(Arc::new(kanon()))
            .with_default(Arc::new(InMemoryRegistry::new()));

        // did:kanon issuer routes to the Kanon registry.
        assert!(reg.supports_identifier(&format!("{ORG_DID}/anoncreds/v0/SCHEMA/Passport/1.0")));

        let schema: anoncreds_core::types::Schema = serde_json::from_value(serde_json::json!({
            "issuerId": ORG_DID,
            "name": "Membership",
            "version": "2.0",
            "attrNames": ["level"],
        }))
        .unwrap();
        let r = reg.register_schema(ORG_DID, &schema).await.unwrap();
        // Kanon-format id proves it routed to the Kanon registry, not the default.
        assert!(r.schema_id.contains("/anoncreds/v0/SCHEMA/Membership/2.0"));
    }

    /// Full AnonCreds issue -> verify flow with `KanonRegistry` as the VDR
    /// (schema + cred-def published to / resolved from the mock Kanon chain).
    /// Proves the CL crypto path works with Kanon-format identifiers.
    #[tokio::test]
    async fn full_anoncreds_flow_over_kanon() {
        use anoncreds_core::types::AttributeInfo;
        use anoncreds_core::{
            AnonCredsHolderService, AnonCredsIssuerService, AnonCredsVerifierService,
        };
        use std::collections::HashMap;

        let registry: Arc<dyn AnonCredsRegistry> = Arc::new(KanonRegistry::new(
            Arc::new(MockKanonChain::new()),
            Arc::new(MemStore::default()),
            KanonConfig::besu_readonly("http://localhost:8545").with_issuer(ORG_DID),
        ));
        let issuer = AnonCredsIssuerService::new(registry.clone());
        let holder = AnonCredsHolderService::new(registry.clone());
        let verifier = AnonCredsVerifierService::new(registry.clone());

        // 1. schema + 2. cred-def -> published to Kanon
        let schema = issuer
            .create_schema(
                ORG_DID,
                "IdentityCredential",
                "1.0",
                vec!["name".into(), "age".into(), "country".into()],
            )
            .await
            .unwrap();
        assert!(schema.schema_id.starts_with(ORG_DID));
        assert!(schema.schema_id.contains("/anoncreds/v0/SCHEMA/"));

        let cred_def = issuer
            .create_credential_definition(ORG_DID, &schema.schema_id, "default", false)
            .await
            .unwrap();
        assert!(cred_def.cred_def_id.contains("/anoncreds/v0/CLAIM_DEF/"));

        // Resolve both back through the registry (i.e. off the mock chain).
        registry.get_schema(&schema.schema_id).await.unwrap();
        registry
            .get_credential_definition(&cred_def.cred_def_id)
            .await
            .unwrap();

        // 3-6. offer -> request -> issue -> store
        let offer = issuer
            .create_credential_offer(&schema.schema_id, &cred_def.cred_def_id)
            .await
            .unwrap();
        let thread_id = "kanon-thread-1";
        let request = holder
            .create_credential_request(thread_id, &offer, &cred_def.cred_def_id, "entropy-xyz")
            .await
            .unwrap();
        let mut attrs = HashMap::new();
        attrs.insert("name".to_string(), "Alice".to_string());
        attrs.insert("age".to_string(), "30".to_string());
        attrs.insert("country".to_string(), "US".to_string());
        let mut credential = issuer
            .create_credential(&cred_def.cred_def_id, &offer, &request, attrs)
            .await
            .unwrap();
        let credential_id = holder
            .process_credential(thread_id, &mut credential, &cred_def.cred_def_id)
            .await
            .unwrap();

        // 7-10. proof request -> present -> verify (resolves schema+cred-def from Kanon)
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
            "kanon-proof",
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
            .unwrap();
        assert!(valid, "AnonCreds presentation over Kanon should verify");

        let revealed = AnonCredsVerifierService::extract_revealed_attributes(&presentation);
        assert_eq!(revealed.get("attr1_referent").unwrap(), "Alice");
    }
}
