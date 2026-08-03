/// Context Loader for JSON-LD Documents
/// Handles loading and caching of JSON-LD contexts
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Pre-fetched, compile-time-embedded JSON-LD contexts.
///
/// Embedding these matters because:
///
/// 1. **Offline + mobile**: the wallet runs inside a sandboxed WebView
///    where HTTP fetches from the Rust side can be slow or fail on
///    constrained networks. Cached contexts mean
///    `JsonLdVcService::verify_credential` doesn't hang on the first
///    decode of an OpenBadges credential.
/// 2. **Determinism**: the context URLs serve a content type that
///    sometimes redirects (e.g. `https://w3id.org/security/data-integrity/v2`
///    302s to an HTML preview unless `Accept: application/ld+json` is
///    set). Pre-fetched copies dodge that whole class of breakage.
///
/// To refresh: re-run `curl -sL -H 'Accept: application/ld+json'` on
/// each context URL and overwrite the corresponding file in
/// `./contexts/`. The const definitions below pull them in unchanged.
///
/// OpenBadges v3 sample credentials reference all of these.
pub const OPENBADGES_V3P0_CANONICAL_CONTEXT: &str =
    include_str!("./contexts/openbadges-v3p0-canonical.json");
pub const OPENBADGES_V3P0_3_0_3_CONTEXT: &str =
    include_str!("./contexts/openbadges-v3p0-3.0.3.json");
pub const OPENBADGES_V3P0_EXTENSIONS_CONTEXT: &str =
    include_str!("./contexts/openbadges-v3p0-extensions.json");
pub const CREDENTIALS_V2_CONTEXT: &str = include_str!("./contexts/credentials-v2.json");
pub const DATA_INTEGRITY_V2_CONTEXT: &str = include_str!("./contexts/data-integrity-v2.json");
pub const MULTIKEY_V1_CONTEXT: &str = include_str!("./contexts/multikey-v1.json");
pub const UNDEFINED_TERMS_V2_CONTEXT: &str = include_str!("./contexts/undefined-terms-v2.json");

/// Default W3C Credentials v1 context
pub const CREDENTIALS_V1_CONTEXT: &str = r#"{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "credentialSubject": {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject"
        },
        "issuer": {
          "@id": "https://www.w3.org/2018/credentials#issuer"
        },
        "issuanceDate": {
          "@id": "https://www.w3.org/2018/credentials#issuanceDate",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "expirationDate": {
          "@id": "https://www.w3.org/2018/credentials#expirationDate",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@container": "@graph"
        }
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "verifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
          "@container": "@graph"
        },
        "holder": {
          "@id": "https://www.w3.org/2018/credentials#holder"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@container": "@graph"
        }
      }
    }
  }
}"#;

/// Ed25519 2020 cryptosuite context
pub const ED25519_2020_V1_CONTEXT: &str = r#"{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "@protected": true,

    "Ed25519VerificationKey2020": {
      "@id": "https://w3id.org/security#Ed25519VerificationKey2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "controller": {
          "@id": "https://w3id.org/security#controller"
        },
        "publicKeyMultibase": {
          "@id": "https://w3id.org/security#publicKeyMultibase"
        }
      }
    },

    "Ed25519Signature2020": {
      "@id": "https://w3id.org/security#Ed25519Signature2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authentication"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreement"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocation"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegation"
            }
          }
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}"#;

/// Ed25519 2018 cryptosuite context
pub const ED25519_2018_V1_CONTEXT: &str = r#"{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "@protected": true,

    "Ed25519VerificationKey2018": {
      "@id": "https://w3id.org/security#Ed25519VerificationKey2018",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "controller": {
          "@id": "https://w3id.org/security#controller"
        },
        "publicKeyBase58": {
          "@id": "https://w3id.org/security#publicKeyBase58"
        }
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}"#;

/// Context loader with caching support
pub struct ContextLoader {
    /// Cache of loaded contexts
    cache: Arc<RwLock<HashMap<String, Value>>>,
    /// HTTP client for fetching remote contexts
    http_client: Option<reqwest::Client>,
}

impl ContextLoader {
    /// Create a new context loader with default cached contexts.
    ///
    /// Pre-populates synchronously so the first `load_context` call
    /// can't race the cache-filling tokio::spawn (the prior shape).
    pub fn new() -> Self {
        let mut initial_cache: HashMap<String, Value> = HashMap::new();

        initial_cache.insert(
            "https://www.w3.org/2018/credentials/v1".to_string(),
            serde_json::from_str(CREDENTIALS_V1_CONTEXT).unwrap(),
        );

        initial_cache.insert(
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            serde_json::from_str(ED25519_2020_V1_CONTEXT).unwrap(),
        );

        initial_cache.insert(
            "https://w3id.org/security/suites/ed25519-2018/v1".to_string(),
            serde_json::from_str(ED25519_2018_V1_CONTEXT).unwrap(),
        );

        // VC Data Model v2 — replaces a previous stub that only
        // exposed `id`/`type`; the real context has the full term
        // definitions OpenBadges v3 (and EBSI, DCC, etc.) rely on.
        initial_cache.insert(
            "https://www.w3.org/ns/credentials/v2".to_string(),
            serde_json::from_str(CREDENTIALS_V2_CONTEXT)
                .expect("embedded credentials-v2 context is valid JSON"),
        );

        // OpenBadges v3p0. The URL `…/context.json` and the
        // versioned `…/context-3.0.3.json` are both valid pointers
        // to the same content (3.0.3 is the latest 3.0 patch from
        // IMS) — sample credentials pick one or the other.
        // Cache both URLs against the per-version file.
        for url in [
            "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.json",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ] {
            initial_cache.insert(
                url.to_string(),
                serde_json::from_str(OPENBADGES_V3P0_3_0_3_CONTEXT)
                    .expect("embedded openbadges-v3p0 3.0.3 context is valid JSON"),
            );
        }
        // The canonical (unversioned) IMS context ships a slightly
        // different shape — keep it under its own URL for completeness.
        initial_cache.insert(
            "https://purl.imsglobal.org/spec/ob/v3p0/context-canonical.json".to_string(),
            serde_json::from_str(OPENBADGES_V3P0_CANONICAL_CONTEXT)
                .expect("embedded openbadges-v3p0 canonical context is valid JSON"),
        );
        initial_cache.insert(
            "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json".to_string(),
            serde_json::from_str(OPENBADGES_V3P0_EXTENSIONS_CONTEXT)
                .expect("embedded openbadges-v3p0 extensions context is valid JSON"),
        );

        // Data Integrity v2 + Multikey v1 — required by any
        // credential signed with `DataIntegrityProof` (the modern
        // default for ldp_vc issuance).
        for url in [
            "https://w3id.org/security/data-integrity/v2",
            "https://www.w3.org/ns/credentials/data-integrity/v2",
        ] {
            initial_cache.insert(
                url.to_string(),
                serde_json::from_str(DATA_INTEGRITY_V2_CONTEXT)
                    .expect("embedded data-integrity-v2 context is valid JSON"),
            );
        }
        initial_cache.insert(
            "https://w3id.org/security/multikey/v1".to_string(),
            serde_json::from_str(MULTIKEY_V1_CONTEXT)
                .expect("embedded multikey-v1 context is valid JSON"),
        );

        // The VC v2 "undefined-terms" alias is referenced by some
        // wallets and EBSI conformance fixtures.
        initial_cache.insert(
            "https://www.w3.org/ns/credentials/undefined-terms/v2".to_string(),
            serde_json::from_str(UNDEFINED_TERMS_V2_CONTEXT)
                .unwrap_or_else(|_| json!({"@context": {}})),
        );

        Self {
            cache: Arc::new(RwLock::new(initial_cache)),
            http_client: Some(reqwest::Client::new()),
        }
    }

    /// Create context loader without HTTP client (offline mode)
    pub fn offline() -> Self {
        let mut loader = Self::new();
        loader.http_client = None;
        loader
    }

    /// Load a context by URL
    pub async fn load_context(
        &self,
        url: &str,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(context) = cache.get(url) {
                return Ok(context.clone());
            }
        }

        // If not in cache and we have HTTP client, try to fetch
        if let Some(client) = &self.http_client {
            let response = client
                .get(url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await?;

            let context: Value = response.json().await?;

            // Cache the fetched context
            {
                let mut cache = self.cache.write().await;
                cache.insert(url.to_string(), context.clone());
            }

            Ok(context)
        } else {
            Err(format!(
                "Context not found in cache and offline mode enabled: {}",
                url
            )
            .into())
        }
    }

    /// Add a context to the cache
    pub async fn add_context(&self, url: String, context: Value) {
        let mut cache = self.cache.write().await;
        cache.insert(url, context);
    }

    /// Clear the context cache (except pre-loaded contexts)
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;

        // Keep only the pre-loaded contexts
        let mut new_cache = HashMap::new();

        if let Some(ctx) = cache.get("https://www.w3.org/2018/credentials/v1") {
            new_cache.insert(
                "https://www.w3.org/2018/credentials/v1".to_string(),
                ctx.clone(),
            );
        }
        if let Some(ctx) = cache.get("https://w3id.org/security/suites/ed25519-2020/v1") {
            new_cache.insert(
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
                ctx.clone(),
            );
        }
        if let Some(ctx) = cache.get("https://w3id.org/security/suites/ed25519-2018/v1") {
            new_cache.insert(
                "https://w3id.org/security/suites/ed25519-2018/v1".to_string(),
                ctx.clone(),
            );
        }

        *cache = new_cache;
    }
}

impl Default for ContextLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_cached_context() {
        let loader = ContextLoader::offline();

        // Give time for the spawn task to populate cache
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let context = loader
            .load_context("https://www.w3.org/2018/credentials/v1")
            .await
            .unwrap();
        assert!(context.is_object());
        assert!(context.get("@context").is_some());
    }

    #[tokio::test]
    async fn test_add_custom_context() {
        let loader = ContextLoader::offline();

        let custom_context = json!({
            "@context": {
                "custom": "https://example.com/custom#"
            }
        });

        loader
            .add_context(
                "https://example.com/custom".to_string(),
                custom_context.clone(),
            )
            .await;

        let loaded = loader
            .load_context("https://example.com/custom")
            .await
            .unwrap();
        assert_eq!(loaded, custom_context);
    }
}
