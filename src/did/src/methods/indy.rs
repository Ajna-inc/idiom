//! did:indy Method Implementation
//!
//! Parses did:indy identifiers per [did-indy](https://hyperledger.github.io/indy-did-method/)
//! and delegates the actual ledger lookup to a pluggable `IndyLedgerClient`.
//! This lets callers wire in an `indy-vdr` pool, the Universal Resolver, or
//! a mock — the resolver doesn't make assumptions about transport.
//!
//! # Format
//! did:indy:{network}:{namespace-specific-id}
//! - network: e.g. `sovrin`, `sovrin:staging`, `idunion`, `bcovrin`
//! - namespace-specific-id: 21-22 character base58btc Indy NYM
//!
//! # Examples
//! - `did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg`
//! - `did:indy:sovrin:staging:6cgbu8ZPoWTnR5Rv5JcSMB`

use async_trait::async_trait;
use std::sync::Arc;

use crate::core::{DidDocument, DidResolver, ResolutionError, ResolutionResult, DID};

/// Pluggable Indy ledger client. Implementations call a real `indy-vdr`
/// pool, the Universal Resolver gateway, or a test mock.
#[async_trait]
pub trait IndyLedgerClient: Send + Sync {
    /// Fetch the NYM (transaction containing the verkey + role) for `did`
    /// from the named Indy network. The returned DidDocument should follow
    /// the did-indy method for translating NYM → DID document.
    async fn resolve_nym(&self, network: &str, did: &str) -> Result<DidDocument, ResolutionError>;
}

/// did:indy Resolver — parses identifiers and dispatches to a ledger client.
pub struct IndyDidResolver {
    ledger: Arc<dyn IndyLedgerClient>,
}

impl IndyDidResolver {
    pub fn new(ledger: Arc<dyn IndyLedgerClient>) -> Self {
        Self { ledger }
    }

    /// Split a did:indy identifier into `(network, nym)`. The network can
    /// be a single segment (`sovrin`) or two segments
    /// (`sovrin:staging`) — the NYM is always the last component.
    fn parse(did: &DID) -> Result<(String, String), ResolutionError> {
        if did.method() != "indy" {
            return Err(ResolutionError::InvalidDid(format!(
                "expected indy method, got {}",
                did.method()
            )));
        }
        let id = did.method_specific_id();
        let segments: Vec<&str> = id.split(':').collect();
        if segments.len() < 2 {
            return Err(ResolutionError::InvalidDid(
                "did:indy must be network:nym".into(),
            ));
        }
        let nym = segments.last().unwrap().to_string();
        if nym.is_empty() {
            return Err(ResolutionError::InvalidDid("empty did:indy NYM".into()));
        }
        // Indy NYMs are 21–22 base58 chars (decoded length 16 bytes). Quick
        // sanity check — callers may use longer custom NYMs so we don't
        // enforce a strict upper bound.
        if nym.len() < 16 || nym.len() > 64 {
            return Err(ResolutionError::InvalidDid(format!(
                "did:indy NYM length {} outside expected range 16–64",
                nym.len()
            )));
        }
        let network = segments[..segments.len() - 1].join(":");
        Ok((network, nym))
    }
}

#[async_trait]
impl DidResolver for IndyDidResolver {
    fn method_name(&self) -> &str {
        "indy"
    }

    fn allows_caching(&self) -> bool {
        // Indy DID documents change when NYM transactions are written, but
        // those are infrequent — caching with a short TTL is the usual
        // pattern (TTL enforcement is left to the caller).
        true
    }

    async fn resolve(&self, did: &DID) -> ResolutionResult<DidDocument> {
        let (network, nym) = Self::parse(did)?;
        self.ledger.resolve_nym(&network, &nym).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Records the network + NYM it's been asked about and returns a
    /// minimal stub DidDocument so the dispatcher logic can be exercised
    /// without an actual ledger.
    struct RecordingClient {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl IndyLedgerClient for RecordingClient {
        async fn resolve_nym(
            &self,
            network: &str,
            did: &str,
        ) -> Result<DidDocument, ResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Minimal DID document so tests can assert resolution succeeded.
            Ok(DidDocument::new(format!("did:indy:{}:{}", network, did)))
        }
    }

    #[test]
    fn parse_single_segment_network() {
        let did = DID::parse("did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg").unwrap();
        let (network, nym) = IndyDidResolver::parse(&did).unwrap();
        assert_eq!(network, "sovrin");
        assert_eq!(nym, "7Tqg6BwSSWapxgUDm9KKgg");
    }

    #[test]
    fn parse_compound_network() {
        let did = DID::parse("did:indy:sovrin:staging:6cgbu8ZPoWTnR5Rv5JcSMB").unwrap();
        let (network, nym) = IndyDidResolver::parse(&did).unwrap();
        assert_eq!(network, "sovrin:staging");
        assert_eq!(nym, "6cgbu8ZPoWTnR5Rv5JcSMB");
    }

    #[test]
    fn parse_rejects_missing_network() {
        let did = DID::parse("did:indy:7Tqg6BwSSWapxgUDm9KKgg").unwrap();
        // Single segment after `did:indy:` parses as a network-only identifier
        // with no NYM — must be rejected.
        let result = IndyDidResolver::parse(&did);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rejects_non_indy_method() {
        let did = DID::parse("did:key:z6MkpTHR8...").unwrap();
        assert!(IndyDidResolver::parse(&did).is_err());
    }

    #[tokio::test]
    async fn resolver_dispatches_to_ledger_client() {
        let client = Arc::new(RecordingClient {
            calls: AtomicUsize::new(0),
        });
        let resolver = IndyDidResolver::new(client.clone());
        let did = DID::parse("did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg").unwrap();
        let doc = resolver.resolve(&did).await.unwrap();
        assert!(doc.id.contains("did:indy:sovrin:7Tqg6BwSSWapxgUDm9KKgg"));
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn method_name_is_indy() {
        let client = Arc::new(RecordingClient {
            calls: AtomicUsize::new(0),
        });
        let r = IndyDidResolver::new(client);
        assert_eq!(r.method_name(), "indy");
    }
}
