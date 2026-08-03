//! Mediator-based handle resolution — resolve `@handle` → DID document via the
//! mediator's identity directory, with **no blockchain validators required**.
//!
//! The Ajna mediator already serves a handle directory:
//!   - storage: `IdentityRegistry` (handle_hash → DID document)
//!   - lookup:  `GET /api/dids/by-handle/{handle_hash}` → `{ data: { document } }`
//!
//! This service implements [`BlockchainService::resolve_handle`] by calling that
//! endpoint, so it can be injected as the agent's `blockchain_service` and
//! `OutOfBandModule::connect_by_handle` works unchanged — but over the mediator
//! instead of the validator network. All other `BlockchainService` methods are
//! unsupported (this service only does handle resolution).
//!
//! `handle_hash` MUST match the mediator's `handle_index_key`, i.e.
//! `BLAKE3(handle.to_lowercase())` hex-encoded.

use agent_core::traits::blockchain::{
    AccountState, BlockchainError, BlockchainResult, BlockchainService, ConsensusStatus,
    DidRegistrationResult, FaucetResult, TransactionResult,
};
use async_trait::async_trait;

/// Resolves handles via the mediator's identity directory over HTTP.
pub struct MediatorIdentityService {
    /// Mediator base URL, e.g. `"https://mediator.ajna.dev"`.
    base_url: String,
    http: reqwest::Client,
}

impl MediatorIdentityService {
    pub fn new(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    /// `BLAKE3(handle.to_lowercase())` hex — must match the mediator's
    /// `identity_registry::handle_index_key` / `ajna_client::handle_crypto`.
    fn handle_hash_hex(handle: &str) -> String {
        hex::encode(blake3::hash(handle.to_lowercase().as_bytes()).as_bytes())
    }

    fn unsupported<T>(op: &str) -> BlockchainResult<T> {
        Err(BlockchainError(format!(
            "{} not supported by MediatorIdentityService (handle resolution only)",
            op
        )))
    }
}

#[async_trait]
impl BlockchainService for MediatorIdentityService {
    // --- Handle resolution: the one method this service actually provides ---
    async fn resolve_handle(&self, handle: &str) -> BlockchainResult<Option<serde_json::Value>> {
        let hash = Self::handle_hash_hex(handle);
        let url = format!(
            "{}/api/dids/by-handle/{}",
            self.base_url.trim_end_matches('/'),
            hash
        );
        tracing::debug!(handle = %handle, url = %url, "Resolving handle via mediator directory");

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BlockchainError(format!("mediator resolve request failed: {}", e)))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(BlockchainError(format!(
                "mediator resolve returned HTTP {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BlockchainError(format!("mediator resolve returned bad JSON: {}", e)))?;

        // Mediator response shape: { "data": { "document": <did_document> } }.
        let doc = body.get("data").and_then(|d| d.get("document")).cloned();
        Ok(doc)
    }

    // --- Everything else: not supported by a directory-only resolver ---
    async fn get_consensus_status(&self) -> BlockchainResult<ConsensusStatus> {
        Self::unsupported("get_consensus_status")
    }
    async fn get_balance(&self, _address: &str) -> BlockchainResult<String> {
        Self::unsupported("get_balance")
    }
    async fn get_nonce(&self, _address: &str) -> BlockchainResult<u64> {
        Self::unsupported("get_nonce")
    }
    async fn get_account(&self, _address: &str) -> BlockchainResult<AccountState> {
        Self::unsupported("get_account")
    }
    async fn get_latest_block_number(&self) -> BlockchainResult<u64> {
        Self::unsupported("get_latest_block_number")
    }
    async fn submit_transaction(&self, _tx_bytes: &[u8]) -> BlockchainResult<TransactionResult> {
        Self::unsupported("submit_transaction")
    }
    async fn request_faucet(&self, _recipient: &str) -> BlockchainResult<FaucetResult> {
        Self::unsupported("request_faucet")
    }
    async fn register_did(
        &self,
        _sid_sanskrit: &str,
        _vm_root: &str,
        _did_document: serde_json::Value,
    ) -> BlockchainResult<DidRegistrationResult> {
        Self::unsupported("register_did")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The canonical handle hash, computed the same way as
    /// `ajna_client::handle_crypto::handle_index_key` and the mediator's
    /// `identity_registry::handle_index_key` — BLAKE3(handle.to_lowercase()) hex.
    fn canonical_hex(handle: &str) -> String {
        hex::encode(blake3::hash(handle.to_lowercase().as_bytes()).as_bytes())
    }

    #[test]
    fn handle_hash_matches_canonical_and_is_case_insensitive() {
        // Same formula as the two canonical implementations.
        assert_eq!(
            MediatorIdentityService::handle_hash_hex("alice-karamada"),
            canonical_hex("alice-karamada")
        );
        // Case-insensitive — the mediator lowercases before hashing, so we must too,
        // otherwise a handle registered as "Alice" would never resolve from "alice".
        assert_eq!(
            MediatorIdentityService::handle_hash_hex("Alice-Karamada"),
            MediatorIdentityService::handle_hash_hex("alice-karamada")
        );
        // 32-byte BLAKE3 digest -> 64 hex chars.
        assert_eq!(MediatorIdentityService::handle_hash_hex("alice").len(), 64);
    }

    /// Faithful mock of the mediator's `GET /api/dids/by-handle/:handle_hash`
    /// (mediator_server/src/routes.rs:779). Hit -> 200 `{"data":{"document":..}}`,
    /// miss -> 404 — exactly what `resolve_handle` Some/None map to.
    async fn spawn_mediator_mock(found_hash: String, doc: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let found_hash = found_hash.clone();
                let doc = doc.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    // Request line: "GET /api/dids/by-handle/<hash> HTTP/1.1"
                    let path = req
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("");
                    let want = format!("/api/dids/by-handle/{}", found_hash);
                    let resp = if path == want {
                        let body = serde_json::json!({ "data": { "document": doc } }).to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn resolve_returns_seeded_document() {
        let doc = serde_json::json!({
            "id": "did:ajna:alice123",
            "service": [{
                "id": "#did-comm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://mediator.ajna.dev"
            }]
        });
        // Seed the directory under the canonical hash of "alice".
        let base = spawn_mediator_mock(canonical_hex("alice"), doc.clone()).await;
        let svc = MediatorIdentityService::new(base, reqwest::Client::new());

        let got = svc
            .resolve_handle("alice")
            .await
            .expect("resolve should succeed");
        assert_eq!(
            got,
            Some(doc),
            "resolve_handle must return the seeded DID document — proves hash + URL + JSON parse all agree with the mediator"
        );
    }

    #[tokio::test]
    async fn resolve_is_case_insensitive_against_directory() {
        let doc = serde_json::json!({ "id": "did:ajna:bob" });
        // Directory holds the lowercase-hashed entry...
        let base = spawn_mediator_mock(canonical_hex("bob-dharma"), doc.clone()).await;
        let svc = MediatorIdentityService::new(base, reqwest::Client::new());
        // ...and a mixed-case query still resolves it.
        let got = svc
            .resolve_handle("Bob-Dharma")
            .await
            .expect("resolve should succeed");
        assert_eq!(got, Some(doc));
    }

    #[tokio::test]
    async fn resolve_unknown_handle_returns_none() {
        // Server only knows "someone"; we ask for "nobody" -> 404 -> Ok(None).
        let base = spawn_mediator_mock(canonical_hex("someone"), serde_json::json!({})).await;
        let svc = MediatorIdentityService::new(base, reqwest::Client::new());
        let got = svc
            .resolve_handle("nobody")
            .await
            .expect("404 must map to Ok(None)");
        assert_eq!(got, None);
    }
}
