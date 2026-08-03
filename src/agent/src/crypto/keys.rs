//! Key extraction utilities for DIDs
//!
//! Provides functions to extract keys from DID documents and find corresponding
//! wallet keys for cryptographic operations.

use crate::error::{AgentError, Result};
use agent_core::traits::WalletProvider;
use did::core::DidRepository;
use didcomm::messaging::DidCommDocumentService;
use std::sync::Arc;

/// Key extraction utilities
pub struct KeyExtractor {
    did_document_service: Arc<DidCommDocumentService>,
    wallet_provider: Arc<dyn WalletProvider>,
    did_repository: Option<Arc<DidRepository>>,
}

impl KeyExtractor {
    /// Create a new KeyExtractor
    pub fn new(
        did_document_service: Arc<DidCommDocumentService>,
        wallet_provider: Arc<dyn WalletProvider>,
    ) -> Self {
        Self {
            did_document_service,
            wallet_provider,
            did_repository: None,
        }
    }

    /// Create a new KeyExtractor with DID repository
    pub fn with_did_repository(
        did_document_service: Arc<DidCommDocumentService>,
        wallet_provider: Arc<dyn WalletProvider>,
        did_repository: Arc<DidRepository>,
    ) -> Self {
        Self {
            did_document_service,
            wallet_provider,
            did_repository: Some(did_repository),
        }
    }

    /// Extract base58-encoded Ed25519 verification public key from a did:key DID
    ///
    /// This extracts the Ed25519 SIGNING key (the first verification method).
    /// Used for finding keys in the wallet (wallet stores Ed25519 keys).
    ///
    /// **DO NOT use this for encryption** - use `extract_key_agreement_from_did()` instead!
    pub async fn extract_public_key_from_did(&self, did: &str) -> Result<String> {
        // DIAG: log what authentication key the resolver returned for this DID.
        // Cross-reference with mediator's `to=…` to spot mis-routing.
        let result = self
            .did_document_service
            .extract_authentication_key(did)
            .await
            .map_err(|e| AgentError::Did(format!("{}", e)));
        match &result {
            Ok(k) => tracing::debug!(target: "didcomm.diag", %did, key = %k, "extract_auth_key"),
            Err(e) => {
                tracing::debug!(target: "didcomm.diag", %did, error = %e, "extract_auth_key FAILED")
            }
        }
        result
    }

    /// Extract base58-encoded X25519 keyAgreement public key from a did:key DID
    ///
    /// For encryption, we need the X25519 keyAgreement key, NOT the Ed25519 signing key.
    /// This function:
    /// 1. Looks at the keyAgreement array in the DID document
    /// 2. Finds the referenced verification method
    /// 3. Extracts the X25519 public key
    ///
    /// **This is the correct key for ENCRYPTION!**
    pub async fn extract_key_agreement_from_did(&self, did: &str) -> Result<String> {
        self.did_document_service
            .extract_key_agreement_key(did)
            .await
            .map_err(|e| AgentError::Did(format!("{}", e)))
    }

    /// Find the wallet key ID for a given DID
    ///
    /// This function:
    /// 1. First checks DidRepository for stored DID records (for did:peer, etc.)
    /// 2. Falls back to extracting public key and searching wallet
    pub async fn find_key_for_did(&self, did: &str) -> Result<String> {
        // First, try to find the key in DidRepository (for did:peer and other created DIDs)
        if let Some(did_repo) = &self.did_repository {
            if let Some(did_record) = did_repo.find_by_did(did) {
                // Found a DID record - extract the first key
                if let Some(first_key) = did_record.keys.first() {
                    return Ok(first_key.kms_key_id.clone());
                }
            }
        }

        // Fall back to the original method: extract public key and search wallet
        // This is still needed for did:key DIDs that may not be in DidRepository

        // Extract the public key from the DID
        let public_key_base58 = self.extract_public_key_from_did(did).await?;
        let public_key_bytes = bs58::decode(&public_key_base58)
            .into_vec()
            .map_err(|e| AgentError::Did(format!("Failed to decode base58: {}", e)))?;

        // List all keys in the wallet and find matching public key
        let keys = self
            .wallet_provider
            .list_keys()
            .await
            .map_err(|e| AgentError::Wallet(format!("Failed to list keys: {}", e)))?;

        for key in keys {
            if key.public_key == public_key_bytes
                && key.key_type == agent_core::traits::KeyType::Ed25519
            {
                return Ok(key.id);
            }
        }

        Err(AgentError::Wallet(format!(
            "No wallet key found for DID: {}",
            did
        )))
    }
}

#[cfg(test)]
mod tests {

    // Tests will be added when we have mock implementations
    // For now, the functions are tested through integration tests
}
