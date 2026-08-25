use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::core::{JwtSigner, KeyType as VcKeyType, SignatureAlgorithm, SigningKey};
use agent_core::traits::{KeyPurpose, KeyType as AgentKeyType, WalletProvider};
use did::registry::DidRegistry;

/// Convert between agent_core KeyType and vc_core KeyType
fn convert_key_type(agent_type: AgentKeyType) -> VcKeyType {
    match agent_type {
        AgentKeyType::Ed25519 => VcKeyType::Ed25519,
        AgentKeyType::EcdsaSecp256r1 => VcKeyType::P256,
        AgentKeyType::X25519 => VcKeyType::Ed25519, // X25519 not directly supported, use Ed25519
        AgentKeyType::Bls12381G1 => VcKeyType::Bls12381,
        AgentKeyType::Bls12381G2 => VcKeyType::Bls12381,
        AgentKeyType::P256 => VcKeyType::P256,
        AgentKeyType::SLHDSA => VcKeyType::Ed25519, // No VC equivalent, fallback
        AgentKeyType::MLDSA65 => VcKeyType::Ed25519, // No VC equivalent, fallback
    }
}

/// Convert vc_core KeyType to agent_core KeyType
fn convert_key_type_to_agent(vc_type: VcKeyType) -> AgentKeyType {
    match vc_type {
        VcKeyType::Ed25519 => AgentKeyType::Ed25519,
        VcKeyType::P256 => AgentKeyType::EcdsaSecp256r1,
        VcKeyType::P384 => AgentKeyType::EcdsaSecp256r1, // Use P256 for P384
        VcKeyType::P521 => AgentKeyType::EcdsaSecp256r1, // Use P256 for P521
        VcKeyType::Rsa2048 => AgentKeyType::Ed25519,     // RSA not supported, fallback
        VcKeyType::Rsa4096 => AgentKeyType::Ed25519,     // RSA not supported, fallback
        VcKeyType::Bls12381 => AgentKeyType::Bls12381G1,
    }
}

/// JWT signer that uses wallet_askar for cryptographic operations
pub struct WalletJwtSigner {
    wallet: Arc<dyn WalletProvider>,
    did_registry: Option<Arc<DidRegistry>>,
}

impl WalletJwtSigner {
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        Self {
            wallet,
            did_registry: None,
        }
    }

    pub fn with_did_registry(mut self, registry: Arc<DidRegistry>) -> Self {
        self.did_registry = Some(registry);
        self
    }

    /// Convert signature algorithm to JWT algorithm string
    fn algorithm_to_jwt_alg(algorithm: SignatureAlgorithm) -> &'static str {
        match algorithm {
            SignatureAlgorithm::EdDSA => "EdDSA",
            SignatureAlgorithm::ES256 => "ES256",
            SignatureAlgorithm::ES384 => "ES384",
            SignatureAlgorithm::ES512 => "ES512",
            SignatureAlgorithm::RS256 => "RS256",
            SignatureAlgorithm::RS384 => "RS384",
            SignatureAlgorithm::RS512 => "RS512",
            SignatureAlgorithm::PS256 => "PS256",
            SignatureAlgorithm::PS384 => "PS384",
            SignatureAlgorithm::PS512 => "PS512",
        }
    }

    /// Create JWT from header and payload
    async fn create_jwt(
        &self,
        header: &Value,
        payload: &Value,
        key_id: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Encode header and payload
        let encoded_header = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        // Create signing input
        let signing_input = format!("{}.{}", encoded_header, encoded_payload);

        // Sign with wallet
        let signature = self.wallet.sign(key_id, signing_input.as_bytes()).await?;

        // Encode signature
        let encoded_signature = URL_SAFE_NO_PAD.encode(&signature.bytes);

        // Combine into JWT
        Ok(format!("{}.{}", signing_input, encoded_signature))
    }

    /// Parse and verify JWT
    async fn parse_jwt(
        &self,
        jwt: &str,
        _public_key: &[u8],
    ) -> Result<(Value, Value), Box<dyn std::error::Error + Send + Sync>> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".into());
        }

        // Decode header and payload
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;

        let header: Value = serde_json::from_slice(&header_bytes)?;
        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or("Missing 'kid' in JWT header")?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or("Missing 'alg' in JWT header")?;
        let key = self
            .wallet
            .get_key(kid)
            .await?
            .ok_or_else(|| format!("Key not found: {kid}"))?;
        let expected_alg = match key.key_type {
            AgentKeyType::Ed25519 => "EdDSA",
            AgentKeyType::EcdsaSecp256r1 | AgentKeyType::P256 => "ES256",
            other => return Err(format!("Unsupported JWT verification key type: {other:?}").into()),
        };
        if alg != expected_alg {
            return Err(format!(
                "Algorithm mismatch: header has {alg}, key requires {expected_alg}"
            )
            .into());
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        if !self
            .wallet
            .verify(kid, signing_input.as_bytes(), &signature_bytes)
            .await?
        {
            return Err("Invalid JWT signature".into());
        }

        Ok((header, payload))
    }
}

#[async_trait]
impl JwtSigner for WalletJwtSigner {
    async fn sign_jwt(
        &self,
        header: &Value,
        payload: &Value,
        key: &SigningKey,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Validate algorithm in header matches key type
        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'alg' in JWT header")?;

        let expected_alg = match key.key_type {
            VcKeyType::Ed25519 => "EdDSA",
            VcKeyType::P256 => "ES256",
            _ => return Err(format!("Unsupported key type: {:?}", key.key_type).into()),
        };

        if alg != expected_alg {
            return Err(format!(
                "Algorithm mismatch: header has {}, key requires {}",
                alg, expected_alg
            )
            .into());
        }

        // Create JWT using wallet for signing
        self.create_jwt(header, payload, &key.id).await
    }

    async fn verify_jwt(
        &self,
        jwt: &str,
        public_key: &[u8],
    ) -> Result<(Value, Value), Box<dyn std::error::Error + Send + Sync>> {
        self.parse_jwt(jwt, public_key).await
    }
}

/// Enhanced JWT service with wallet integration
pub struct WalletBackedJwtVcService {
    wallet: Arc<dyn WalletProvider>,
    did_registry: Option<Arc<DidRegistry>>,
    signer: WalletJwtSigner,
}

impl WalletBackedJwtVcService {
    pub fn new(wallet: Arc<dyn WalletProvider>) -> Self {
        let signer = WalletJwtSigner::new(wallet.clone());
        Self {
            wallet,
            did_registry: None,
            signer,
        }
    }

    pub fn with_did_registry(mut self, registry: Arc<DidRegistry>) -> Self {
        self.did_registry = Some(registry.clone());
        self.signer = self.signer.with_did_registry(registry);
        self
    }

    /// Create or get a signing key for the given key ID
    pub async fn get_or_create_signing_key(
        &self,
        key_id: &str,
        key_type: VcKeyType,
    ) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
        let agent_key_type = convert_key_type_to_agent(key_type);

        // Try to get existing key
        if let Some(key) = self.wallet.get_key(key_id).await? {
            Ok(SigningKey {
                id: key.id.clone(),
                key_type: convert_key_type(key.key_type),
                controller: key_id.to_string(), // TODO: Extract controller from DID URL
                private_key: vec![],            // Not exposed
                public_key: key.public_key.clone(),
            })
        } else {
            // Create new key
            let key = self
                .wallet
                .create_key(agent_key_type, KeyPurpose::General)
                .await?;

            Ok(SigningKey {
                id: key.id.clone(),
                key_type: convert_key_type(key.key_type),
                controller: key_id.to_string(),
                private_key: vec![], // Not exposed
                public_key: key.public_key.clone(),
            })
        }
    }

    /// Sign JWT with wallet
    pub async fn sign_jwt(
        &self,
        header: &Value,
        payload: &Value,
        key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure header has correct algorithm
        let mut header = header.clone();
        header["alg"] = json!(WalletJwtSigner::algorithm_to_jwt_alg(algorithm));

        // Get or create signing key
        let key_type = match algorithm {
            SignatureAlgorithm::EdDSA => VcKeyType::Ed25519,
            SignatureAlgorithm::ES256 => VcKeyType::P256,
            _ => return Err(format!("Unsupported algorithm: {:?}", algorithm).into()),
        };

        let signing_key = self.get_or_create_signing_key(key_id, key_type).await?;

        // Sign with wallet
        self.signer.sign_jwt(&header, payload, &signing_key).await
    }

    /// Verify JWT signature
    pub async fn verify_jwt(
        &self,
        jwt: &str,
    ) -> Result<(Value, Value), Box<dyn std::error::Error + Send + Sync>> {
        // Parse JWT to get header
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".into());
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
        let header: Value = serde_json::from_slice(&header_bytes)?;

        // Get key ID from header
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or("Missing 'kid' in JWT header")?;

        // Resolve public key
        let public_key = if self.did_registry.is_some() {
            // A registry-backed verifier must resolve and authorize the exact
            // issuer assertion key. Until that is implemented, fail closed
            // instead of parsing an unverified token.
            return Err("DID-registry JWT key resolution is not implemented".into());
        } else {
            // Try to get from wallet
            if let Some(key) = self.wallet.get_key(kid).await? {
                key.public_key
            } else {
                return Err(format!("Key not found: {}", kid).into());
            }
        };

        // Verify and return header/payload
        self.signer.verify_jwt(jwt, &public_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_conversion() {
        assert_eq!(
            WalletJwtSigner::algorithm_to_jwt_alg(SignatureAlgorithm::EdDSA),
            "EdDSA"
        );
        assert_eq!(
            WalletJwtSigner::algorithm_to_jwt_alg(SignatureAlgorithm::ES256),
            "ES256"
        );
    }
}
