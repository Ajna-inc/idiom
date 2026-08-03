//! Real OID4VCI credential minters + holder proof builder.
//!
//! Bridges the OID4VCI issuer service to the `vc` crate's actual signing:
//! - `vc+sd-jwt` credentials are signed via [`SdJwtIssuer`] (selective
//!   disclosure + EdDSA), and
//! - `jwt_vc_json` credentials are signed via [`WalletBackedJwtVcService`].
//!
//! Both use a wallet-held Ed25519 issuer key, so issuance does the real
//! cryptographic work (the previous `EchoMinter` returned `{"ok":true}`).
//!
//! [`WalletJwtProofBuilder`] is the holder counterpart: it produces the
//! `openid4vci-proof+jwt` key-possession proof the issuer binds into `cnf`.

use super::holder::ProofBuilder;
use super::issuer::Oid4vciCredentialMinter;
use super::types::{CredentialConfiguration, CredentialProof, CredentialRequest};
use agent_core::traits::wallet::WalletProvider;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use vc::core::SignatureAlgorithm;
use vc::formats::jwt_vc::WalletBackedJwtVcService;
use vc::formats::sd_jwt::{DisclosureFrame, SdJwtIssuer};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Build an Ed25519 OKP JWK from raw public-key bytes.
pub fn ed25519_jwk(public_key: &[u8]) -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": B64.encode(public_key) })
}

/// Pull the holder binding JWK out of a JWT proof's header (`jwk`).
fn holder_jwk_from_proof(proof: Option<&CredentialProof>) -> Option<Value> {
    let CredentialProof::Jwt { jwt } = proof? else {
        return None;
    };
    let header_b64 = jwt.split('.').next()?;
    let header: Value = serde_json::from_slice(&B64.decode(header_b64).ok()?).ok()?;
    header.get("jwk").cloned()
}

/// A real OID4VCI minter that signs `vc+sd-jwt` and `jwt_vc_json` credentials
/// with a wallet-held issuer key. Subject claims come from a per-configuration
/// template registered up front.
pub struct VcCredentialMinter {
    wallet: Arc<dyn WalletProvider>,
    /// Wallet key id used to sign issued credentials.
    issuer_key_id: String,
    /// Value used as the `iss` claim (issuer DID or URL).
    issuer_id: String,
    /// `configuration_id` → subject-claim template (a JSON object).
    templates: HashMap<String, Value>,
}

impl VcCredentialMinter {
    pub fn new(
        wallet: Arc<dyn WalletProvider>,
        issuer_key_id: impl Into<String>,
        issuer_id: impl Into<String>,
        templates: HashMap<String, Value>,
    ) -> Self {
        Self {
            wallet,
            issuer_key_id: issuer_key_id.into(),
            issuer_id: issuer_id.into(),
            templates,
        }
    }

    fn subject_claims(&self, configuration_id: &str) -> serde_json::Map<String, Value> {
        self.templates
            .get(configuration_id)
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    }

    async fn mint_sd_jwt(
        &self,
        configuration_id: &str,
        subject_id: Option<&str>,
        holder_jwk: Option<Value>,
    ) -> Result<Value, String> {
        let subject = self.subject_claims(configuration_id);

        // Full SD-JWT claim set: registered JWT claims + subject attributes.
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), json!(self.issuer_id));
        claims.insert("iat".into(), json!(now_ts()));
        claims.insert("vct".into(), json!(configuration_id));
        if let Some(sub) = subject_id {
            claims.insert("sub".into(), json!(sub));
        }
        for (k, v) in &subject {
            claims.insert(k.clone(), v.clone());
        }

        // Every subject attribute is selectively disclosable.
        let paths: Vec<Vec<String>> = subject.keys().map(|k| vec![k.clone()]).collect();
        let frame = DisclosureFrame::from_paths(&paths);

        let issuer = SdJwtIssuer::new(self.wallet.clone());
        let sd_jwt = issuer
            .issue(
                Value::Object(claims),
                &frame,
                &self.issuer_key_id,
                holder_jwk,
            )
            .await
            .map_err(|e| format!("sd-jwt issue failed: {e}"))?;

        Ok(json!(sd_jwt.to_compact()))
    }

    async fn mint_jwt_vc(
        &self,
        configuration_id: &str,
        subject_id: Option<&str>,
        holder_jwk: Option<Value>,
    ) -> Result<Value, String> {
        let mut subject = self.subject_claims(configuration_id);
        if let Some(sub) = subject_id {
            subject.insert("id".into(), json!(sub));
        }

        let mut payload = serde_json::Map::new();
        payload.insert("iss".into(), json!(self.issuer_id));
        payload.insert("iat".into(), json!(now_ts()));
        payload.insert("nbf".into(), json!(now_ts()));
        if let Some(sub) = subject_id {
            payload.insert("sub".into(), json!(sub));
        }
        if let Some(jwk) = holder_jwk {
            payload.insert("cnf".into(), json!({ "jwk": jwk }));
        }
        payload.insert(
            "vc".into(),
            json!({
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", configuration_id],
                "credentialSubject": Value::Object(subject),
            }),
        );

        let header = json!({ "typ": "JWT", "alg": "EdDSA" });
        let svc = WalletBackedJwtVcService::new(self.wallet.clone());
        let jwt = svc
            .sign_jwt(
                &header,
                &Value::Object(payload),
                &self.issuer_key_id,
                SignatureAlgorithm::EdDSA,
            )
            .await
            .map_err(|e| format!("jwt-vc sign failed: {e}"))?;

        Ok(json!(jwt))
    }
}

#[async_trait::async_trait]
impl Oid4vciCredentialMinter for VcCredentialMinter {
    async fn mint(
        &self,
        configuration_id: &str,
        subject_id: Option<&str>,
        request: &CredentialRequest,
    ) -> Result<Value, String> {
        let holder_jwk = holder_jwk_from_proof(request.proof.as_ref());
        match request.format.as_str() {
            "vc+sd-jwt" | "dc+sd-jwt" => {
                self.mint_sd_jwt(configuration_id, subject_id, holder_jwk)
                    .await
            }
            "jwt_vc_json" | "jwt_vc" => {
                self.mint_jwt_vc(configuration_id, subject_id, holder_jwk)
                    .await
            }
            other => Err(format!("unsupported credential format: {other}")),
        }
    }
}

/// Holder-side proof builder: produces the `openid4vci-proof+jwt` JWT that
/// proves possession of the holder key and carries the public JWK the issuer
/// binds into the credential's `cnf`.
pub struct WalletJwtProofBuilder {
    wallet: Arc<dyn WalletProvider>,
    holder_key_id: String,
    holder_public: Vec<u8>,
    audience: String,
}

impl WalletJwtProofBuilder {
    pub fn new(
        wallet: Arc<dyn WalletProvider>,
        holder_key_id: impl Into<String>,
        holder_public: Vec<u8>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            wallet,
            holder_key_id: holder_key_id.into(),
            holder_public,
            audience: audience.into(),
        }
    }
}

#[async_trait::async_trait]
impl ProofBuilder for WalletJwtProofBuilder {
    async fn build_proof(
        &self,
        c_nonce: &str,
        _config: &CredentialConfiguration,
    ) -> super::error::Result<CredentialProof> {
        let header = json!({
            "typ": "openid4vci-proof+jwt",
            "alg": "EdDSA",
            "jwk": ed25519_jwk(&self.holder_public),
        });
        let payload = json!({
            "aud": self.audience,
            "iat": now_ts(),
            "nonce": c_nonce,
        });

        let signing_input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(payload.to_string())
        );
        let sig = self
            .wallet
            .sign(&self.holder_key_id, signing_input.as_bytes())
            .await
            .map_err(|e| super::error::Oid4vciError::ProofError(e.to_string()))?;
        let jwt = format!("{signing_input}.{}", B64.encode(sig.bytes));

        Ok(CredentialProof::Jwt { jwt })
    }
}
