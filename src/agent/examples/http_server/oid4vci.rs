//! OID4VCI (SD-JWT / JWT-VC) issuer setup + HTTP handlers for the example.

use super::*;

// ============================ OID4VCI ==================================

use agent::modules::oid4vci::issuer::Oid4vciIssuerConfig;
use agent::modules::oid4vci::types::{CredentialConfiguration, CredentialRequest};
use agent::modules::oid4vci::{
    Oid4vciCredentialMinter, Oid4vciHolderService, VcCredentialMinter, WalletJwtProofBuilder,
};
use agent_core::traits::wallet::{KeyPurpose, KeyType};
use axum::extract::Form;
use axum::http::HeaderMap;

/// Build the OID4VCI issuer config + real minter. Creates a wallet-held
/// Ed25519 issuer key and registers two credential configurations: `sdjwt`
/// (vc+sd-jwt) and `jwtvc` (jwt_vc_json), each with a fixed subject template.
pub async fn build_oid4vci_issuer_setup(
    wallet: Arc<dyn WalletProvider>,
    endpoint: &str,
) -> (Oid4vciIssuerConfig, Arc<dyn Oid4vciCredentialMinter>) {
    let issuer_key = wallet
        .create_key(KeyType::Ed25519, KeyPurpose::General)
        .await
        .expect("create oid4vci issuer key");
    let base = endpoint.trim_end_matches('/').to_string();

    let mk = |format: &str| CredentialConfiguration {
        format: format.to_string(),
        scope: None,
        credential_signing_alg_values_supported: vec!["EdDSA".to_string()],
        anoncreds: None,
        display: None,
    };
    let mut configs = std::collections::HashMap::new();
    configs.insert("sdjwt".to_string(), mk("vc+sd-jwt"));
    configs.insert("jwtvc".to_string(), mk("jwt_vc_json"));

    let config = Oid4vciIssuerConfig {
        issuer_url: base.clone(),
        credential_issuer_did: base.clone(),
        credential_endpoint: format!("{base}/oid4vci/credential"),
        token_endpoint: format!("{base}/oid4vci/token"),
        nonce_endpoint: Some(format!("{base}/oid4vci/nonce")),
        credential_configurations_supported: configs,
        ..Default::default()
    };

    let template = json!({ "given_name": "Alice", "family_name": "Holder", "degree": "BSc" });
    let mut templates = std::collections::HashMap::new();
    templates.insert("sdjwt".to_string(), template.clone());
    templates.insert("jwtvc".to_string(), template);

    let minter = Arc::new(VcCredentialMinter::new(
        wallet,
        issuer_key.id,
        base,
        templates,
    ));
    (config, minter)
}

/// Pull the bearer token out of the Authorization header.
fn bearer(headers: &HeaderMap) -> Result<String, StatusCode> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or(StatusCode::UNAUTHORIZED)
}

/// GET /.well-known/openid-credential-issuer
pub async fn oid4vci_metadata(
    State(agent): State<SharedAgent>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let issuer = agent
        .oid4vci_issuer
        .as_ref()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    Ok(Json(serde_json::to_value(issuer.metadata()).unwrap()))
}

#[derive(Deserialize)]
pub struct Oid4vciOfferRequest {
    #[serde(rename = "configId")]
    config_id: String,
    #[serde(default)]
    subject_id: Option<String>,
}

/// POST /oid4vci/offer — mint a pre-authorized-code credential offer.
pub async fn oid4vci_create_offer(
    State(agent): State<SharedAgent>,
    Json(req): Json<Oid4vciOfferRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let issuer = agent
        .oid4vci_issuer
        .as_ref()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let offer = issuer.create_offer(vec![req.config_id], req.subject_id);
    Ok(Json(serde_json::to_value(offer).unwrap()))
}

#[derive(Deserialize)]
pub struct TokenForm {
    #[allow(dead_code)]
    grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,
}

/// POST /oid4vci/token — exchange a pre-authorized code for an access token.
pub async fn oid4vci_token(
    State(agent): State<SharedAgent>,
    Form(form): Form<TokenForm>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let issuer = agent
        .oid4vci_issuer
        .as_ref()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let issuance = issuer
        .accept_token_request(&form.pre_authorized_code)
        .map_err(|e| {
            eprintln!("oid4vci_token: {e}");
            StatusCode::BAD_REQUEST
        })?;
    Ok(Json(serde_json::to_value(issuance.response).unwrap()))
}

/// POST /oid4vci/nonce — mint a fresh c_nonce for the access token.
pub async fn oid4vci_nonce(
    State(agent): State<SharedAgent>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = bearer(&headers)?;
    let issuer = agent
        .oid4vci_issuer
        .as_ref()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let nonce = issuer.mint_nonce(&token).map_err(|e| {
        eprintln!("oid4vci_nonce: {e}");
        StatusCode::BAD_REQUEST
    })?;
    Ok(Json(json!({ "c_nonce": nonce })))
}

/// POST /oid4vci/credential — verify the holder proof and mint (sign) the
/// credential. This is where the real signing work happens.
pub async fn oid4vci_credential(
    State(agent): State<SharedAgent>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = bearer(&headers)?;
    let issuer = agent
        .oid4vci_issuer
        .as_ref()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let resp = issuer
        .accept_credential_request(&token, &req)
        .await
        .map_err(|e| {
            eprintln!("oid4vci_credential: {e}");
            StatusCode::BAD_REQUEST
        })?;
    Ok(Json(serde_json::to_value(resp).unwrap()))
}

/// Holder key, created once per process. The holder proof binds this key into
/// the credential's `cnf`.
static HOLDER_KEY: tokio::sync::OnceCell<(String, Vec<u8>)> = tokio::sync::OnceCell::const_new();

async fn holder_key(agent: &SharedAgent) -> Result<(String, Vec<u8>), StatusCode> {
    let wallet = agent.wallet_provider();
    let kv = HOLDER_KEY
        .get_or_try_init(|| async move {
            let k = wallet
                .create_key(KeyType::Ed25519, KeyPurpose::General)
                .await?;
            Ok::<_, agent_core::error::AgentError>((k.id.clone(), k.public_key.clone()))
        })
        .await
        .map_err(|e| {
            eprintln!("holder_key: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(kv.clone())
}

#[derive(Deserialize)]
pub struct ReceiveOfferRequest {
    offer: serde_json::Value,
    #[serde(rename = "configId")]
    config_id: String,
}

/// POST /oid4vci/receive-offer — holder driver. Resolves the offer, builds a
/// key-possession proof, and runs the full HTTP exchange against the issuer
/// (token → nonce → credential). Returns the received (signed) credential.
pub async fn oid4vci_receive_offer(
    State(agent): State<SharedAgent>,
    Json(req): Json<ReceiveOfferRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (key_id, pubkey) = holder_key(&agent).await?;
    let holder = Oid4vciHolderService::new().map_err(|e| {
        eprintln!("oid4vci_receive_offer new: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let resolved = holder
        .resolve_credential_offer(&req.offer.to_string())
        .await
        .map_err(|e| {
            eprintln!("oid4vci_receive_offer resolve: {e}");
            StatusCode::BAD_GATEWAY
        })?;
    let audience = resolved.metadata.credential_issuer.clone();
    let proof_builder =
        WalletJwtProofBuilder::new(agent.wallet_provider(), key_id, pubkey, audience);
    let issued = holder
        .request_credential(&resolved, &req.config_id, &proof_builder)
        .await
        .map_err(|e| {
            eprintln!("oid4vci_receive_offer request: {e}");
            StatusCode::BAD_GATEWAY
        })?;
    Ok(Json(json!({
        "format": issued.format,
        "credential": issued.credential,
    })))
}
