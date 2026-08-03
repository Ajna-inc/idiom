//! AnonCreds credential setup + DIDComm issuance HTTP handlers (feature-gated).

use super::*;

// ===== AnonCreds credential setup (issuer-side, single-agent) =====

#[cfg(feature = "anoncreds")]
const DEFAULT_ISSUER_ID: &str = "did:idiom:issuer";

#[cfg(feature = "anoncreds")]
#[derive(Deserialize)]
pub struct SetupSchemaRequest {
    name: String,
    version: String,
    attributes: Vec<String>,
    #[serde(rename = "issuerId", default)]
    issuer_id: Option<String>,
}

/// POST /setup/schema — create + register an AnonCreds schema on the configured
/// ledger backend. Returns `{ schemaId }`.
#[cfg(feature = "anoncreds")]
pub async fn setup_schema(
    State(agent): State<SharedAgent>,
    Json(req): Json<SetupSchemaRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Owned Arc so no borrow of `agent` is held across the await.
    let issuer = agent
        .anoncreds()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?
        .issuer_service();
    let issuer_id = req
        .issuer_id
        .unwrap_or_else(|| DEFAULT_ISSUER_ID.to_string());
    let reg = issuer
        .create_schema(&issuer_id, &req.name, &req.version, req.attributes)
        .await
        .map_err(|e| {
            eprintln!("setup_schema: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(
        json!({ "schemaId": reg.schema_id, "issuerId": issuer_id }),
    ))
}

#[cfg(feature = "anoncreds")]
#[derive(Deserialize)]
pub struct SetupCredDefRequest {
    #[serde(rename = "schemaId")]
    schema_id: String,
    #[serde(default)]
    tag: Option<String>,
    #[serde(rename = "supportRevocation", default)]
    support_revocation: bool,
    #[serde(rename = "issuerId", default)]
    issuer_id: Option<String>,
}

/// POST /setup/cred-def — create + register a credential definition for a
/// schema. Returns `{ credDefId }`.
#[cfg(feature = "anoncreds")]
pub async fn setup_cred_def(
    State(agent): State<SharedAgent>,
    Json(req): Json<SetupCredDefRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let issuer = agent
        .anoncreds()
        .ok_or(StatusCode::NOT_IMPLEMENTED)?
        .issuer_service();
    let issuer_id = req
        .issuer_id
        .unwrap_or_else(|| DEFAULT_ISSUER_ID.to_string());
    let tag = req.tag.unwrap_or_else(|| "default".to_string());
    let reg = issuer
        .create_credential_definition(&issuer_id, &req.schema_id, &tag, req.support_revocation)
        .await
        .map_err(|e| {
            eprintln!("setup_cred_def: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(json!({ "credDefId": reg.cred_def_id })))
}

// ===== Real DIDComm issuance path (through the agent, over a connection) =====

#[cfg(feature = "anoncreds")]
#[derive(Deserialize)]
pub struct IssueOfferRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
    #[serde(rename = "schemaId")]
    schema_id: String,
    #[serde(rename = "credDefId")]
    cred_def_id: String,
    #[serde(default)]
    attributes: std::collections::HashMap<String, String>,
}

/// POST /issue/offer — issue a credential to a connection over **real DIDComm**.
/// Runs the full protocol through the agent: create offer → register auto-issue
/// attributes → send the offer over the connection. The holder auto-accepts
/// (offer→request), the issuer auto-issues (request→credential), the holder
/// stores it. Returns `{ exchangeId }`.
#[cfg(feature = "anoncreds")]
pub async fn issue_offer(
    State(agent): State<SharedAgent>,
    Json(req): Json<IssueOfferRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let cred_exchange = {
        let m = agent.anoncreds().ok_or(StatusCode::NOT_IMPLEMENTED)?;
        m.credential_exchange_service()
    };

    let (record, offer_msg) = cred_exchange
        .create_offer(Some(&req.connection_id), &req.schema_id, &req.cred_def_id)
        .await
        .map_err(|e| {
            eprintln!("issue_offer create: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Persist the values on the exchange record so the issuer auto-issues when
    // the holder's request arrives — and so it still works after a restart / when
    // the request is replayed against a seeded OfferSent exchange.
    cred_exchange
        .set_auto_issue_attributes(&record.id, req.attributes)
        .await
        .map_err(|e| {
            eprintln!("issue_offer set_auto_issue: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Send the offer over the real connection — through the agent's messaging.
    agent
        .send_for_connection(&req.connection_id, offer_msg.to_didcomm_message())
        .await
        .map_err(|e| {
            eprintln!("issue_offer send: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({ "exchangeId": record.id })))
}

/// GET /credentials/count — number of AnonCreds credentials the holder has
/// actually stored. The honest "processed" sink for the issuance benchmark.
#[cfg(feature = "anoncreds")]
pub async fn credentials_count(
    State(agent): State<SharedAgent>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let holder = {
        let m = agent.anoncreds().ok_or(StatusCode::NOT_IMPLEMENTED)?;
        m.holder_service()
    };
    let creds = holder.list_credentials().await.map_err(|e| {
        eprintln!("credentials_count: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(json!({ "count": creds.len() })))
}
