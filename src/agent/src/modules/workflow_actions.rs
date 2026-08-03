//! Credential workflow action handlers.
//!
//! Bridges workflow transitions to the AnonCreds exchange services so a
//! workflow step can issue a credential (offer) or request a proof. These live
//! in the agent crate (not `protocol_workflow`) because they need the exchange
//! services + DIDComm sender; they implement `protocol_workflow`'s
//! `WorkflowActionHandler` trait and are registered on the `WorkflowModule`
//! once AnonCreds is set up. Mirrors the Python `issue_credential` /
//! `present_proof` actions (FASTER actions intentionally omitted).

use std::collections::HashMap;
use std::sync::Arc;

use anoncreds_core::types::{AttributeInfo, PredicateInfo, PredicateTypes};
use async_trait::async_trait;
use protocol_credentials::{CredentialExchangeService, RequestCredentialHandler};
use protocol_proofs::ProofExchangeService;
use protocol_workflow::actions::registry::{ActionContext, ActionResult, WorkflowActionHandler};
use protocol_workflow::domain::template::{CredentialProfile, ProofProfile};
use protocol_workflow::engine::attribute::AttributePlanner;
use protocol_workflow::WorkflowError;
use serde_json::json;

use crate::messaging::DidCommSender;
use crate::modules::ConnectionsModule;

type WfResult<T> = std::result::Result<T, WorkflowError>;

fn fail(msg: impl Into<String>) -> WorkflowError {
    WorkflowError::ActionFailed(msg.into())
}

/// The connection to send to. Workflow instances carry a single holder
/// connection (`instance.connection_id`); `to_ref` names the target
/// participant but connection binding is at the instance level.
fn resolve_connection(ctx: &ActionContext, to_ref: &str) -> WfResult<String> {
    ctx.instance
        .connection_id
        .clone()
        .ok_or_else(|| fail(format!("no connection on instance for target '{to_ref}'")))
}

/// Coerce a JSON value to the string form AnonCreds attributes use.
fn value_to_string(v: serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Look up a value from the action's staticInput or the profile options.
fn str_field(
    ctx: &ActionContext,
    options: Option<&serde_json::Value>,
    key: &str,
) -> Option<String> {
    ctx.action
        .static_input
        .as_ref()
        .and_then(|s| s.get(key))
        .or_else(|| options.and_then(|o| o.get(key)))
        .and_then(|v| v.as_str())
        .map(String::from)
}

// --- issue-credential -----------------------------------------------------

pub struct IssueCredentialAction {
    pub cred_exchange: Arc<CredentialExchangeService>,
    pub connections: ConnectionsModule,
    pub sender: Arc<DidCommSender>,
    /// Shared issuer request handler — attributes registered here are used to
    /// auto-issue the credential with the workflow's values when the holder
    /// sends its request.
    pub request_handler: Arc<RequestCredentialHandler>,
}

impl IssueCredentialAction {
    pub const TYPE_URI: &'static str = "https://didcomm.org/issue-credential/2.0/offer-credential";

    fn profile<'a>(&self, ctx: &'a ActionContext) -> Option<&'a CredentialProfile> {
        let name = ctx.action.profile_ref.as_ref()?.strip_prefix("cp.")?;
        ctx.template.catalog.credential_profiles.get(name)
    }

    /// Materialize the credential attribute values: from the profile's
    /// attribute plan (context/static/computed), else from `staticInput.attributes`.
    fn resolve_attributes(
        &self,
        ctx: &ActionContext,
        profile: Option<&CredentialProfile>,
    ) -> WfResult<HashMap<String, String>> {
        if let Some(p) = profile {
            if !p.attribute_plan.is_empty() {
                let resolved = AttributePlanner::resolve(
                    &p.attribute_plan,
                    &ctx.instance.context,
                    &ctx.instance.participants,
                    &ctx.instance.artifacts,
                )?;
                return Ok(resolved
                    .into_iter()
                    .map(|(k, v)| (k, value_to_string(v)))
                    .collect());
            }
        }
        // Fallback: staticInput.attributes = { name: value, … }
        let attrs = ctx
            .action
            .static_input
            .as_ref()
            .and_then(|s| s.get("attributes"))
            .and_then(|a| a.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), value_to_string(v.clone())))
                    .collect()
            })
            .unwrap_or_default();
        Ok(attrs)
    }
}

#[async_trait]
impl WorkflowActionHandler for IssueCredentialAction {
    fn type_uri(&self) -> &str {
        Self::TYPE_URI
    }

    async fn execute(&self, ctx: ActionContext) -> WfResult<ActionResult> {
        let profile = self.profile(&ctx);
        let options = profile.and_then(|p| p.options.as_ref());
        let cred_def_id = profile
            .and_then(|p| p.cred_def_id.clone())
            .or_else(|| str_field(&ctx, options, "cred_def_id"))
            .ok_or_else(|| fail("issue-credential: no cred_def_id (catalog or staticInput)"))?;
        // schema_id is optional: DigiCred workflow templates patch in only the
        // cred_def_id. When absent, the issuer derives it from the cred-def.
        let schema_id = str_field(&ctx, options, "schema_id").unwrap_or_default();
        let to_ref = profile.map(|p| p.to_ref.as_str()).unwrap_or("holder");
        let connection_id = resolve_connection(&ctx, to_ref)?;

        // Resolve the credential attribute values now (from context).
        let attributes = self.resolve_attributes(&ctx, profile)?;

        let (record, offer_msg) = self
            .cred_exchange
            .create_offer(Some(&connection_id), &schema_id, &cred_def_id)
            .await
            .map_err(|e| fail(format!("create_offer: {e}")))?;

        // The Aries 2.0 offer carries the attribute preview; also register the
        // attributes so the issuer auto-issues with them on the holder's request.
        let preview: Vec<(String, String)> = attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !attributes.is_empty() {
            self.request_handler
                .register_auto_issue_attributes(&record.id, attributes)
                .await;
        }

        let conn = self
            .connections
            .get_by_id(&connection_id)
            .await
            .map_err(|e| fail(format!("connection lookup: {e}")))?
            .ok_or_else(|| fail(format!("connection {connection_id} not found")))?;
        // Send the Aries 2.0 offer value (top-level @type + credential_preview +
        // offers~attach) so an interoperable wallet's anoncreds format service reads it.
        let offer_value = offer_msg.to_aries_v2_value(&preview);
        self.sender
            .send_via_connection(&conn, &offer_value)
            .await
            .map_err(|e| fail(format!("send offer: {e}")))?;

        Ok(ActionResult {
            artifacts: Some(json!({ "cred_ex_id": record.id })),
            context_merge: None,
            message_id: Some(offer_msg.thread_id.clone()),
        })
    }
}

// --- present-proof --------------------------------------------------------

pub struct PresentProofAction {
    pub proof_exchange: Arc<ProofExchangeService>,
    pub connections: ConnectionsModule,
    pub sender: Arc<DidCommSender>,
}

impl PresentProofAction {
    pub const TYPE_URI: &'static str = "https://didcomm.org/present-proof/2.0/request-presentation";

    fn profile<'a>(&self, ctx: &'a ActionContext) -> Option<&'a ProofProfile> {
        let name = ctx.action.profile_ref.as_ref()?.strip_prefix("pp.")?;
        ctx.template.catalog.proof_profiles.get(name)
    }
}

fn predicate_type(s: &str) -> PredicateTypes {
    match s {
        ">=" => PredicateTypes::GE,
        ">" => PredicateTypes::GT,
        "<=" => PredicateTypes::LE,
        "<" => PredicateTypes::LT,
        _ => PredicateTypes::GE,
    }
}

#[async_trait]
impl WorkflowActionHandler for PresentProofAction {
    fn type_uri(&self) -> &str {
        Self::TYPE_URI
    }

    async fn execute(&self, ctx: ActionContext) -> WfResult<ActionResult> {
        let profile = self
            .profile(&ctx)
            .ok_or_else(|| fail("present-proof: proof profile (pp.<name>) not found in catalog"))?;

        let name = str_field(&ctx, profile.options.as_ref(), "name")
            .unwrap_or_else(|| "proof-request".to_string());
        let version =
            str_field(&ctx, profile.options.as_ref(), "version").unwrap_or_else(|| "1.0".into());

        let mut requested_attributes: HashMap<String, AttributeInfo> = HashMap::new();
        for attr in &profile.requested_attributes {
            requested_attributes.insert(
                format!("{attr}_referent"),
                AttributeInfo {
                    name: Some(attr.clone()),
                    names: None,
                    restrictions: None,
                    non_revoked: None,
                },
            );
        }
        let mut requested_predicates: HashMap<String, PredicateInfo> = HashMap::new();
        for (i, pred) in profile.requested_predicates.iter().enumerate() {
            requested_predicates.insert(
                format!("pred{i}_referent"),
                PredicateInfo {
                    name: pred.name.clone(),
                    p_type: predicate_type(&pred.p_type),
                    p_value: pred.p_value.as_i64().unwrap_or(0) as i32,
                    restrictions: None,
                    non_revoked: None,
                },
            );
        }

        let connection_id = resolve_connection(&ctx, &profile.to_ref)?;
        let (record, req_msg) = self
            .proof_exchange
            .create_request(
                &name,
                &version,
                requested_attributes,
                requested_predicates,
                Some(connection_id.clone()),
            )
            .await
            .map_err(|e| fail(format!("create_request: {e}")))?;

        let conn = self
            .connections
            .get_by_id(&connection_id)
            .await
            .map_err(|e| fail(format!("connection lookup: {e}")))?
            .ok_or_else(|| fail(format!("connection {connection_id} not found")))?;
        // Send the Aries 2.0 request value (top-level @type + request_presentations~attach)
        // so an interoperable wallet's anoncreds format service reads it — same shape as the
        // credential offer.
        let req_value = req_msg.to_aries_v2_value();
        self.sender
            .send_via_connection(&conn, &req_value)
            .await
            .map_err(|e| fail(format!("send proof request: {e}")))?;

        Ok(ActionResult {
            artifacts: Some(json!({ "pres_ex_id": record.id })),
            context_merge: None,
            message_id: None,
        })
    }
}
