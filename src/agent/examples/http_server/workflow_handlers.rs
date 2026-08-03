//! Workflow-protocol HTTP handlers for the example server.
//! (Extracted from main.rs — same `use super::*` scope.)

use super::*;

/// Helper: send a DIDComm message via an established connection.
async fn send_didcomm(
    agent: &agent::Agent,
    connection_id: &str,
    message: didcomm::core::Message,
) -> Result<(), StatusCode> {
    agent
        .send_for_connection(connection_id, message)
        .await
        .map_err(|e| {
            eprintln!("Error sending workflow message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// Helper: resolve the workflow module or return 501.
fn workflow(agent: &agent::Agent) -> Result<Arc<agent::modules::WorkflowModule>, StatusCode> {
    agent.workflow().ok_or(StatusCode::NOT_IMPLEMENTED)
}

pub async fn publish_template(
    State(agent): State<SharedAgent>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let template: protocol_workflow::WorkflowTemplate =
        serde_json::from_value(req["template"].clone()).map_err(|e| {
            eprintln!("Invalid template format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let record = workflow(&agent)?
        .publish_template(template)
        .await
        .map_err(|e| {
            eprintln!("Error publishing template: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!(
        "✓ Published workflow template: {} v{}",
        record.template_id, record.version
    );
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

pub async fn list_templates(
    State(agent): State<SharedAgent>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let templates = workflow(&agent)?.list_templates().await.map_err(|e| {
        eprintln!("Error listing templates: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(serde_json::to_value(&templates).unwrap()))
}

pub async fn get_template(
    State(agent): State<SharedAgent>,
    Path(template_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let version = params.get("version").map(|v| v.as_str());

    let record = workflow(&agent)?
        .get_template(&template_id, version)
        .await
        .map_err(|e| {
            eprintln!("Error getting template: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(serde_json::to_value(&record).unwrap()))
}

#[derive(Deserialize)]
pub struct FetchTemplateRemoteRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
    #[serde(rename = "templateId")]
    template_id: String,
    #[serde(rename = "templateVersion")]
    template_version: Option<String>,
}

/// Fetch a template from a remote agent via DIDComm fetch-template message.
/// Sends FetchTemplateMessage, waits for TemplateHandler to store the response.
pub async fn fetch_template_remote(
    State(agent_state): State<SharedAgent>,
    Json(req): Json<FetchTemplateRemoteRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Send the fetch-template message
    {
        let agent = &agent_state;

        let fetch_msg = protocol_workflow::FetchTemplateMessage {
            template_id: req.template_id.clone(),
            template_version: req.template_version.clone(),
            prefer_hash: false,
        };

        let body =
            serde_json::to_value(&fetch_msg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::FetchTemplateMessage::TYPE.to_string(),
            body,
        );

        println!(
            "→ Sending fetch-template to connection {}",
            req.connection_id
        );
        send_didcomm(agent, &req.connection_id, didcomm_msg).await?;
    } // Drop lock so agent can process incoming messages

    // Poll for template arrival (TemplateHandler stores it via publish_template)
    let version_ref = req.template_version.as_deref();
    for i in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        if let Ok(Some(record)) = workflow(&agent_state)?
            .get_template(&req.template_id, version_ref)
            .await
        {
            println!(
                "✓ Fetched template from remote: {} (after {}s)",
                record.template_id,
                i + 1
            );
            return Ok(Json(serde_json::to_value(&record).unwrap()));
        }
    }

    eprintln!("Timeout waiting for template from remote");
    Err(StatusCode::GATEWAY_TIMEOUT)
}

#[derive(Deserialize)]
pub struct StartWorkflowRequest {
    template_id: String,
    template_version: Option<String>,
    instance_id: Option<String>,
    connection_id: Option<String>,
    participants: Option<std::collections::HashMap<String, protocol_workflow::Participant>>,
    context: Option<serde_json::Value>,
}

pub async fn start(
    State(agent): State<SharedAgent>,
    Json(req): Json<StartWorkflowRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let opts = protocol_workflow::services::StartOptions {
        template_id: req.template_id.clone(),
        template_version: req.template_version.clone(),
        instance_id: req.instance_id.clone(),
        connection_id: req.connection_id.clone(),
        participants: req.participants.clone(),
        context: req.context.clone(),
        role: protocol_workflow::WorkflowRole::Coordinator,
    };

    let record = workflow(&agent)?.start(opts).await.map_err(|e| {
        eprintln!("Error starting workflow: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // If connection_id provided, send StartMessage to remote agent
    if let Some(ref conn_id) = req.connection_id {
        let start_msg = protocol_workflow::StartMessage {
            template_id: req.template_id,
            template_version: req.template_version,
            instance_id: Some(record.data.instance_id.clone()),
            connection_id: Some(conn_id.clone()),
            participants: req.participants,
            context: req.context,
            allow_discover: None,
            template_hash: None,
        };

        let body = serde_json::to_value(&start_msg).unwrap();
        let didcomm_msg = didcomm::core::Message::new(
            record.data.instance_id.clone(),
            protocol_workflow::StartMessage::TYPE.to_string(),
            body,
        );

        if let Err(e) = send_didcomm(&agent, conn_id, didcomm_msg).await {
            eprintln!("Warning: failed to send StartMessage to remote: {:?}", e);
        }
    }

    println!(
        "✓ Workflow started: instance_id={} state={}",
        record.data.instance_id, record.data.state
    );
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

#[derive(Deserialize)]
pub struct AdvanceWorkflowRequest {
    instance_id: String,
    event: String,
    idempotency_key: Option<String>,
    input: Option<serde_json::Value>,
}

pub async fn advance(
    State(agent): State<SharedAgent>,
    Json(req): Json<AdvanceWorkflowRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let opts = protocol_workflow::services::AdvanceOptions {
        instance_id: req.instance_id.clone(),
        event: req.event.clone(),
        idempotency_key: req.idempotency_key.clone(),
        input: req.input.clone(),
    };

    let record = workflow(&agent)?.advance(opts).await.map_err(|e| {
        eprintln!("Error advancing workflow: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // If instance has connection_id, send AdvanceMessage to remote
    if let Some(ref conn_id) = record.data.connection_id {
        let advance_msg = protocol_workflow::AdvanceMessage {
            instance_id: req.instance_id.clone(),
            event: req.event,
            idempotency_key: req.idempotency_key,
            input: req.input,
        };

        let body = serde_json::to_value(&advance_msg).unwrap();
        let mut didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::AdvanceMessage::TYPE.to_string(),
            body,
        );
        didcomm_msg.pthid = Some(req.instance_id);

        if let Err(e) = send_didcomm(&agent, conn_id, didcomm_msg).await {
            eprintln!("Warning: failed to send AdvanceMessage to remote: {:?}", e);
        }
    }

    println!(
        "✓ Workflow advanced: instance_id={} state={}",
        record.data.instance_id, record.data.state
    );
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

pub async fn status(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let opts = protocol_workflow::services::StatusOptions {
        instance_id,
        include_actions: true,
        include_ui: false,
        ui_profile: None,
        viewer: None,
    };

    let result = workflow(&agent)?.status(opts).await.map_err(|e| {
        eprintln!("Error getting workflow status: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // StatusResponse contains StatusMessage (Serialize) + WorkflowInstanceRecord
    Ok(Json(json!({
        "instance_id": result.message.instance_id,
        "state": result.message.state,
        "section": result.message.section,
        "allowed_events": result.message.allowed_events,
        "action_menu": result.message.action_menu,
        "artifacts": result.message.artifacts,
    })))
}

pub async fn get_instance(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let record = workflow(&agent)?
        .get_instance(&instance_id)
        .await
        .map_err(|e| {
            eprintln!("Error getting workflow instance: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(serde_json::to_value(&record).unwrap()))
}

#[derive(Deserialize)]
pub struct LifecycleRequest {
    reason: Option<String>,
}

pub async fn pause(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
    Json(req): Json<LifecycleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let record = workflow(&agent)?
        .pause(&instance_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            eprintln!("Error pausing workflow: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Send PauseMessage to remote if connected
    if let Some(ref conn_id) = record.data.connection_id {
        let pause_msg = protocol_workflow::PauseMessage {
            instance_id: instance_id.clone(),
            reason: req.reason,
        };
        let body = serde_json::to_value(&pause_msg).unwrap();
        let mut didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::PauseMessage::TYPE.to_string(),
            body,
        );
        didcomm_msg.pthid = Some(instance_id.clone());
        let _ = send_didcomm(&agent, conn_id, didcomm_msg).await;
    }

    println!("✓ Workflow paused: instance_id={}", instance_id);
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

pub async fn resume(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
    Json(req): Json<LifecycleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let record = workflow(&agent)?
        .resume(&instance_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            eprintln!("Error resuming workflow: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(ref conn_id) = record.data.connection_id {
        let resume_msg = protocol_workflow::ResumeMessage {
            instance_id: instance_id.clone(),
            reason: req.reason,
        };
        let body = serde_json::to_value(&resume_msg).unwrap();
        let mut didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::ResumeMessage::TYPE.to_string(),
            body,
        );
        didcomm_msg.pthid = Some(instance_id.clone());
        let _ = send_didcomm(&agent, conn_id, didcomm_msg).await;
    }

    println!("✓ Workflow resumed: instance_id={}", instance_id);
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

pub async fn cancel(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
    Json(req): Json<LifecycleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let record = workflow(&agent)?
        .cancel(&instance_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            eprintln!("Error cancelling workflow: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(ref conn_id) = record.data.connection_id {
        let cancel_msg = protocol_workflow::CancelMessage {
            instance_id: instance_id.clone(),
            reason: req.reason,
        };
        let body = serde_json::to_value(&cancel_msg).unwrap();
        let mut didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::CancelMessage::TYPE.to_string(),
            body,
        );
        didcomm_msg.pthid = Some(instance_id.clone());
        let _ = send_didcomm(&agent, conn_id, didcomm_msg).await;
    }

    println!("✓ Workflow cancelled: instance_id={}", instance_id);
    Ok(Json(serde_json::to_value(&record).unwrap()))
}

pub async fn complete(
    State(agent): State<SharedAgent>,
    Path(instance_id): Path<String>,
    Json(req): Json<LifecycleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let record = workflow(&agent)?
        .complete(&instance_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            eprintln!("Error completing workflow: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(ref conn_id) = record.data.connection_id {
        let complete_msg = protocol_workflow::CompleteMessage {
            instance_id: instance_id.clone(),
            reason: req.reason,
        };
        let body = serde_json::to_value(&complete_msg).unwrap();
        let mut didcomm_msg = didcomm::core::Message::new(
            uuid::Uuid::new_v4().to_string(),
            protocol_workflow::CompleteMessage::TYPE.to_string(),
            body,
        );
        didcomm_msg.pthid = Some(instance_id.clone());
        let _ = send_didcomm(&agent, conn_id, didcomm_msg).await;
    }

    println!("✓ Workflow completed: instance_id={}", instance_id);
    Ok(Json(serde_json::to_value(&record).unwrap()))
}
