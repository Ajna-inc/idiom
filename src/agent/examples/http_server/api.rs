//! Core management API + basic-messages + SSE handlers for the example.

use super::*;

// ===== API Handlers =====

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "label": "Rust Interop Agent"
    }))
}

#[derive(Deserialize)]
pub struct CreateInvitationRequest {
    label: Option<String>,
    #[serde(rename = "multiUse")]
    multi_use: Option<bool>,
}

pub async fn create_oob_invitation(
    State(agent): State<SharedAgent>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut config = InvitationConfig::new();
    if let Some(label) = req.label {
        config = config.with_label(label);
    }
    if let Some(multi_use) = req.multi_use {
        config = config.with_multi_use(multi_use);
    }

    let record = agent.create_oob_invitation(config).await.map_err(|e| {
        eprintln!("Error creating invitation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!("✓ Created OOB invitation: {}", record.id);

    Ok(Json(json!({
        "id": record.id,
        "invitation": record.invitation,
        "outOfBandRecord": record,
    })))
}

#[derive(Deserialize)]
pub struct ReceiveInvitationRequest {
    invitation: serde_json::Value,
}

pub async fn receive_oob_invitation(
    State(agent): State<SharedAgent>,
    Json(req): Json<ReceiveInvitationRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let invitation: protocol_oob::OutOfBandInvitation = serde_json::from_value(req.invitation)
        .map_err(|e| {
            eprintln!("Invalid invitation format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let result = agent
        .receive_oob_invitation(invitation, Some(true))
        .await
        .map_err(|e| {
            eprintln!("Error receiving invitation: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("✓ Received OOB invitation: {}", result.oob_record.id);

    Ok(Json(json!({
        "id": result.oob_record.id,
        "outOfBandRecord": result.oob_record,
    })))
}

pub async fn get_connections(
    State(agent): State<SharedAgent>,
) -> Result<Json<Vec<protocol_connections::ConnectionRecord>>, StatusCode> {
    let connections = agent.connections().get_all().await.map_err(|e| {
        eprintln!("Error getting connections: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    println!(
        "\n[API /connections] Returning {} connections:",
        connections.len()
    );
    for (i, conn) in connections.iter().enumerate() {
        println!(
            "  [{}] id={}, state={:?}, role={:?}, thread_id={}",
            i, conn.id, conn.state, conn.role, conn.thread_id
        );
    }

    Ok(Json(connections))
}

pub async fn get_connection(
    State(agent): State<SharedAgent>,
    Path(id): Path<String>,
) -> Result<Json<protocol_connections::ConnectionRecord>, StatusCode> {
    let connection = agent
        .connections()
        .find_by_id(&id)
        .await
        .map_err(|e| {
            eprintln!("Error getting connection: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(connection))
}

pub async fn get_oob_records(
    State(agent): State<SharedAgent>,
) -> Result<Json<Vec<protocol_oob::OutOfBandRecord>>, StatusCode> {
    let records = agent.oob().get_all().await.map_err(|e| {
        eprintln!("Error getting OOB records: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(records))
}

// ===== Basic Messages Handlers =====

#[derive(Deserialize)]
pub struct GetBasicMessagesQuery {
    #[serde(rename = "connectionId")]
    connection_id: String,
}

pub async fn get_basic_messages(
    State(agent): State<SharedAgent>,
    axum::extract::Query(query): axum::extract::Query<GetBasicMessagesQuery>,
) -> Result<Json<Vec<protocol_basic_messages::BasicMessageRecord>>, StatusCode> {
    let messages = agent
        .basic_messages()
        .expect("basic_messages module composed")
        .find_by_connection_id(&query.connection_id)
        .await
        .map_err(|e| {
            eprintln!("Error getting basic messages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(messages))
}

#[derive(Deserialize)]
pub struct SendBasicMessageRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
    content: String,
    #[serde(rename = "parentThreadId")]
    parent_thread_id: Option<String>,
}

pub async fn send_basic_message(
    State(agent): State<SharedAgent>,
    Json(req): Json<SendBasicMessageRequest>,
) -> Result<Json<protocol_basic_messages::BasicMessageRecord>, StatusCode> {
    let record = agent
        .basic_messages()
        .expect("basic_messages module composed")
        .send_message(&req.connection_id, req.content, req.parent_thread_id)
        .await
        .map_err(|e| {
            eprintln!("Error sending basic message: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("✓ Sent basic message: {}", record.id);

    Ok(Json(record))
}

// ===== Server-Sent Events Stream =====

pub async fn event_stream(
    State(agent): State<SharedAgent>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    // Subscribe to agent's event bus
    let mut subscriber = agent.events.subscribe();

    // Create async stream
    let stream = async_stream::stream! {
        loop {
            match subscriber.recv().await {
                Ok(event) => {
                    let data = json!({
                        "timestamp": event.timestamp,
                        "topic": event.topic,
                        "event_type": event.name,
                        "payload": event.data,
                    });

                    yield Ok(SseEvent::default().data(data.to_string()));
                }
                Err(e) => {
                    eprintln!("Error receiving event: {}", e);
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}
