//! Event Monitoring Server
//!
//! HTTP server for streaming consensus and peer events to external test harnesses.
//! Supports both WebSocket and Server-Sent Events (SSE) for real-time monitoring.

use agent_events::{Event, EventBus};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{sse::Event as SseEvent, IntoResponse, Sse},
    routing::get,
    Router,
};
use futures_util::{stream::Stream, SinkExt, StreamExt};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info};

/// Monitoring server configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Address to bind to
    pub addr: SocketAddr,

    /// Maximum events to buffer
    pub buffer_size: usize,

    /// Enable CORS for web dashboard
    pub enable_cors: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 9080)),
            buffer_size: 1000,
            enable_cors: true,
        }
    }
}

/// Monitoring server state
#[derive(Clone)]
struct MonitoringState {
    /// Event bus to subscribe to
    event_bus: Arc<EventBus>,

    /// Recent events buffer for history queries
    recent_events: Arc<RwLock<Vec<Event>>>,

    /// Configuration
    config: MonitoringConfig,
}

/// Monitoring server for streaming events
pub struct MonitoringServer {
    /// Server state
    state: MonitoringState,

    /// Server handle
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl MonitoringServer {
    /// Create a new monitoring server
    pub fn new(config: MonitoringConfig, event_bus: Arc<EventBus>) -> Self {
        let state = MonitoringState {
            event_bus,
            recent_events: Arc::new(RwLock::new(Vec::new())),
            config,
        };

        Self {
            state,
            handle: None,
        }
    }

    /// Start the monitoring server
    pub async fn start(&mut self) -> Result<(), MonitoringError> {
        let state = self.state.clone();
        let addr = self.state.config.addr;

        // Build router
        let mut app = Router::new()
            .route("/events/ws", get(websocket_handler))
            .route("/events/sse", get(sse_handler))
            .route("/events/history", get(history_handler))
            .route("/health", get(health_handler))
            .with_state(state.clone());

        // Add CORS if enabled
        if state.config.enable_cors {
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);
            app = app.layer(cors);
        }

        info!(addr = %addr, "Starting monitoring server");

        // Spawn server task
        let handle = tokio::spawn(async move {
            // Start event buffer task (await the async fn so the task is spawned
            // now — previously the un-awaited future meant the buffer didn't
            // start until the server below stopped).
            let buffer_task = Self::start_event_buffer(state.clone()).await;

            // Start HTTP server - handle bind errors gracefully
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app).await {
                        tracing::warn!("Monitoring server error: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to bind monitoring server on {}: {} (continuing without monitoring)", addr, e);
                }
            }

            let _ = buffer_task.await;
        });

        self.handle = Some(handle);

        info!(addr = %addr, "Monitoring server started");
        Ok(())
    }

    /// Background task to buffer recent events
    async fn start_event_buffer(state: MonitoringState) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut subscriber = state.event_bus.subscribe();

            while let Some(event) = subscriber.next().await {
                let mut events = state.recent_events.write().await;
                events.push(event.clone());

                // Keep only recent events
                if events.len() > state.config.buffer_size {
                    let drain_count = events.len() - state.config.buffer_size;
                    events.drain(0..drain_count);
                }
            }
        })
    }

    /// Stop the monitoring server
    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            info!("Monitoring server stopped");
        }
    }
}

/// WebSocket handler
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<MonitoringState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

/// Handle WebSocket connection
async fn handle_websocket(socket: WebSocket, state: MonitoringState) {
    let (mut sender, _receiver) = socket.split();

    debug!("WebSocket client connected");

    // Subscribe to all events
    let mut subscriber = state.event_bus.subscribe();

    // Stream events to client
    while let Some(event) = subscriber.next().await {
        match serde_json::to_string(&event) {
            Ok(json) => {
                if sender.send(Message::Text(json)).await.is_err() {
                    debug!("WebSocket client disconnected");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize event");
            }
        }
    }
}

/// Server-Sent Events handler
async fn sse_handler(
    State(state): State<MonitoringState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    debug!("SSE client connected");

    let subscriber = state.event_bus.subscribe();
    let stream = subscriber.filter_map(|event| async move {
        match serde_json::to_string(&event) {
            Ok(json) => Some(Ok(SseEvent::default().data(json))),
            Err(e) => {
                error!(error = %e, "Failed to serialize event");
                None
            }
        }
    });

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

/// Event history handler (JSON dump)
async fn history_handler(
    State(state): State<MonitoringState>,
) -> Result<axum::Json<Vec<Event>>, StatusCode> {
    let events = state.recent_events.read().await;
    Ok(axum::Json(events.clone()))
}

/// Health check handler
async fn health_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "ajna-monitoring"
    }))
}

/// Query parameters for filtering history
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Filter by topic
    pub topic: Option<String>,

    /// Filter by agent ID
    pub agent_id: Option<String>,

    /// Limit number of results
    pub limit: Option<usize>,
}

/// Monitoring errors
#[derive(Debug, thiserror::Error)]
pub enum MonitoringError {
    /// Failed to bind server
    #[error("Failed to bind server: {0}")]
    BindError(String),

    /// Failed to start server
    #[error("Failed to start server: {0}")]
    StartError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_server_creation() {
        let config = MonitoringConfig::default();
        let event_bus = Arc::new(EventBus::new(100));
        let server = MonitoringServer::new(config, event_bus);

        assert!(server.handle.is_none());
    }

    #[tokio::test]
    async fn test_monitoring_config_default() {
        let config = MonitoringConfig::default();
        assert_eq!(config.buffer_size, 1000);
        assert!(config.enable_cors);
    }
}
