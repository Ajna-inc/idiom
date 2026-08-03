//! Ajna DIDComm Mediator Server
//!
//! Usage:
//!   STORAGE_KEY=<key> cargo run -p mediator_server
//!
//! Environment variables:
//!   MEDIATOR_HOST              - Bind host (default: 0.0.0.0)
//!   MEDIATOR_PORT              - Bind port (default: 3000)
//!   MEDIATOR_ENDPOINT          - Public endpoint URL
//!   MEDIATOR_LABEL             - Agent label
//!   MEDIATOR_AUTO_GRANT        - Auto-grant mediation (default: true)
//!   MEDIATOR_FORWARDING_STRATEGY - queue-only | queue-and-live-delivery
//!   DATABASE_URL               - Askar database URL (default: sqlite://./mediator.db)
//!   STORAGE_KEY                - Askar encryption key (required)
//!   RUST_LOG                   - Log level (default: info)

use mediator_server::{app::MediatorApp, config::MediatorConfig, routes::build_router};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load configuration
    let config = MediatorConfig::from_env().map_err(|e| {
        tracing::error!("Configuration error: {}", e);
        e
    })?;

    tracing::info!(
        endpoint = %config.endpoint,
        auto_grant = config.auto_grant,
        forwarding = ?config.forwarding_strategy,
        database = %config.database_url,
        "Starting Ajna DIDComm Mediator"
    );

    // Build the app
    let app = Arc::new(MediatorApp::build(&config).await?);

    tracing::info!(
        did = %app.mediator_did,
        label = %app.label,
        "Mediator initialized"
    );

    // NOTE: the actual pickup-queue TTL cleanup runs inside
    // `MediatorApp::build` (see the spawned "[Pickup TTL] cleanup task"),
    // governed by PICKUP_MESSAGE_MAX_AGE_SECS / PICKUP_CLEANUP_INTERVAL_SECS.
    // `PICKUP_MESSAGE_TTL_DAYS` is retained only as a startup log field for
    // operators; it does not drive any cleanup on its own.
    let ttl_days: u64 = std::env::var("PICKUP_MESSAGE_TTL_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);

    // Build router
    let router = build_router(app);

    // Bind and serve
    let bind_addr = config.bind_addr();
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, ttl_days = ttl_days, "Listening");

    // Graceful shutdown on SIGTERM/SIGINT
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Mediator server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C"),
        _ = terminate => tracing::info!("Received SIGTERM"),
    }

    // Drain period: let in-flight requests complete
    tracing::info!("Draining in-flight requests (5s)...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
}
