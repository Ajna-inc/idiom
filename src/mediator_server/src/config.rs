//! Configuration for the mediator server.
//!
//! All configuration is read from environment variables.

use protocol_coordinate_mediation::ForwardingStrategy;

/// Mediator server configuration
#[derive(Debug, Clone)]
pub struct MediatorConfig {
    /// Bind host (default: 0.0.0.0)
    pub host: String,
    /// Bind port (default: 3000)
    pub port: u16,
    /// Public endpoint URL (default: http://localhost:3000)
    pub endpoint: String,
    /// Agent label (default: Ajna DIDComm Mediator)
    pub label: String,
    /// Auto-grant mediation requests (default: true)
    pub auto_grant: bool,
    /// Forwarding strategy (default: QueueAndLiveDelivery)
    pub forwarding_strategy: ForwardingStrategy,
    /// Direct routing mode (default: true)
    ///
    /// When true, mediation grants return empty `routing_keys`, and the mediator
    /// routes incoming authcrypt JWEs by inspecting the JWE `kid` / `skid` headers
    /// against the keylist — matching Aries TS behavior. This eliminates the Forward
    /// envelope round-trip and enables true return-route (inline response in the
    /// same HTTP request).
    ///
    /// When false, grants include the mediator's DID as a routing key, and agents
    /// wrap messages in Forward envelopes addressed to the mediator (legacy/RFC0211).
    pub direct_routing: bool,
    /// Database URL for Askar (default: sqlite://./mediator.db)
    pub database_url: String,
    /// Askar encryption key (required)
    pub storage_key: String,
    /// Max age (seconds) for queued pickup messages. Older messages are
    /// deleted by the periodic TTL task. Default: 7 days.
    pub pickup_message_max_age_secs: u64,
    /// Interval (seconds) between full pickup-queue TTL sweeps. Default: 1 hour.
    pub pickup_cleanup_interval_secs: u64,
    /// Push-notification backend (FCM, webhook, or none).
    pub push_notifications: PushNotificationConfig,
}

/// Push-notification configuration. Mirrors credo-ts's `config.pushNotifications`
/// shape: either a Firebase service-account path (preferred) or a webhook URL.
/// If both are unset, push notifications are disabled.
#[derive(Debug, Clone, Default)]
pub struct PushNotificationConfig {
    /// Path to the Google service-account JSON. Enables FCM HTTP v1 push.
    pub firebase_credentials_path: Option<String>,
    /// Inline Google service-account JSON (e.g. from a secret env var).
    /// Preferred over the file path — no on-disk credentials needed.
    pub firebase_credentials_json: Option<String>,
    /// HTTP URL to POST `{connectionId, deviceToken, devicePlatform}` to.
    /// Mutually exclusive with `firebase_credentials_path` — if both set,
    /// FCM wins.
    pub webhook_url: Option<String>,
    /// Visible title for the notification body. Defaults to "New message".
    pub title: String,
    /// Visible body text. Defaults to a generic message.
    pub body: String,
}

impl PushNotificationConfig {
    pub fn from_env() -> Self {
        Self {
            firebase_credentials_path: std::env::var("FIREBASE_CREDENTIALS_JSON_PATH").ok(),
            firebase_credentials_json: std::env::var("FIREBASE_CREDENTIALS_JSON")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            webhook_url: std::env::var("PUSH_NOTIFICATION_WEBHOOK_URL").ok(),
            title: std::env::var("PUSH_NOTIFICATION_TITLE")
                .unwrap_or_else(|_| "New message".to_string()),
            body: std::env::var("PUSH_NOTIFICATION_BODY")
                .unwrap_or_else(|_| "You have a new encrypted message".to_string()),
        }
    }

    /// True iff at least one backend is configured.
    pub fn enabled(&self) -> bool {
        self.firebase_credentials_path.is_some()
            || self.firebase_credentials_json.is_some()
            || self.webhook_url.is_some()
    }
}

impl MediatorConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, String> {
        let host = std::env::var("MEDIATOR_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = std::env::var("MEDIATOR_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .map_err(|e| format!("Invalid MEDIATOR_PORT: {}", e))?;
        let endpoint = std::env::var("MEDIATOR_ENDPOINT")
            .unwrap_or_else(|_| format!("http://localhost:{}", port));
        let label =
            std::env::var("MEDIATOR_LABEL").unwrap_or_else(|_| "Ajna DIDComm Mediator".to_string());
        let auto_grant = std::env::var("MEDIATOR_AUTO_GRANT")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let forwarding_strategy = ForwardingStrategy::from_str_lossy(
            &std::env::var("MEDIATOR_FORWARDING_STRATEGY")
                .unwrap_or_else(|_| "queue-and-live-delivery".to_string()),
        );
        let direct_routing = std::env::var("MEDIATOR_DIRECT_ROUTING")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let mut database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://./mediator.db".to_string());

        // Append connection pool config to PostgreSQL URL if not already specified.
        // Askar's SQLx backend reads ?max_connections=N&min_connections=N from the URL.
        if database_url.starts_with("postgres") && !database_url.contains("max_connections") {
            let max_pool =
                std::env::var("DATABASE_MAX_POOL_SIZE").unwrap_or_else(|_| "32".to_string());
            let min_pool =
                std::env::var("DATABASE_MIN_POOL_SIZE").unwrap_or_else(|_| "5".to_string());
            let sep = if database_url.contains('?') { "&" } else { "?" };
            database_url = format!(
                "{}{}max_connections={}&min_connections={}",
                database_url, sep, max_pool, min_pool
            );
        }

        let storage_key = std::env::var("STORAGE_KEY")
            .map_err(|_| "STORAGE_KEY environment variable is required".to_string())?;

        let pickup_message_max_age_secs = std::env::var("PICKUP_MESSAGE_MAX_AGE_SECS")
            .unwrap_or_else(|_| (7 * 86_400).to_string())
            .parse()
            .unwrap_or(7 * 86_400);
        let pickup_cleanup_interval_secs = std::env::var("PICKUP_CLEANUP_INTERVAL_SECS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);

        let push_notifications = PushNotificationConfig::from_env();

        Ok(Self {
            host,
            port,
            endpoint,
            label,
            auto_grant,
            forwarding_strategy,
            direct_routing,
            database_url,
            storage_key,
            pickup_message_max_age_secs,
            pickup_cleanup_interval_secs,
            push_notifications,
        })
    }

    /// Socket address for binding
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
