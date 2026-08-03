use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::domain::instance::WorkflowInstanceData;
use crate::domain::template::{ActionDef, WorkflowTemplate};
use crate::error::{Result, WorkflowError};

/// Context passed to an action handler during execution.
pub struct ActionContext {
    pub template: WorkflowTemplate,
    pub instance: WorkflowInstanceData,
    pub action: ActionDef,
    pub input: Option<serde_json::Value>,
}

/// Result returned by an action handler.
#[derive(Debug, Clone, Default)]
pub struct ActionResult {
    /// Outputs stored in instance.artifacts.
    pub artifacts: Option<serde_json::Value>,
    /// Merged into instance.context.
    pub context_merge: Option<serde_json::Value>,
    /// Stored in history entry.
    pub message_id: Option<String>,
}

/// Trait for implementing workflow action handlers.
#[async_trait]
pub trait WorkflowActionHandler: Send + Sync {
    fn type_uri(&self) -> &str;
    async fn execute(&self, ctx: ActionContext) -> Result<ActionResult>;
}

/// Registry of action handlers keyed by typeURI.
///
/// Handlers are held behind an `RwLock` so credential/proof action handlers —
/// which need the agent's exchange services + sender and thus only exist after
/// the AnonCreds module is set up — can be registered post-construction via
/// `&self` (through the `Arc<ActionRegistry>` held by `WorkflowService`).
pub struct ActionRegistry {
    handlers: RwLock<HashMap<String, Arc<dyn WorkflowActionHandler>>>,
    pub timeout: Duration,
}

impl ActionRegistry {
    pub fn new() -> Self {
        let registry = Self {
            handlers: RwLock::new(HashMap::new()),
            timeout: Duration::from_secs(15),
        };
        // Register built-in actions
        registry.register(Arc::new(LocalStateSetAction));
        registry
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Register (or replace) a handler by its typeURI. Takes `&self` so it can
    /// be called after the registry is wrapped in `Arc`.
    pub fn register(&self, handler: Arc<dyn WorkflowActionHandler>) {
        self.handlers
            .write()
            .unwrap()
            .insert(handler.type_uri().to_string(), handler);
    }

    pub async fn execute(
        &self,
        action_def: &ActionDef,
        ctx: ActionContext,
    ) -> Result<ActionResult> {
        // Clone the Arc out and release the lock before awaiting.
        let handler = {
            self.handlers
                .read()
                .unwrap()
                .get(&action_def.type_uri)
                .cloned()
        }
        .ok_or_else(|| WorkflowError::ActionHandlerNotFound(action_def.type_uri.clone()))?;

        // Execute with timeout
        match tokio::time::timeout(self.timeout, handler.execute(ctx)).await {
            Ok(result) => result,
            Err(_) => Err(WorkflowError::ActionTimeout(self.timeout)),
        }
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in action: merges staticInput.merge into instance context.
pub struct LocalStateSetAction;

impl LocalStateSetAction {
    pub const TYPE_URI: &'static str = "https://didcomm.org/workflow/actions/state:set@1";
}

#[async_trait]
impl WorkflowActionHandler for LocalStateSetAction {
    fn type_uri(&self) -> &str {
        Self::TYPE_URI
    }

    async fn execute(&self, ctx: ActionContext) -> Result<ActionResult> {
        // Mirror the reference plugin's state:set: start from staticInput
        // (accepting the legacy `{ "merge": {...} }` wrapper when it is the sole
        // key), then overlay the whole advance `input` — input overrides static.
        // The entire input object is merged (not a `.form` sub-key), so bare
        // context paths (e.g. `student_id`, `clr`) populate as the attribute
        // plans expect.
        let mut merged = serde_json::Map::new();

        if let Some(static_input) = &ctx.action.static_input {
            let is_legacy_wrapper = static_input.get("merge").is_some()
                && static_input
                    .as_object()
                    .map(|o| o.len() == 1)
                    .unwrap_or(false);
            let base = if is_legacy_wrapper {
                static_input.get("merge").unwrap()
            } else {
                static_input
            };
            if let Some(obj) = base.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }

        if let Some(obj) = ctx.input.as_ref().and_then(|v| v.as_object()) {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }

        let context_merge = if merged.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(merged))
        };

        Ok(ActionResult {
            artifacts: None,
            context_merge,
            message_id: None,
        })
    }
}
