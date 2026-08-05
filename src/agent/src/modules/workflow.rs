use std::sync::Arc;

use protocol_workflow::{
    actions::registry::{ActionRegistry, WorkflowActionHandler},
    domain::role::WorkflowRole,
    domain::template::WorkflowTemplate,
    handlers::{
        AdvanceHandler, CancelHandler, CompleteHandler, DiscoverHandler, FetchTemplateHandler,
        PauseHandler, ProblemReportHandler, PublishTemplateHandler, ResumeHandler, StartHandler,
        StatusHandler, TemplateHandler,
    },
    queue::command_queue::{CommandQueueConfig, JobHandler, PersistentCommandQueue},
    repository::{
        command_record::CommandType, command_repository::WorkflowCommandRepository,
        instance_record::WorkflowInstanceRecord, instance_repository::WorkflowInstanceRepository,
        template_record::WorkflowTemplateRecord, template_repository::WorkflowTemplateRepository,
    },
    services::{AdvanceOptions, StartOptions, StatusOptions, StatusResponse, WorkflowService},
    AdvanceMessage, PublishTemplateMessage, StartMessage, WorkflowError,
};

use std::future::Future;
use std::pin::Pin;
use tokio::task::JoinHandle;

/// Delays (ms) between the extra idempotent re-deliveries of an auto-advance
/// message to the peer. Spaced a few seconds apart to survive the window where
/// the peer is still processing an earlier transition. See `try_auto_advance`.
const AUTO_ADVANCE_RESEND_DELAYS_MS: [u64; 2] = [1500, 3500];

/// Callback the agent installs so the module can push protocol messages to a
/// connection's peer. Args: `(connection_id, message_type_uri, body_fields)`.
/// The agent side owns the DIDComm packing (wire shape + v1/v2), so the module
/// stays transport-agnostic. Reusable for every workflow message.
pub type WorkflowSendCallback = Arc<
    dyn Fn(
            String,
            String,
            serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

pub struct WorkflowModule {
    /// Shared repos + action registry, held so the service can be (re)built with
    /// the agent's event bus in `register`.
    template_repo: Arc<WorkflowTemplateRepository>,
    instance_repo: Arc<WorkflowInstanceRepository>,
    action_registry: Arc<ActionRegistry>,
    /// Lazily-built (or eagerly-built) workflow service. When composed into an
    /// agent, [`AgentModule::register`] (re)builds it with the event bus.
    service: once_cell::sync::OnceCell<Arc<WorkflowService>>,
    command_queue: Arc<PersistentCommandQueue>,
    worker_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Set by the agent via `set_send_callback`; used by `start`/`advance` to
    /// notify the peer when we drive the workflow as Coordinator.
    send_callback: Arc<tokio::sync::RwLock<Option<WorkflowSendCallback>>>,
}

impl WorkflowModule {
    /// Config-only constructor (no agent deps). The workflow service is built
    /// (with the agent's event bus) when the module is registered with an agent;
    /// stand-alone callers get a bus-less service on first `svc()` access.
    pub fn new() -> Self {
        Self::new_with_event_bus(None, None)
    }

    /// Create a workflow module, optionally pre-wiring an event bus + agent id.
    /// When composed into an agent, `register` rebuilds the service with the
    /// agent's bus regardless of what is passed here.
    pub fn new_with_event_bus(
        event_bus: Option<Arc<agent_events::EventBus>>,
        agent_id: Option<String>,
    ) -> Self {
        let template_repo = Arc::new(WorkflowTemplateRepository::new());
        let instance_repo = Arc::new(WorkflowInstanceRepository::new());
        let command_repo = Arc::new(WorkflowCommandRepository::new());
        let action_registry = Arc::new(ActionRegistry::new());

        let service = once_cell::sync::OnceCell::new();
        if let (Some(bus), Some(id)) = (event_bus, agent_id) {
            let svc = Arc::new(
                WorkflowService::new(
                    template_repo.clone(),
                    instance_repo.clone(),
                    action_registry.clone(),
                )
                .with_event_bus(bus, id),
            );
            let _ = service.set(svc);
        }

        let command_queue = Arc::new(PersistentCommandQueue::new(
            command_repo,
            CommandQueueConfig::default(),
        ));

        Self {
            template_repo,
            instance_repo,
            action_registry,
            service,
            command_queue,
            worker_handle: std::sync::Mutex::new(None),
            send_callback: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Build (once) or return the workflow service. When neither `register` nor
    /// `new_with_event_bus` supplied a bus, a bus-less service is built lazily.
    fn svc(&self) -> &Arc<WorkflowService> {
        self.service.get_or_init(|| {
            Arc::new(WorkflowService::new(
                self.template_repo.clone(),
                self.instance_repo.clone(),
                self.action_registry.clone(),
            ))
        })
    }

    /// Rebuild the service with the agent's event bus. Idempotent — a no-op if
    /// the service was already built (e.g. via `new_with_event_bus`).
    fn init_service_with_bus(&self, event_bus: Arc<agent_events::EventBus>, agent_id: String) {
        let _ = self.service.set(Arc::new(
            WorkflowService::new(
                self.template_repo.clone(),
                self.instance_repo.clone(),
                self.action_registry.clone(),
            )
            .with_event_bus(event_bus, agent_id),
        ));
    }

    /// Retained for callers that already build the module then bolt on
    /// the bus afterwards (eg. `setup_*` helpers).
    pub fn with_event_bus(self, event_bus: Arc<agent_events::EventBus>, agent_id: String) -> Self {
        self.init_service_with_bus(event_bus, agent_id);
        self
    }

    /// Create all DIDComm message handlers for this protocol.
    /// Register an additional workflow action handler (e.g. issue-credential,
    /// present-proof) after construction. Used by the agent to wire credential
    /// actions once the AnonCreds module + sender are available.
    pub fn register_action(&self, handler: Arc<dyn WorkflowActionHandler>) {
        self.svc().action_registry().register(handler);
    }

    /// Install the agent's DIDComm send callback so `start`/`advance` can notify
    /// the peer. Called once during agent initialization.
    pub async fn set_send_callback(&self, cb: WorkflowSendCallback) {
        *self.send_callback.write().await = Some(cb);
    }

    /// Best-effort push of a workflow protocol message to a connection's peer.
    async fn notify_peer(&self, connection_id: &str, type_uri: &str, body: serde_json::Value) {
        let cb = { self.send_callback.read().await.clone() };
        if let Some(cb) = cb {
            if let Err(e) = cb(connection_id.to_string(), type_uri.to_string(), body).await {
                tracing::warn!(target: "workflow", "notify peer ({type_uri}) failed: {e}");
            }
        }
    }

    pub fn create_handlers(&self) -> Vec<Arc<dyn didcomm::messaging::handlers::MessageHandler>> {
        let handlers: Vec<Arc<dyn didcomm::messaging::handlers::MessageHandler>> = vec![
            Arc::new(StartHandler::new(
                self.command_queue.clone(),
                self.svc().clone(),
            )),
            Arc::new(AdvanceHandler::new(self.command_queue.clone())),
            Arc::new(StatusHandler::new(self.svc().clone())),
            Arc::new(PauseHandler::new(self.command_queue.clone())),
            Arc::new(ResumeHandler::new(self.command_queue.clone())),
            Arc::new(CancelHandler::new(self.command_queue.clone())),
            Arc::new(CompleteHandler::new(self.command_queue.clone())),
            Arc::new(ProblemReportHandler::new()),
            Arc::new(PublishTemplateHandler::new(self.svc().clone())),
            Arc::new(DiscoverHandler::new(self.svc().clone())),
            Arc::new(FetchTemplateHandler::new(self.svc().clone())),
            Arc::new(TemplateHandler::new(self.svc().clone())),
        ];
        handlers
    }

    /// Start the command queue background worker.
    pub fn start_worker(&self) {
        let service = self.svc().clone();

        let handler: JobHandler = Arc::new(move |cmd_record| {
            let svc = service.clone();
            Box::pin(async move {
                match cmd_record.cmd {
                    CommandType::Start => {
                        let start_msg: protocol_workflow::StartMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;

                        let opts = StartOptions {
                            template_id: start_msg.template_id,
                            template_version: start_msg.template_version,
                            instance_id: start_msg.instance_id,
                            connection_id: cmd_record.connection_id,
                            participants: start_msg.participants,
                            context: start_msg.context,
                            role: WorkflowRole::Processor,
                        };
                        svc.start(opts).await?;
                    }
                    CommandType::Advance => {
                        let advance_msg: protocol_workflow::AdvanceMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;

                        let opts = AdvanceOptions {
                            instance_id: advance_msg.instance_id,
                            event: advance_msg.event,
                            idempotency_key: advance_msg.idempotency_key,
                            input: advance_msg.input,
                        };
                        // Peer-received advance = mirror path: tolerate action
                        // failures so a holder that can't run a coordinator-only
                        // action still advances its mirrored state (Python parity).
                        svc.advance_mirror(opts).await?;
                    }
                    CommandType::Pause => {
                        let pause_msg: protocol_workflow::PauseMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;
                        svc.pause(&pause_msg.instance_id, pause_msg.reason.as_deref())
                            .await?;
                    }
                    CommandType::Resume => {
                        let resume_msg: protocol_workflow::ResumeMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;
                        svc.resume(&resume_msg.instance_id, resume_msg.reason.as_deref())
                            .await?;
                    }
                    CommandType::Cancel => {
                        let cancel_msg: protocol_workflow::CancelMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;
                        svc.cancel(&cancel_msg.instance_id, cancel_msg.reason.as_deref())
                            .await?;
                    }
                    CommandType::Complete => {
                        let complete_msg: protocol_workflow::CompleteMessage =
                            serde_json::from_value(cmd_record.payload)
                                .map_err(|e| WorkflowError::Serialization(e.to_string()))?;
                        svc.complete(&complete_msg.instance_id, complete_msg.reason.as_deref())
                            .await?;
                    }
                }
                Ok(())
            })
        });

        let handle = self.command_queue.start_worker(handler);
        if let Ok(mut guard) = self.worker_handle.lock() {
            *guard = Some(handle);
        }
    }

    /// Shutdown the command queue worker.
    pub fn shutdown(&self) {
        self.command_queue.shutdown();
    }

    // ─── Public API ─────────────────────────────────────────────────────

    pub async fn publish_template(
        &self,
        template: WorkflowTemplate,
    ) -> Result<WorkflowTemplateRecord, WorkflowError> {
        self.svc().publish_template(template).await
    }

    pub async fn start(&self, opts: StartOptions) -> Result<WorkflowInstanceRecord, WorkflowError> {
        let is_coordinator = opts.role == WorkflowRole::Coordinator;
        let connection_id = opts.connection_id.clone();
        let rec = self.svc().start(opts).await?;

        // As the initiating party (Coordinator) on a connection, drive the
        // peer's mirror: publish the template it needs, then send `start`. The
        // command-queue (inbound) path uses `service.start` directly and never
        // reaches here, so there's no echo loop.
        if is_coordinator {
            if let Some(conn_id) = connection_id {
                let d = &rec.data;
                // Push the full template so the peer doesn't have to fetch it.
                if let Ok(Some(trec)) = self
                    .svc()
                    .get_template(&d.template_id, Some(&d.template_version))
                    .await
                {
                    let publish = PublishTemplateMessage {
                        template: trec.template,
                        mode: None,
                    };
                    if let Ok(body) = serde_json::to_value(&publish) {
                        self.notify_peer(&conn_id, PublishTemplateMessage::TYPE, body)
                            .await;
                    }
                }
                let start_msg = StartMessage {
                    template_id: d.template_id.clone(),
                    template_version: Some(d.template_version.clone()),
                    instance_id: Some(d.instance_id.clone()),
                    connection_id: Some(conn_id.clone()),
                    participants: Some(d.participants.clone()),
                    context: Some(d.context.clone()),
                    allow_discover: Some(true),
                    template_hash: None,
                };
                if let Ok(body) = serde_json::to_value(&start_msg) {
                    self.notify_peer(&conn_id, StartMessage::TYPE, body).await;
                }
            }
        }
        Ok(rec)
    }

    pub async fn advance(
        &self,
        opts: AdvanceOptions,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        let advance_msg = AdvanceMessage {
            instance_id: opts.instance_id.clone(),
            event: opts.event.clone(),
            idempotency_key: opts.idempotency_key.clone(),
            input: opts.input.clone(),
        };
        let rec = self.svc().advance(opts).await?;
        // Relay the operator's transition to the peer so its mirror advances.
        if let Some(conn_id) = rec.data.connection_id.clone() {
            if let Ok(body) = serde_json::to_value(&advance_msg) {
                self.notify_peer(&conn_id, AdvanceMessage::TYPE, body).await;
            }
        }
        Ok(rec)
    }

    /// Auto-advance every active workflow instance on `connection_id` by `event`,
    /// ignoring instances where `event` isn't a valid transition from their
    /// current state.
    ///
    /// **LOCAL ONLY — no DIDComm `WorkflowAdvance` is sent to the peer**, exactly
    /// matching the Python plugin's `auto_advance_by_connection` (see its
    /// docstring: "Both sides independently observe the same credential/proof
    /// state changes and auto-advance their own workflow instances. This
    /// ensures interoperability."). The verifier fires
    /// `presentation_received` and the prover fires `verified_ack` off their own
    /// present-proof state — each advances its own mirror. Relaying here instead
    /// would emit a second `workflow/1.0/advance` on the same thread that the
    /// peer's command queue dedups (drops) against the operator's `request_proof`.
    /// So this calls `service.advance` directly (no `notify_peer`).
    pub async fn advance_by_connection(&self, connection_id: &str, event: &str) {
        let instances = match self
            .svc()
            .instance_repo()
            .find_by_connection(connection_id)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "advance_by_connection({connection_id}, {event}): lookup failed: {e}"
                );
                return;
            }
        };
        for inst in instances {
            let instance_id = inst.instance_id().to_string();
            // Distinct idempotency key per (event, instance) — matches the Python
            // plugin's `auto:{event}:{instance_id}`. Lets the peer's advance()
            // dedup our re-deliveries idempotently.
            let idem = format!("auto:{event}:{instance_id}");
            let opts = AdvanceOptions {
                instance_id: instance_id.clone(),
                event: event.to_string(),
                idempotency_key: Some(idem.clone()),
                input: None,
            };
            match self.advance(opts).await {
                Ok(rec) => {
                    tracing::info!(
                        "auto-advanced workflow {} on '{}' -> '{}'",
                        rec.instance_id(),
                        event,
                        rec.state()
                    );
                    // Re-deliver the advance to the peer a couple more times, a
                    // few seconds apart. The peer may still be processing the
                    // operator's earlier `request_proof` when our first delivery
                    // lands (its instance is at `start`, so the transition is
                    // rejected / raced). Some agents auto-advance and retry (3× / 2s)
                    // to survive exactly this window; being much faster, idiom must
                    // do the same. Idempotent via `idempotency_key`, so the peer
                    // applies it once and ignores the rest.
                    if let Some(conn_id) = rec.data.connection_id.clone() {
                        let advance_msg = AdvanceMessage {
                            instance_id: instance_id.clone(),
                            event: event.to_string(),
                            idempotency_key: Some(idem.clone()),
                            input: None,
                        };
                        if let Ok(body) = serde_json::to_value(&advance_msg) {
                            let cb_slot = self.send_callback.clone();
                            tokio::spawn(async move {
                                for delay_ms in AUTO_ADVANCE_RESEND_DELAYS_MS {
                                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                        .await;
                                    let cb = { cb_slot.read().await.clone() };
                                    if let Some(cb) = cb {
                                        let _ = cb(
                                            conn_id.clone(),
                                            AdvanceMessage::TYPE.to_string(),
                                            body.clone(),
                                        )
                                        .await;
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => tracing::debug!(
                    "auto-advance {} on '{}' skipped: {}",
                    inst.instance_id(),
                    event,
                    e
                ),
            }
        }
    }

    pub async fn status(&self, opts: StatusOptions) -> Result<StatusResponse, WorkflowError> {
        self.svc().status(opts).await
    }

    pub async fn pause(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().pause(instance_id, reason).await
    }

    pub async fn resume(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().resume(instance_id, reason).await
    }

    pub async fn cancel(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().cancel(instance_id, reason).await
    }

    pub async fn complete(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().complete(instance_id, reason).await
    }

    pub async fn list_templates(&self) -> Result<Vec<WorkflowTemplateRecord>, WorkflowError> {
        self.svc().list_templates().await
    }

    pub async fn get_template(
        &self,
        template_id: &str,
        version: Option<&str>,
    ) -> Result<Option<WorkflowTemplateRecord>, WorkflowError> {
        self.svc().get_template(template_id, version).await
    }

    pub async fn get_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<WorkflowInstanceRecord>, WorkflowError> {
        self.svc().get_instance(instance_id).await
    }

    pub async fn list_instances(&self) -> Result<Vec<WorkflowInstanceRecord>, WorkflowError> {
        self.svc().list_instances().await
    }

    /// Delete every version of a template (`id` may be a template_id or a
    /// record id). Returns the number of records removed.
    pub async fn delete_template(&self, id: &str) -> Result<usize, WorkflowError> {
        self.svc().delete_template(id).await
    }

    /// Shallow-merge a patch into an instance's context (operator-side update;
    /// does not drive the FSM).
    pub async fn update_context(
        &self,
        instance_id: &str,
        patch: serde_json::Value,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().update_context(instance_id, patch).await
    }

    /// Shallow-merge artifacts into an instance (operator-side update; does
    /// not drive the FSM).
    pub async fn append_artifacts(
        &self,
        instance_id: &str,
        artifacts: serde_json::Value,
    ) -> Result<WorkflowInstanceRecord, WorkflowError> {
        self.svc().append_artifacts(instance_id, artifacts).await
    }
}

impl Default for WorkflowModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl agent_module::AgentModule for WorkflowModule {
    fn name(&self) -> &str {
        "workflow"
    }

    /// Register the workflow protocol handlers and wire the outbound send
    /// callback. Preserves the exact behavior of the previous agent-level
    /// registration: handlers from `create_handlers()`, then a send callback
    /// that packs an Aries `@type` + `body` envelope and pushes it over the
    /// connection via the shared [`agent_module::OutboundSender`] (which owns
    /// connection lookup + the DIDComm resolve/pack/forward path).
    async fn register(&self, ctx: &agent_module::ModuleContext) -> agent_module::ModuleResult {
        // Build the workflow service wired to the agent's event bus so
        // `workflow.state_changed` / `status_changed` / `completed` fire on
        // every advance. Idempotent if a bus was already supplied.
        self.init_service_with_bus(ctx.events.clone(), ctx.label.clone());

        {
            let mut registry = ctx.handler_registry.write().await;
            for handler in self.create_handlers() {
                registry.register(handler);
            }
        }
        tracing::debug!("✓ [WorkflowModule] Workflow handlers registered");

        // Wire the workflow module's outbound send so `start`/`advance` push
        // protocol messages to the peer's mirror. The module stays
        // transport-agnostic; the DIDComm wire shape (Aries `@type` + a `body`
        // sub-object, with v1/v2 handled by the envelope service) is owned here.
        let sender = ctx.sender.clone();
        self.set_send_callback(Arc::new(move |conn_id, type_uri, body| {
            let sender = sender.clone();
            Box::pin(async move {
                // Correlate the DIDComm thread by the workflow instance_id
                // (Aries/ACA-Py convention): peers
                // StartHandler — match `~thread.thid == body.instance_id`. Every
                // workflow message body carries instance_id; without an explicit
                // `~thread`, the peer falls back to our random `@id` and logs a
                // "start correlation mismatch (thid != instance_id)".
                let thid = body
                    .get("instance_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let mut message = serde_json::json!({
                    "@type": type_uri,
                    "@id": uuid::Uuid::new_v4().to_string(),
                    "body": body,
                });
                if let Some(thid) = thid {
                    message["~thread"] = serde_json::json!({ "thid": thid });
                }
                sender
                    .send_via_connection(&conn_id, &message)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            })
        }))
        .await;
        tracing::debug!("✓ [WorkflowModule] Workflow send callback wired");

        // Start the command queue background worker (previously done later in
        // `Agent::initialize`; keeping it here means the module fully owns its
        // lifecycle).
        self.start_worker();
        tracing::debug!("✓ [WorkflowModule] Workflow command queue worker started");
        Ok(())
    }
}

/// Typed, decoupled access to the [`WorkflowModule`] from an [`crate::Agent`].
pub trait WorkflowExt {
    fn workflow_module(&self) -> Option<std::sync::Arc<WorkflowModule>>;
}

impl WorkflowExt for crate::Agent {
    fn workflow_module(&self) -> Option<std::sync::Arc<WorkflowModule>> {
        self.module::<WorkflowModule>()
    }
}
