use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tracing;

use crate::actions::registry::{ActionContext, ActionRegistry, ActionResult};
use crate::domain::instance::{
    InstanceHistoryItem, InstanceStatus, Participant, WorkflowInstanceData,
};
use crate::domain::policy::PolicyMode;
use crate::domain::role::WorkflowRole;
use crate::domain::template::{StateType, WorkflowTemplate};
use crate::engine::guard::GuardEvaluator;
use crate::error::{Result, WorkflowError};
use crate::messages::StatusMessage;
use crate::repository::instance_record::WorkflowInstanceRecord;
use crate::repository::instance_repository::WorkflowInstanceRepositoryTrait;
use crate::repository::template_record::{self, WorkflowTemplateRecord};
use crate::repository::template_repository::WorkflowTemplateRepositoryTrait;

const IDEMPOTENCY_HISTORY_LIMIT: usize = 100;

/// Options for starting a workflow instance.
#[derive(Debug, Clone)]
pub struct StartOptions {
    pub template_id: String,
    pub template_version: Option<String>,
    pub instance_id: Option<String>,
    pub connection_id: Option<String>,
    pub participants: Option<HashMap<String, Participant>>,
    pub context: Option<serde_json::Value>,
    pub role: WorkflowRole,
}

/// Options for advancing a workflow instance.
#[derive(Debug, Clone)]
pub struct AdvanceOptions {
    pub instance_id: String,
    pub event: String,
    pub idempotency_key: Option<String>,
    pub input: Option<serde_json::Value>,
}

/// Options for requesting status.
#[derive(Debug, Clone)]
pub struct StatusOptions {
    pub instance_id: String,
    pub include_actions: bool,
    pub include_ui: bool,
    pub ui_profile: Option<String>,
    pub viewer: Option<String>,
}

/// Status response data.
#[derive(Debug, Clone)]
pub struct StatusResponse {
    pub message: StatusMessage,
    pub record: WorkflowInstanceRecord,
}

pub struct WorkflowService {
    template_repo: Arc<dyn WorkflowTemplateRepositoryTrait>,
    instance_repo: Arc<dyn WorkflowInstanceRepositoryTrait>,
    action_registry: Arc<ActionRegistry>,
    /// Per-instance advance lock. `advance` is a load → check-transition →
    /// run-action → save critical section; without serialization a manual
    /// advance and a background/auto advance on the SAME instance interleave,
    /// so one reads a stale state and fails with `NoEnabledTransition` (and the
    /// other's write is lost). A per-instance async mutex makes the section
    /// atomic; different instances never block each other.
    advance_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,
    #[cfg(feature = "events")]
    agent_id: String,
}

impl WorkflowService {
    pub fn new(
        template_repo: Arc<dyn WorkflowTemplateRepositoryTrait>,
        instance_repo: Arc<dyn WorkflowInstanceRepositoryTrait>,
        action_registry: Arc<ActionRegistry>,
    ) -> Self {
        Self {
            template_repo,
            instance_repo,
            action_registry,
            advance_locks: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "events")]
            event_bus: None,
            #[cfg(feature = "events")]
            agent_id: "unknown".to_string(),
        }
    }

    /// Get-or-create the per-instance advance lock (see `advance_locks`).
    fn instance_lock(&self, instance_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.advance_locks.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(instance_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    #[cfg(feature = "events")]
    pub fn with_event_bus(
        mut self,
        event_bus: Arc<agent_events::EventBus>,
        agent_id: String,
    ) -> Self {
        self.event_bus = Some(event_bus);
        self.agent_id = agent_id;
        self
    }

    /// Repository accessors — used by `WorkflowModule::with_event_bus`
    /// when it needs to rebuild a fresh service with the bus wired.
    pub fn template_repo(&self) -> Arc<dyn WorkflowTemplateRepositoryTrait> {
        self.template_repo.clone()
    }
    pub fn instance_repo(&self) -> Arc<dyn WorkflowInstanceRepositoryTrait> {
        self.instance_repo.clone()
    }
    pub fn action_registry(&self) -> Arc<ActionRegistry> {
        self.action_registry.clone()
    }

    // ─── Template Management ────────────────────────────────────────────

    pub async fn publish_template(
        &self,
        template: WorkflowTemplate,
    ) -> Result<WorkflowTemplateRecord> {
        // Validate template structure
        self.validate_template(&template)?;

        // Check for existing template with same id+version (upsert)
        if let Some(mut existing) = self
            .template_repo
            .find_by_template_id_and_version(&template.template_id, Some(&template.version))
            .await?
        {
            existing.template = template.clone();
            existing.hash = template_record::compute_template_hash(&template);
            existing.title = template.title.clone();
            existing.updated_at = Utc::now();
            self.template_repo.update(&existing).await?;
            return Ok(existing);
        }

        let record = WorkflowTemplateRecord::new(template);
        self.template_repo.save(&record).await?;
        Ok(record)
    }

    pub async fn get_template(
        &self,
        template_id: &str,
        version: Option<&str>,
    ) -> Result<Option<WorkflowTemplateRecord>> {
        self.template_repo
            .find_by_template_id_and_version(template_id, version)
            .await
    }

    pub async fn list_templates(&self) -> Result<Vec<WorkflowTemplateRecord>> {
        self.template_repo.find_all().await
    }

    /// Delete every version of a template. `id` may be a `template_id` or a
    /// record id. Returns the number of records removed.
    pub async fn delete_template(&self, id: &str) -> Result<usize> {
        let all = self.template_repo.find_all().await?;
        let mut deleted = 0;
        for rec in all {
            if rec.template_id == id || rec.id == id {
                self.template_repo.delete(&rec.id).await?;
                deleted += 1;
            }
        }
        if deleted == 0 {
            return Err(WorkflowError::TemplateNotFound(id.to_string()));
        }
        Ok(deleted)
    }

    // ─── Instance Lifecycle ─────────────────────────────────────────────

    pub async fn start(&self, opts: StartOptions) -> Result<WorkflowInstanceRecord> {
        // Idempotency: return existing if instance_id matches
        if let Some(ref instance_id) = opts.instance_id {
            if let Some(existing) = self.instance_repo.find_by_instance_id(instance_id).await? {
                return Ok(existing);
            }
        }

        // Load template
        let template_record = self
            .template_repo
            .find_by_template_id_and_version(&opts.template_id, opts.template_version.as_deref())
            .await?
            .ok_or_else(|| WorkflowError::TemplateNotFound(opts.template_id.clone()))?;

        let template = &template_record.template;

        // Check instance policy
        self.check_instance_policy(template, opts.connection_id.as_deref())
            .await?;

        // Find start state
        let start_state = template.start_state().ok_or_else(|| {
            WorkflowError::ValidationFailed("Template has no start state".to_string())
        })?;

        let instance_id = opts
            .instance_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let instance_data = WorkflowInstanceData {
            instance_id,
            template_id: template.template_id.clone(),
            template_version: template.version.clone(),
            connection_id: opts.connection_id,
            participants: opts.participants.unwrap_or_default(),
            state: start_state.name.clone(),
            section: start_state.section.clone(),
            context: opts.context.unwrap_or_else(|| serde_json::json!({})),
            artifacts: serde_json::json!({}),
            status: InstanceStatus::Active,
            history: Vec::new(),
            multiplicity_key_value: None,
            idempotency_keys: Vec::new(),
        };

        let record = WorkflowInstanceRecord::new(instance_data, opts.role);
        self.instance_repo.save(&record).await?;

        #[cfg(feature = "events")]
        self.emit_state_changed(&record, None, "start").await;

        tracing::info!(
            "Started workflow instance {} (template={}, state={})",
            record.instance_id(),
            record.data.template_id,
            record.state()
        );

        Ok(record)
    }

    /// Advance an instance (strict): an action-handler failure aborts the
    /// transition. Used for coordinator/operator-driven advances.
    pub async fn advance(&self, opts: AdvanceOptions) -> Result<WorkflowInstanceRecord> {
        self.advance_inner(opts, false).await
    }

    /// Advance a *mirrored* instance from a peer-received advance: an
    /// action-handler failure is tolerated and the state transition still
    /// commits. Mirrors the Python workflow plugin's
    /// `receive_advance(lenient_actions=True)` — a holder that cannot run a
    /// coordinator-only action (e.g. the verifier's request-presentation) must
    /// still advance its mirrored state to stay in sync.
    pub async fn advance_mirror(&self, opts: AdvanceOptions) -> Result<WorkflowInstanceRecord> {
        self.advance_inner(opts, true).await
    }

    async fn advance_inner(
        &self,
        opts: AdvanceOptions,
        lenient: bool,
    ) -> Result<WorkflowInstanceRecord> {
        // Serialize all advances on this instance. Held across the whole
        // load → check-transition → run-action → save section so a concurrent
        // manual + auto/mirror advance can't read a stale state (which surfaced
        // as spurious `NoEnabledTransition` errors) or clobber each other's
        // write. Per-instance, so other instances proceed in parallel.
        let lock = self.instance_lock(&opts.instance_id);
        let _guard = lock.lock().await;

        let mut record = self
            .instance_repo
            .find_by_instance_id(&opts.instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(opts.instance_id.clone()))?;

        // Validate status
        match record.data.status {
            InstanceStatus::Paused => {
                return Err(WorkflowError::InvalidStatus {
                    status: InstanceStatus::Paused,
                    operation: "advance".to_string(),
                });
            }
            InstanceStatus::Canceled => {
                return Err(WorkflowError::InvalidStatus {
                    status: InstanceStatus::Canceled,
                    operation: "advance".to_string(),
                });
            }
            InstanceStatus::Completed => {
                return Err(WorkflowError::InvalidStatus {
                    status: InstanceStatus::Completed,
                    operation: "advance".to_string(),
                });
            }
            _ => {}
        }

        // Idempotency check
        if let Some(ref key) = opts.idempotency_key {
            if record.data.idempotency_keys.contains(key) {
                return Ok(record);
            }
        }

        // Load template
        let template_record = self
            .template_repo
            .find_by_template_id_and_version(
                &record.data.template_id,
                Some(&record.data.template_version),
            )
            .await?
            .ok_or_else(|| WorkflowError::TemplateNotFound(record.data.template_id.clone()))?;

        let template = &template_record.template;

        // Find enabled transitions
        let transitions = template.transitions_from(&record.data.state, &opts.event);
        let enabled_transition = transitions.iter().find(|t| {
            GuardEvaluator::eval(
                t.guard.as_deref(),
                &record.data.context,
                &record.data.participants,
                &record.data.artifacts,
            )
        });

        let transition = enabled_transition.ok_or_else(|| WorkflowError::NoEnabledTransition {
            state: record.data.state.clone(),
            event: opts.event.clone(),
        })?;

        let prev_state = record.data.state.clone();
        let target_state = transition.to.clone();
        let action_key = transition.action.clone();

        // Execute action if defined
        let mut action_result = ActionResult::default();
        if let Some(ref action_key) = action_key {
            if let Some(action_def) = template.find_action(action_key) {
                let ctx = ActionContext {
                    template: template.clone(),
                    instance: record.data.clone(),
                    action: action_def.clone(),
                    input: opts.input.clone(),
                };
                match self.action_registry.execute(action_def, ctx).await {
                    Ok(res) => action_result = res,
                    // On the mirror path a coordinator-only action (which the
                    // holder can't run) is expected to fail — tolerate it and
                    // still commit the transition, matching Python's
                    // `receive_advance(lenient_actions=True)`.
                    Err(e) if lenient => {
                        tracing::warn!(
                            "workflow {} action '{}' failed on mirror advance (tolerated): {}",
                            opts.instance_id,
                            action_key,
                            e
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Update instance state
        record.data.state = target_state.clone();

        // Update section from target state
        if let Some(target_state_def) = template.find_state(&target_state) {
            record.data.section = target_state_def.section.clone();
        }

        // Merge artifacts
        if let Some(new_artifacts) = action_result.artifacts {
            merge_json(&mut record.data.artifacts, &new_artifacts);
        }

        // Merge context
        if let Some(context_merge) = action_result.context_merge {
            merge_json(&mut record.data.context, &context_merge);
        }

        // Record history
        record.data.history.push(InstanceHistoryItem {
            ts: Utc::now().to_rfc3339(),
            event: opts.event.clone(),
            from: prev_state.clone(),
            to: target_state.clone(),
            action_key: action_key.clone(),
            msg_id: action_result.message_id,
        });

        // Track idempotency key
        if let Some(ref key) = opts.idempotency_key {
            record.data.idempotency_keys.push(key.clone());
            // Trim to limit
            if record.data.idempotency_keys.len() > IDEMPOTENCY_HISTORY_LIMIT {
                let excess = record.data.idempotency_keys.len() - IDEMPOTENCY_HISTORY_LIMIT;
                record.data.idempotency_keys.drain(0..excess);
            }
        }

        // Check if target state is final
        let is_final = template
            .find_state(&target_state)
            .map(|s| s.state_type == StateType::Final)
            .unwrap_or(false);

        if is_final {
            record.data.status = InstanceStatus::Completed;
        }

        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;

        #[cfg(feature = "events")]
        self.emit_state_changed(&record, Some(&prev_state), &opts.event)
            .await;

        if is_final {
            #[cfg(feature = "events")]
            self.emit_completed(&record).await;
        }

        tracing::info!(
            "Advanced workflow {} from '{}' to '{}' on event '{}'",
            record.instance_id(),
            prev_state,
            target_state,
            opts.event
        );

        Ok(record)
    }

    pub async fn status(&self, opts: StatusOptions) -> Result<StatusResponse> {
        let record = self
            .instance_repo
            .find_by_instance_id(&opts.instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(opts.instance_id.clone()))?;

        // Load template to compute allowed events
        let template_record = self
            .template_repo
            .find_by_template_id_and_version(
                &record.data.template_id,
                Some(&record.data.template_version),
            )
            .await?;

        let mut allowed_events = Vec::new();

        if let Some(template_record) = &template_record {
            let template = &template_record.template;
            // Find all transitions from current state where guard passes
            for transition in &template.transitions {
                if transition.from == record.data.state {
                    let guard_passes = GuardEvaluator::eval(
                        transition.guard.as_deref(),
                        &record.data.context,
                        &record.data.participants,
                        &record.data.artifacts,
                    );
                    if guard_passes && !allowed_events.contains(&transition.on) {
                        allowed_events.push(transition.on.clone());
                    }
                }
            }
        }

        let message = StatusMessage {
            instance_id: record.data.instance_id.clone(),
            state: record.data.state.clone(),
            section: record.data.section.clone(),
            allowed_events,
            action_menu: Vec::new(),
            artifacts: record.data.artifacts.clone(),
            ui: None,
            ui_profile: opts.ui_profile,
            assets: None,
        };

        Ok(StatusResponse { message, record })
    }

    pub async fn pause(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord> {
        let mut record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;

        #[cfg(feature = "events")]
        let prev_status = record.data.status;
        record.data.status = InstanceStatus::Paused;
        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;

        #[cfg(feature = "events")]
        self.emit_status_changed(&record, prev_status).await;

        tracing::info!(
            "Paused workflow instance {} (reason: {:?})",
            instance_id,
            reason
        );
        Ok(record)
    }

    pub async fn resume(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord> {
        let mut record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;

        #[cfg(feature = "events")]
        let prev_status = record.data.status;
        record.data.status = InstanceStatus::Active;
        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;

        #[cfg(feature = "events")]
        self.emit_status_changed(&record, prev_status).await;

        tracing::info!(
            "Resumed workflow instance {} (reason: {:?})",
            instance_id,
            reason
        );
        Ok(record)
    }

    pub async fn cancel(
        &self,
        instance_id: &str,
        reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord> {
        let mut record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;

        #[cfg(feature = "events")]
        let prev_status = record.data.status;
        record.data.status = InstanceStatus::Canceled;
        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;

        #[cfg(feature = "events")]
        self.emit_status_changed(&record, prev_status).await;

        tracing::info!(
            "Canceled workflow instance {} (reason: {:?})",
            instance_id,
            reason
        );
        Ok(record)
    }

    pub async fn complete(
        &self,
        instance_id: &str,
        _reason: Option<&str>,
    ) -> Result<WorkflowInstanceRecord> {
        let record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;

        // Verify state is final (don't force-complete if not in final state)
        let template_record = self
            .template_repo
            .find_by_template_id_and_version(
                &record.data.template_id,
                Some(&record.data.template_version),
            )
            .await?;

        if let Some(template_record) = template_record {
            let is_final = template_record
                .template
                .find_state(&record.data.state)
                .map(|s| s.state_type == StateType::Final)
                .unwrap_or(false);

            if !is_final {
                return Err(WorkflowError::InvalidStatus {
                    status: record.data.status,
                    operation: format!(
                        "complete (state '{}' is not a final state)",
                        record.data.state
                    ),
                });
            }
        }

        Ok(record)
    }

    pub async fn get_instance(&self, instance_id: &str) -> Result<Option<WorkflowInstanceRecord>> {
        self.instance_repo.find_by_instance_id(instance_id).await
    }

    pub async fn list_instances(&self) -> Result<Vec<WorkflowInstanceRecord>> {
        self.instance_repo.find_all().await
    }

    /// Shallow-merge `patch` into the instance's context (non-object patches
    /// replace it wholesale). Out-of-band update used by operator UIs; does not
    /// drive the FSM.
    pub async fn update_context(
        &self,
        instance_id: &str,
        patch: serde_json::Value,
    ) -> Result<WorkflowInstanceRecord> {
        let mut record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;
        merge_json(&mut record.data.context, &patch);
        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;
        Ok(record)
    }

    /// Shallow-merge `artifacts` into the instance's accumulated artifacts.
    /// Out-of-band update used by operator UIs; does not drive the FSM.
    pub async fn append_artifacts(
        &self,
        instance_id: &str,
        artifacts: serde_json::Value,
    ) -> Result<WorkflowInstanceRecord> {
        let mut record = self
            .instance_repo
            .find_by_instance_id(instance_id)
            .await?
            .ok_or_else(|| WorkflowError::InstanceNotFound(instance_id.to_string()))?;
        merge_json(&mut record.data.artifacts, &artifacts);
        record.updated_at = Utc::now();
        self.instance_repo.update(&record).await?;
        Ok(record)
    }

    // ─── Internal Helpers ───────────────────────────────────────────────

    fn validate_template(&self, template: &WorkflowTemplate) -> Result<()> {
        // Must have at least one start state
        let start_count = template
            .states
            .iter()
            .filter(|s| s.state_type == StateType::Start)
            .count();
        if start_count == 0 {
            return Err(WorkflowError::ValidationFailed(
                "Template must have at least one start state".to_string(),
            ));
        }
        if start_count > 1 {
            return Err(WorkflowError::ValidationFailed(
                "Template must have exactly one start state".to_string(),
            ));
        }

        // Validate transition references
        let state_names: Vec<&str> = template.states.iter().map(|s| s.name.as_str()).collect();
        for transition in &template.transitions {
            if !state_names.contains(&transition.from.as_str()) {
                return Err(WorkflowError::ValidationFailed(format!(
                    "Transition 'from' references unknown state: '{}'",
                    transition.from
                )));
            }
            if !state_names.contains(&transition.to.as_str()) {
                return Err(WorkflowError::ValidationFailed(format!(
                    "Transition 'to' references unknown state: '{}'",
                    transition.to
                )));
            }
            if let Some(ref action_key) = transition.action {
                if template.find_action(action_key).is_none() {
                    return Err(WorkflowError::ValidationFailed(format!(
                        "Transition action references unknown action key: '{}'",
                        action_key
                    )));
                }
            }
        }

        Ok(())
    }

    async fn check_instance_policy(
        &self,
        template: &WorkflowTemplate,
        connection_id: Option<&str>,
    ) -> Result<()> {
        if template.instance_policy.mode == PolicyMode::SingletonPerConnection {
            if let Some(conn_id) = connection_id {
                let existing = self
                    .instance_repo
                    .find_by_template_and_connection(&template.template_id, Some(conn_id))
                    .await?;

                // Check if there's an active instance
                let active = existing.iter().any(|r| {
                    matches!(
                        r.data.status,
                        InstanceStatus::Active | InstanceStatus::Paused
                    )
                });

                if active {
                    return Err(WorkflowError::PolicyViolation(format!(
                        "Singleton policy: active instance already exists for template '{}' on connection '{}'",
                        template.template_id, conn_id
                    )));
                }
            }
        }
        Ok(())
    }

    // ─── Event Emission ─────────────────────────────────────────────────

    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &WorkflowInstanceRecord,
        previous_state: Option<&str>,
        event: &str,
    ) {
        if let Some(ref bus) = self.event_bus {
            let payload = crate::events::WorkflowStateChangedPayload {
                instance_id: record.data.instance_id.clone(),
                previous_state: previous_state.map(str::to_string),
                new_state: record.data.state.clone(),
                event: event.to_string(),
                template_id: record.data.template_id.clone(),
                connection_id: record.data.connection_id.clone(),
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            tracing::debug!(
                target: "workflow.emit",
                instance = %record.data.instance_id,
                previous = ?previous_state,
                new = %record.data.state,
                event,
                "state_changed"
            );
            let _ = bus.emit(&meta, payload).await;
        } else {
            tracing::debug!(
                target: "workflow.emit",
                instance = %record.data.instance_id,
                new = %record.data.state,
                "NO event_bus wired — silent"
            );
        }
    }

    #[cfg(feature = "events")]
    async fn emit_status_changed(
        &self,
        record: &WorkflowInstanceRecord,
        previous_status: InstanceStatus,
    ) {
        if let Some(ref bus) = self.event_bus {
            let payload = crate::events::WorkflowStatusChangedPayload {
                instance_id: record.data.instance_id.clone(),
                previous_status,
                new_status: record.data.status,
                template_id: record.data.template_id.clone(),
                connection_id: record.data.connection_id.clone(),
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(feature = "events")]
    async fn emit_completed(&self, record: &WorkflowInstanceRecord) {
        if let Some(ref bus) = self.event_bus {
            let payload = crate::events::WorkflowCompletedPayload {
                instance_id: record.data.instance_id.clone(),
                state: record.data.state.clone(),
                section: record.data.section.clone(),
                template_id: record.data.template_id.clone(),
                connection_id: record.data.connection_id.clone(),
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }
}

/// Merge source JSON object into target JSON object (shallow merge).
fn merge_json(target: &mut serde_json::Value, source: &serde_json::Value) {
    if let (Some(target_obj), Some(source_obj)) = (target.as_object_mut(), source.as_object()) {
        for (key, value) in source_obj {
            target_obj.insert(key.clone(), value.clone());
        }
    }
}
