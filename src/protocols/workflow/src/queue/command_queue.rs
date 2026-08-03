use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::task::JoinHandle;
use tracing;

use crate::error::Result;
use crate::repository::command_record::{CommandStatus, CommandType, WorkflowCommandRecord};
use crate::repository::command_repository::WorkflowCommandRepositoryTrait;

/// Configuration for the persistent command queue.
#[derive(Debug, Clone)]
pub struct CommandQueueConfig {
    pub poll_interval: Duration,
    pub concurrency: usize,
    pub processing_timeout: Duration,
    pub max_attempts: u32,
    pub completed_retention: Duration,
    pub failed_retention: Duration,
}

impl Default for CommandQueueConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            concurrency: 3,
            processing_timeout: Duration::from_secs(30),
            max_attempts: 3,
            completed_retention: Duration::from_secs(3600), // 1 hour
            failed_retention: Duration::from_secs(86400),   // 24 hours
        }
    }
}

/// Persistent command queue with polling, retry, and deduplication.
pub struct PersistentCommandQueue {
    repository: Arc<dyn WorkflowCommandRepositoryTrait>,
    config: CommandQueueConfig,
    shutdown: Arc<AtomicBool>,
}

/// Type alias for the async job handler function.
pub type JobHandler = Arc<
    dyn Fn(WorkflowCommandRecord) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync,
>;

impl PersistentCommandQueue {
    pub fn new(
        repository: Arc<dyn WorkflowCommandRepositoryTrait>,
        config: CommandQueueConfig,
    ) -> Self {
        Self {
            repository,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Enqueue a command with deduplication (skip if same cmd+thid already pending/processing).
    pub async fn enqueue(
        &self,
        cmd: CommandType,
        thid: &str,
        connection_id: Option<&str>,
        idempotency_key: Option<&str>,
        payload: serde_json::Value,
    ) -> Result<()> {
        // Deduplication: check for existing pending/processing command with same cmd+thid
        if let Some(_existing) = self
            .repository
            .find_by_cmd_and_thid_pending(cmd, thid)
            .await?
        {
            tracing::debug!("Skipping duplicate command {:?} for thid={}", cmd, thid);
            return Ok(());
        }

        let record = WorkflowCommandRecord::new(
            cmd,
            thid.to_string(),
            connection_id.map(|s| s.to_string()),
            idempotency_key.map(|s| s.to_string()),
            payload,
        );

        self.repository.save(&record).await?;
        tracing::debug!(
            "Enqueued command {:?} for thid={} (id={})",
            cmd,
            thid,
            record.id
        );
        Ok(())
    }

    /// Start the background polling worker.
    pub fn start_worker(&self, handler: JobHandler) -> JoinHandle<()> {
        let repository = self.repository.clone();
        let config = self.config.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            tracing::info!(
                "Workflow command queue worker started (poll={}ms, concurrency={})",
                config.poll_interval.as_millis(),
                config.concurrency
            );

            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));
            cleanup_interval.tick().await; // skip first tick

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    tracing::info!("Workflow command queue worker shutting down");
                    break;
                }

                // Poll for pending commands
                match repository.find_pending().await {
                    Ok(pending) => {
                        let batch: Vec<_> = pending.into_iter().take(config.concurrency).collect();

                        for mut cmd_record in batch {
                            // Mark as processing
                            cmd_record.status = CommandStatus::Processing;
                            cmd_record.attempts += 1;
                            cmd_record.last_attempt_at = Some(Utc::now());
                            let _ = repository.update(&cmd_record).await;

                            let handler = handler.clone();
                            let repo = repository.clone();
                            let max_attempts = config.max_attempts;
                            let timeout = config.processing_timeout;

                            tokio::spawn(async move {
                                let result =
                                    tokio::time::timeout(timeout, handler(cmd_record.clone()))
                                        .await;

                                match result {
                                    Ok(Ok(())) => {
                                        cmd_record.status = CommandStatus::Completed;
                                        let _ = repo.update(&cmd_record).await;
                                    }
                                    Ok(Err(e)) => {
                                        let error_msg = e.to_string();

                                        // Special deferral for missing templates:
                                        // Don't count against max_attempts — retry
                                        // indefinitely until template arrives via
                                        // fetch-template / template response exchange.
                                        let is_template_not_found = matches!(
                                            &e,
                                            crate::error::WorkflowError::TemplateNotFound(_)
                                        );

                                        if is_template_not_found {
                                            tracing::info!(
                                                "Command {} ({:?}) deferred: template not found, will retry",
                                                cmd_record.id, cmd_record.cmd
                                            );
                                            // Decrement attempts so it doesn't count
                                            if cmd_record.attempts > 0 {
                                                cmd_record.attempts -= 1;
                                            }
                                            cmd_record.status = CommandStatus::Pending;
                                            cmd_record.error = Some(error_msg);
                                            let _ = repo.update(&cmd_record).await;
                                            // Small backoff before next poll picks it up
                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                        } else {
                                            tracing::warn!(
                                                "Command {} ({:?}) failed: {}",
                                                cmd_record.id,
                                                cmd_record.cmd,
                                                error_msg
                                            );
                                            if cmd_record.attempts >= max_attempts {
                                                cmd_record.status = CommandStatus::Failed;
                                            } else {
                                                cmd_record.status = CommandStatus::Pending;
                                            }
                                            cmd_record.error = Some(error_msg);
                                            let _ = repo.update(&cmd_record).await;
                                        }
                                    }
                                    Err(_) => {
                                        tracing::warn!(
                                            "Command {} ({:?}) timed out",
                                            cmd_record.id,
                                            cmd_record.cmd
                                        );
                                        if cmd_record.attempts >= max_attempts {
                                            cmd_record.status = CommandStatus::Failed;
                                        } else {
                                            cmd_record.status = CommandStatus::Pending;
                                        }
                                        cmd_record.error = Some("Processing timeout".to_string());
                                        let _ = repo.update(&cmd_record).await;
                                    }
                                }
                            });
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to poll pending commands: {}", e);
                    }
                }

                // Periodic cleanup of old completed/failed records
                tokio::select! {
                    _ = tokio::time::sleep(config.poll_interval) => {},
                    _ = cleanup_interval.tick() => {
                        let completed_cutoff = Utc::now() - chrono::Duration::from_std(config.completed_retention).unwrap_or_default();
                        if let Ok(deleted) = repository.delete_completed_before(completed_cutoff).await {
                            if deleted > 0 {
                                tracing::debug!("Cleaned up {} completed/failed command records", deleted);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Signal the worker to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}
