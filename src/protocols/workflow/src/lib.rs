//! # Workflow Protocol
//!
//! DIDComm Workflow Protocol (`https://didcomm.org/workflow/1.0`) implementation.
//!
//! Enables two agents (coordinator/processor) to execute declarative state-machine
//! workflows defined as JSON templates over DIDComm.

pub mod actions;
pub mod domain;
pub mod engine;
pub mod events;
pub mod handlers;
pub mod messages;
pub mod queue;
pub mod repository;
pub mod services;

// Re-export domain types
pub use domain::{
    instance::{InstanceHistoryItem, InstanceStatus, Participant, WorkflowInstanceData},
    policy::{InstancePolicy, PolicyMode},
    role::WorkflowRole,
    template::{
        ActionDef, AttributeSpec, Catalog, CredentialProfile, DisplayHints, ProofProfile,
        SectionDef, StateDef, StateType, TransitionDef, UiItem, WorkflowTemplate,
    },
};

// Re-export messages
pub use messages::{
    AdvanceMessage, CancelMessage, CompleteMessage, DiscoverMessage, FetchTemplateMessage,
    PauseMessage, ProblemReportMessage, PublishTemplateMessage, ResumeMessage, StartMessage,
    StatusMessage, StatusRequestMessage, TemplateResponseMessage, WorkflowsResponseMessage,
};

// Re-export repository
pub use repository::{
    command_record::{CommandStatus, CommandType, WorkflowCommandRecord},
    command_repository::{WorkflowCommandRepository, WorkflowCommandRepositoryTrait},
    instance_record::WorkflowInstanceRecord,
    instance_repository::{WorkflowInstanceRepository, WorkflowInstanceRepositoryTrait},
    template_record::WorkflowTemplateRecord,
    template_repository::{WorkflowTemplateRepository, WorkflowTemplateRepositoryTrait},
};

// Re-export services
pub use services::WorkflowService;

// Re-export actions
pub use actions::registry::{ActionContext, ActionRegistry, ActionResult, WorkflowActionHandler};

// Re-export engine
pub use engine::guard::GuardEvaluator;

// Re-export queue
pub use queue::command_queue::{CommandQueueConfig, PersistentCommandQueue};

// Re-export events
pub use events::{topics, types};

// Error types
pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum WorkflowError {
        #[error("Workflow instance not found: {0}")]
        InstanceNotFound(String),

        #[error("Workflow template not found: {0}")]
        TemplateNotFound(String),

        #[error("Invalid state transition: from '{from}' on event '{event}'")]
        InvalidTransition { from: String, event: String },

        #[error("Instance is {status:?}, cannot {operation}")]
        InvalidStatus {
            status: super::InstanceStatus,
            operation: String,
        },

        #[error("No enabled transitions for event '{event}' in state '{state}'")]
        NoEnabledTransition { state: String, event: String },

        #[error("Instance policy violation: {0}")]
        PolicyViolation(String),

        #[error("Action execution failed: {0}")]
        ActionFailed(String),

        #[error("Action timeout after {0:?}")]
        ActionTimeout(std::time::Duration),

        #[error("Action handler not found for typeURI: {0}")]
        ActionHandlerNotFound(String),

        #[error("Template validation failed: {0}")]
        ValidationFailed(String),

        #[error("Idempotent operation: already processed with key '{0}'")]
        IdempotentDuplicate(String),

        #[error("Connection binding mismatch: expected {expected}, got {actual}")]
        ConnectionMismatch { expected: String, actual: String },

        #[error("Serialization error: {0}")]
        Serialization(String),

        #[error("Repository error: {0}")]
        Repository(String),

        #[error("Internal error: {0}")]
        Internal(String),
    }

    pub type Result<T> = std::result::Result<T, WorkflowError>;
}

pub use error::{Result, WorkflowError};
