pub mod advance;
pub mod cancel;
pub mod complete;
pub mod discover;
pub mod fetch_template;
pub mod pause;
pub mod problem_report;
pub mod publish_template;
pub mod resume;
pub mod start;
pub mod status;
pub mod template_response;
pub mod workflows_response;

pub use advance::AdvanceMessage;
pub use cancel::CancelMessage;
pub use complete::CompleteMessage;
pub use discover::DiscoverMessage;
pub use fetch_template::FetchTemplateMessage;
pub use pause::PauseMessage;
pub use problem_report::ProblemReportMessage;
pub use publish_template::PublishTemplateMessage;
pub use resume::ResumeMessage;
pub use start::StartMessage;
pub use status::{StatusMessage, StatusRequestMessage};
pub use template_response::TemplateResponseMessage;
pub use workflows_response::WorkflowsResponseMessage;

/// Protocol base URI.
pub const PROTOCOL_URI: &str = "https://didcomm.org/workflow/1.0";
