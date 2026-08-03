//! DIDComm push notifications protocol (RFC 0734, FCM).
//!
//! `https://didcomm.org/push-notifications-fcm/1.0/*` — one protocol URI
//! covers iOS and Android; the platform difference lives in the FCM v1
//! payload the mediator emits (apns block for iOS, android block for
//! Android), not in the protocol. iOS apps obtain an FCM token via
//! Firebase's APNS bridge and the mediator never speaks APNS directly.
//!
//! Layers:
//!
//! 1. [`messages`] — wire types for the 5 messages
//!    (`set-device-info`, `delete-device-info`, `get-device-info`,
//!    `device-info`, `problem-report`).
//! 2. [`domain`] — `DevicePlatform` enum.
//! 3. [`repository`] — `DeviceInfoRecord` (one row per connection) + a
//!    trait + an in-memory implementation. Storage-backed implementations
//!    plug in via the trait.
//! 4. [`service`] — message-level state rules + dedup/upsert wrapper.
//! 5. [`handlers`] — DIDComm `MessageHandler` impls the mediator registers.
//! 6. [`notifier`] — `PushNotifier` trait + test fixtures. The real FCM /
//!    webhook implementations live in `mediator_server` so this crate stays
//!    HTTP-client free.

pub mod domain;
pub mod error;
pub mod handlers;
pub mod messages;
pub mod notifier;
pub mod repository;
pub mod service;

pub use domain::DevicePlatform;
pub use error::{PushNotificationError, Result};
pub use handlers::{DeleteDeviceInfoHandler, GetDeviceInfoHandler, SetDeviceInfoHandler};
pub use messages::{
    DeleteDeviceInfoMessage, DeviceInfoMessage, GetDeviceInfoMessage, ProblemDescription,
    ProblemReportMessage, SetDeviceInfoMessage, DELETE_DEVICE_INFO_TYPE, DEVICE_INFO_TYPE,
    GET_DEVICE_INFO_TYPE, PROBLEM_REPORT_TYPE, SET_DEVICE_INFO_TYPE,
};
pub use notifier::{ErroringNotifier, PushNotifier, RecordingNotifier};
pub use repository::{
    DeviceInfoRecord, DeviceInfoRepository, DeviceInfoRepositoryTrait, DeviceInfoTags,
};
pub use service::{PushNotificationService, SetOutcome};
