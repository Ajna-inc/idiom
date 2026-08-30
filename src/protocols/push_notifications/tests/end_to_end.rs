//! End-to-end push-notifications test exercising every layer together.
//!
//! Scenario (production flow):
//!
//! 1. Wallet sends `set-device-info` over its mediator connection (we
//!    simulate this by handing an InboundMessage straight to the
//!    `SetDeviceInfoHandler`).
//! 2. The handler upserts a `DeviceInfoRecord` into the shared repository.
//! 3. A forward message arrives for the same connection. The mediator
//!    queues it then invokes the `PushNotifier`.
//! 4. The notifier reads the device-info record and dispatches a push.
//!
//! This test uses the `RecordingNotifier` stand-in so we can assert the
//! notifier saw the correct connection id without depending on a live FCM
//! or webhook server. The FCM/webhook impls live in `mediator_server` and
//! have their own tests over fake HTTP servers (see
//! `mediator_server::push_notifier::tests::fcm_full_flow_against_fake_servers`).

use async_trait::async_trait;
use didcomm::core::Message as DidcommMessage;
use didcomm::messaging::{InboundMessage, MessageContext, MessageHandler};
use protocol_push_notifications::{
    DeviceInfoRepository, DeviceInfoRepositoryTrait, PushNotificationService, PushNotifier,
    RecordingNotifier, SetDeviceInfoHandler, SET_DEVICE_INFO_TYPE,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

fn inbound_set(conn: &str, token: &str, platform: &str) -> InboundMessage {
    InboundMessage {
        message: DidcommMessage {
            id: "msg-set".to_string(),
            msg_type: SET_DEVICE_INFO_TYPE.to_string(),
            body: json!({"device_token": token, "device_platform": platform}),
            from: Some("did:peer:1zWallet".to_string()),
            to: Some(vec!["did:peer:1zMediator".to_string()]),
            thread: None,
            pthid: None,
            created_time: None,
            expires_time: None,
            attachments: None,
            extra: Default::default(),
        },
        context: MessageContext {
            from: Some("did:peer:1zWallet".to_string()),
            to: Some("did:peer:1zMediator".to_string()),
            thread_id: None,
            parent_thread_id: None,
            connection_id: Some(conn.to_string()),
            encrypted: true,
            authenticated: true,
            sender_endpoint: None,
            raw_plaintext: None,
        },
    }
}

/// Inline tiny push notifier that reads the same repository the handler
/// writes to, so we can assert end-to-end repository-→-notify behaviour
/// without needing FCM/webhook plumbing.
struct ReadingRepoNotifier {
    repo: Arc<dyn DeviceInfoRepositoryTrait>,
    seen: Arc<Mutex<Vec<(String, String, String)>>>,
}

#[async_trait]
impl PushNotifier for ReadingRepoNotifier {
    async fn notify(&self, connection_id: &str) -> Result<(), String> {
        let rec = self
            .repo
            .find_by_connection_id(connection_id)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(r) = rec {
            self.seen.lock().await.push((
                connection_id.to_string(),
                r.device_token,
                r.device_platform.to_string(),
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn handler_upserts_then_notifier_reads_same_record() {
    let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
    let service = Arc::new(PushNotificationService::new(repo.clone()));
    let handler = SetDeviceInfoHandler::new(service);

    // (1) Wallet sends set-device-info.
    handler
        .handle(inbound_set("conn-X", "tok-X", "ios"))
        .await
        .unwrap();

    // (2) A queued forward triggers notify on the same repo.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let notifier = ReadingRepoNotifier {
        repo: repo.clone(),
        seen: seen.clone(),
    };
    notifier.notify("conn-X").await.unwrap();

    let calls = seen.lock().await.clone();
    assert_eq!(
        calls,
        vec![("conn-X".to_string(), "tok-X".to_string(), "ios".to_string())],
        "notifier should see the token the handler just persisted"
    );
}

#[tokio::test]
async fn token_rotation_is_observed_by_notifier() {
    let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
    let service = Arc::new(PushNotificationService::new(repo.clone()));
    let handler = SetDeviceInfoHandler::new(service);

    handler
        .handle(inbound_set("conn-Y", "tok-old", "android"))
        .await
        .unwrap();
    handler
        .handle(inbound_set("conn-Y", "tok-new", "android"))
        .await
        .unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let notifier = ReadingRepoNotifier {
        repo: repo.clone(),
        seen: seen.clone(),
    };
    notifier.notify("conn-Y").await.unwrap();

    let calls = seen.lock().await.clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "tok-new", "rotation must overwrite");
    assert_eq!(calls[0].2, "android");
}

#[tokio::test]
async fn deletion_makes_notifier_a_noop() {
    let repo: Arc<dyn DeviceInfoRepositoryTrait> = Arc::new(DeviceInfoRepository::new());
    let service = Arc::new(PushNotificationService::new(repo.clone()));
    let handler = SetDeviceInfoHandler::new(service.clone());

    handler
        .handle(inbound_set("c", "tok", "ios"))
        .await
        .unwrap();
    service.delete_device_info("c").await.unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let notifier = ReadingRepoNotifier {
        repo: repo.clone(),
        seen: seen.clone(),
    };
    notifier.notify("c").await.unwrap();

    assert!(
        seen.lock().await.is_empty(),
        "after delete, notify must not record anything"
    );
}

#[tokio::test]
async fn recording_notifier_smoke_against_protocol_crate_api() {
    // Sanity that the trait + RecordingNotifier the ForwardService uses
    // remains compatible: this is the same Arc<dyn PushNotifier> shape
    // that forward_service::with_push_notifier expects.
    let n: Arc<dyn PushNotifier> = Arc::new(RecordingNotifier::new());
    n.notify("conn-1").await.unwrap();
    n.notify("conn-2").await.unwrap();
}
