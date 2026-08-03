//! User-profile events.

use crate::repository::UserProfileRecord;
use serde::{Deserialize, Serialize};

pub mod topics {
    pub const PROFILE: &str = "profile";
}

pub mod types {
    /// Peer sent us their profile (received over DIDComm).
    pub const RECEIVED: &str = "received";
    /// A peer's profile was updated locally (after `received` lands and is
    /// persisted to the repository).
    pub const PEER_UPDATED: &str = "peer_updated";
    /// The local user's own profile was updated.
    pub const OWN_UPDATED: &str = "own_updated";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileReceivedPayload {
    pub connection_id: String,
    pub send_back_yours: bool,
    /// Inner `ProfileData` JSON — kept loosely typed because the on-the-wire
    /// shape can carry V1 attachments that don't always round-trip through
    /// the typed `ProfileData` struct.
    pub profile: serde_json::Value,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for ProfileReceivedPayload {
    const TOPIC: &'static str = topics::PROFILE;
    const NAME: &'static str = types::RECEIVED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePeerUpdatedPayload {
    pub connection_id: String,
    pub record: UserProfileRecord,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for ProfilePeerUpdatedPayload {
    const TOPIC: &'static str = topics::PROFILE;
    const NAME: &'static str = types::PEER_UPDATED;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileOwnUpdatedPayload {
    pub record: UserProfileRecord,
}

#[cfg(feature = "events")]
impl agent_events::TypedEvent for ProfileOwnUpdatedPayload {
    const TOPIC: &'static str = topics::PROFILE;
    const NAME: &'static str = types::OWN_UPDATED;
}

#[cfg(all(test, feature = "events"))]
mod tests {
    use super::*;
    use agent_events::{EventBus, EventMetadata, TypedEvent};
    use serde_json::json;

    fn meta() -> EventMetadata {
        EventMetadata::for_tenant("test-tenant")
    }

    #[test]
    fn typed_event_bindings_match_constants() {
        assert_eq!(
            <ProfileReceivedPayload as TypedEvent>::TOPIC,
            topics::PROFILE
        );
        assert_eq!(
            <ProfileReceivedPayload as TypedEvent>::NAME,
            types::RECEIVED
        );
        assert_eq!(
            <ProfilePeerUpdatedPayload as TypedEvent>::NAME,
            types::PEER_UPDATED
        );
        assert_eq!(
            <ProfileOwnUpdatedPayload as TypedEvent>::NAME,
            types::OWN_UPDATED
        );
    }

    #[tokio::test]
    async fn profile_received_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        bus.emit(
            &meta(),
            ProfileReceivedPayload {
                connection_id: "conn-1".into(),
                send_back_yours: true,
                profile: json!({"displayName": "Alice"}),
            },
        )
        .await
        .unwrap();
        let env = sub.recv().await.unwrap();
        let decoded: ProfileReceivedPayload = env.payload().unwrap();
        assert_eq!(decoded.connection_id, "conn-1");
        assert!(decoded.send_back_yours);
        assert_eq!(decoded.profile["displayName"], "Alice");
        assert_eq!(env.topic, topics::PROFILE);
    }

    #[tokio::test]
    async fn peer_updated_carries_record() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let record = UserProfileRecord {
            display_name: Some("Bob".into()),
            ..Default::default()
        };
        bus.emit(
            &meta(),
            ProfilePeerUpdatedPayload {
                connection_id: "conn-2".into(),
                record,
            },
        )
        .await
        .unwrap();
        let decoded: ProfilePeerUpdatedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.record.display_name.as_deref(), Some("Bob"));
    }

    #[tokio::test]
    async fn own_updated_round_trip() {
        let bus = EventBus::new(10);
        let mut sub = bus.subscribe();
        let record = UserProfileRecord {
            display_name: Some("Self".into()),
            ..Default::default()
        };
        bus.emit(&meta(), ProfileOwnUpdatedPayload { record })
            .await
            .unwrap();
        let decoded: ProfileOwnUpdatedPayload = sub.recv().await.unwrap().payload().unwrap();
        assert_eq!(decoded.record.display_name.as_deref(), Some("Self"));
    }
}
