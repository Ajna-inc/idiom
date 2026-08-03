//! Out-of-band invitation URL encoding tests.
//!
//! Validates the `?oob=` URL encoding round-trips losslessly, that
//! malformed URLs are rejected, and that the encoded payload preserves
//! label / goal / goal-code fields.

use protocol_oob::OutOfBandInvitation;

fn make_invitation() -> OutOfBandInvitation {
    OutOfBandInvitation::new(vec![])
        .with_label("Alice".to_string())
        .with_handshake_protocols(vec!["https://didcomm.org/didexchange/1.1".to_string()])
        .with_goal("connect".to_string(), "Establish DIDComm".to_string())
}

#[test]
fn to_url_roundtrips_via_from_url() {
    let inv = make_invitation();
    let url = inv.to_url("https://example.com").expect("encode url");
    assert!(url.starts_with("https://example.com?oob="));
    let restored = OutOfBandInvitation::from_url(&url).expect("decode url");
    assert_eq!(restored.id, inv.id);
    assert_eq!(restored.label, inv.label);
    assert_eq!(restored.handshake_protocols, inv.handshake_protocols);
    assert_eq!(restored.goal, inv.goal);
}

#[test]
fn from_url_rejects_missing_oob_param() {
    let result = OutOfBandInvitation::from_url("https://example.com/no-oob");
    assert!(result.is_err());
}

#[test]
fn from_url_rejects_non_url_input() {
    let result = OutOfBandInvitation::from_url("not a url at all");
    assert!(result.is_err());
}

#[test]
fn from_url_rejects_invalid_base64() {
    let result = OutOfBandInvitation::from_url("https://example.com?oob=not-base64!!!");
    assert!(result.is_err());
}

#[test]
fn url_carries_label_in_payload() {
    let inv = make_invitation();
    let url = inv.to_url("https://example.com").unwrap();
    let restored = OutOfBandInvitation::from_url(&url).unwrap();
    assert_eq!(restored.label.as_deref(), Some("Alice"));
}

#[test]
fn url_carries_goal_and_goal_code() {
    let inv = make_invitation();
    let url = inv.to_url("https://example.com").unwrap();
    let restored = OutOfBandInvitation::from_url(&url).unwrap();
    assert_eq!(restored.goal_code.as_deref(), Some("connect"));
    assert_eq!(restored.goal.as_deref(), Some("Establish DIDComm"));
}
