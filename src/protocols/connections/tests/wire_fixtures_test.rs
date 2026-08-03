//! Wire-fixture compatibility tests.
//!
//! Each fixture under `tests/fixtures/aries/*.json` is a representative
//! sample of what a DIDComm agent emits on the wire for a DID Exchange
//! message. These files are intended to be **byte-for-byte swappable**
//! with fixtures captured from a real DIDComm agent — keeping them as
//! separate files (rather than inline string literals) means we can
//! re-capture them as peer implementations evolve without touching test
//! code.
//!
//! The contract these tests assert: every fixture decodes cleanly into
//! our typed Rust struct without losing semantic information. If a
//! fixture starts failing, our parser has drifted from the peer's emitter.
//!
//! When recapturing: dump the JWE from a real DIDComm agent, run
//! `decrypt_only` on it, write the decrypted plaintext into the
//! matching fixture file. The wire format is stable across patch
//! versions (DID Exchange 1.1 is locked by RFC 0023).

use protocol_connections::messages::{
    DidExchangeCompleteMessage, DidExchangeRequestMessage, DidExchangeResponseMessage,
};

fn load_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/aries/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"))
}

#[test]
fn fixture_didexchange_request_decodes() {
    let json = load_fixture("didexchange_request.json");
    let decoded: DidExchangeRequestMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.label, "Faber");
    assert_eq!(decoded.did, "did:peer:2.Ez6LSn...etc");
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
    assert_eq!(
        decoded.parent_thread_id(),
        Some("6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e")
    );
}

#[test]
fn fixture_didexchange_response_decodes() {
    let json = load_fixture("didexchange_response.json");
    let decoded: DidExchangeResponseMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.did, "did:peer:2.Ez6LSnRESPONDER");
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
}

#[test]
fn fixture_didexchange_complete_decodes() {
    let json = load_fixture("didexchange_complete.json");
    let decoded: DidExchangeCompleteMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.thread_id(), "ff8c61c0-2acd-4ee1-8f6e-2c4316f7a9bd");
    assert_eq!(
        decoded.parent_thread_id(),
        Some("6e1f1b03-6f1f-4e3e-9e8d-7a5e7a5e7a5e")
    );
}

/// Round-trip: load a fixture, decode, re-serialize. Our re-serialized
/// JSON may use a different key order than the fixture, but re-parsing
/// our output must match the fixture's structural content.
#[test]
fn fixture_request_round_trips_structurally() {
    let json = load_fixture("didexchange_request.json");
    let decoded: DidExchangeRequestMessage = serde_json::from_str(&json).unwrap();
    let reserialized = serde_json::to_string(&decoded).unwrap();
    let original_value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let reserialized_value: serde_json::Value = serde_json::from_str(&reserialized).unwrap();
    assert_eq!(original_value["@type"], reserialized_value["@type"]);
    assert_eq!(original_value["label"], reserialized_value["label"]);
    assert_eq!(original_value["did"], reserialized_value["did"]);
    assert_eq!(
        original_value["~thread"]["thid"],
        reserialized_value["~thread"]["thid"]
    );
    assert_eq!(
        original_value["~thread"]["pthid"],
        reserialized_value["~thread"]["pthid"]
    );
}
