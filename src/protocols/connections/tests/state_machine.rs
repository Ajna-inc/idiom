//! Connection state-machine tests:
//! - Legacy RFC 0160 connection state wire values
//! - The DidExchange (RFC 0023) → RFC 0160 state mapping function

use protocol_connections::{ConnectionState, DidExchangeState};

#[test]
fn rfc_0160_state_wire_values() {
    assert_eq!(ConnectionState::Null.to_string(), "null");
    assert_eq!(ConnectionState::Invited.to_string(), "invited");
    assert_eq!(ConnectionState::Requested.to_string(), "requested");
    assert_eq!(ConnectionState::Responded.to_string(), "responded");
    assert_eq!(ConnectionState::Complete.to_string(), "complete");
}

#[test]
fn rfc_0160_state_from_did_exchange_state_for_all_inputs() {
    assert_eq!(
        DidExchangeState::Abandoned.rfc0160_state(),
        ConnectionState::Null
    );
    assert_eq!(
        DidExchangeState::Start.rfc0160_state(),
        ConnectionState::Null
    );

    assert_eq!(
        DidExchangeState::InvitationReceived.rfc0160_state(),
        ConnectionState::Invited
    );
    assert_eq!(
        DidExchangeState::InvitationSent.rfc0160_state(),
        ConnectionState::Invited
    );

    assert_eq!(
        DidExchangeState::RequestReceived.rfc0160_state(),
        ConnectionState::Requested
    );
    assert_eq!(
        DidExchangeState::RequestSent.rfc0160_state(),
        ConnectionState::Requested
    );

    assert_eq!(
        DidExchangeState::ResponseReceived.rfc0160_state(),
        ConnectionState::Responded
    );
    assert_eq!(
        DidExchangeState::ResponseSent.rfc0160_state(),
        ConnectionState::Responded
    );

    assert_eq!(
        DidExchangeState::Completed.rfc0160_state(),
        ConnectionState::Complete
    );
}
