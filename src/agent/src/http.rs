//! Shared HTTP client construction for DIDComm transport.
//!
//! All outbound DIDComm HTTP requests (connection-request → mediation
//! bootstrap → keylist-update → pickup poll) go through `Agent::http_client`,
//! a single `reqwest::Client` instance that:
//!
//! - **Pools TLS connections** across back-to-back POSTs. The mediation
//!   bootstrap fires 3 POSTs to the same mediator endpoint in sequence
//!   (connection-request, mediate-request, keylist-update); with separate
//!   `reqwest::Client::new()` instances each pays a full TLS handshake
//!   (~150-500ms on 4G). One shared pool means one handshake.
//!
//! - **Negotiates HTTP/2** via ALPN. `http2_prior_knowledge` would skip
//!   ALPN entirely but breaks against HTTP/1.1-only mediators (idiom's
//!   own mediator is H1.1 today); we let reqwest pick H2 when the server
//!   offers it, keep H1.1 as fallback.
//!
//! - **Fails fast**: 5s connect timeout (instead of the OS default ~75s
//!   on dead routes), 30s overall request budget for the longer mediator
//!   round-trips (mediate-grant can take ~5-10s on a cold mediator).
//!
//! - **Keepalive**: 60s TCP keepalive so the pool's idle connections
//!   don't get reaped by NAT before the next POST.
//!
//! If you find yourself writing `reqwest::Client::new()` anywhere in
//! `agent/`, `agent_ffi/`, `agent_tenants/`, or `protocol_*`, replace it
//! with `agent.http_client.clone()` (cloning is cheap — internally Arc).

use std::time::Duration;

/// Build the shared DIDComm HTTP client. Single source of truth for client
/// tuning across the agent.
pub fn shared_didcomm_client() -> reqwest::Client {
    reqwest::Client::builder()
        // 15s overall request budget — with `connect_timeout` already at 5s,
        // the remaining 10s covers the mediator's processing of the longest
        // round-trip (mediate-grant). A larger budget here just makes the
        // failure path drag (caller waits 15s+ before retrying) without
        // helping the happy path.
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(60))
        .tcp_nodelay(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}
