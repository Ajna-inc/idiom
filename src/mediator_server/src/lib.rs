//! Ajna DIDComm Mediator Server
//!
//! A production-grade DIDComm mediator built on existing protocol crates.
//!
//! # Features
//!
//! - Coordinate Mediation (RFC 0211): request/grant/keylist management
//! - Message Forwarding (RFC 0094): queue forwarded messages for recipients
//! - Pickup V2 (RFC 0685): status/delivery/acknowledgment
//! - Live Delivery: push via WebSocket when recipient is connected
//! - Direct routing by recipient-key JWE lookup
//! - OOB Invitations: reusable invitation endpoint
//! - Push notifications (FCM v1 / webhook)
//! - Persistent storage via Aries Askar (SQLite/PostgreSQL)

pub mod app;
pub mod config;
pub mod crypto;
pub mod metrics;
pub mod push_notifier;
pub mod routes;
pub mod ws;
