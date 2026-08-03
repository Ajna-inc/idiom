//! mDoc (Mobile Document) implementation following ISO/IEC 18013-5
//!
//! This module provides support for ISO-compliant mobile documents,
//! commonly used for mobile driver's licenses (mDL) and other mobile credentials.

pub mod device_auth;
pub mod disclosure;
pub mod encoder;
pub mod issuer_auth;
pub mod service;
pub mod types;

pub use device_auth::{DeviceAuth, DeviceSignature};
pub use disclosure::{DeviceRequest, DeviceResponse, DisclosureRequest};
pub use encoder::MdocEncoder;
pub use issuer_auth::IssuerAuth;
pub use service::MdocService;
pub use types::*;
