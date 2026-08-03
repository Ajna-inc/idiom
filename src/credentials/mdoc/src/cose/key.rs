//! COSE_Key wrapper for public keys

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Wrapper around COSE_Key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoseKey {
    /// Key type (kty)
    pub kty: i32,

    /// Algorithm (alg)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<i32>,

    /// Key ID (kid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<Vec<u8>>,

    /// Additional parameters
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

impl CoseKey {
    pub fn new(kty: i32) -> Self {
        Self {
            kty,
            alg: None,
            kid: None,
            params: HashMap::new(),
        }
    }

    pub fn with_algorithm(mut self, alg: i32) -> Self {
        self.alg = Some(alg);
        self
    }

    pub fn with_kid(mut self, kid: Vec<u8>) -> Self {
        self.kid = Some(kid);
        self
    }

    pub fn with_param(mut self, key: String, value: serde_json::Value) -> Self {
        self.params.insert(key, value);
        self
    }
}
