/// DIDComm version configuration and selection
///
/// This module provides types for configuring which DIDComm protocol version
/// to use when packing messages, enabling modular support for v1, v2, or both.
use serde::{Deserialize, Serialize};

/// DIDComm protocol version selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DIDCommVersion {
    /// Only use DIDComm v1 (legacy mode)
    ///
    /// - Uses JWE format with "JWM/1.0" type
    /// - Requires `public_key_base58` in DID documents
    /// - Authcrypt/Anoncrypt modes
    /// - ChaCha20Poly1305 encryption
    V1Only,

    /// Only use DIDComm v2 (modern mode)
    ///
    /// - Uses SICPA didcomm library
    /// - Supports `publicKeyMultibase` (z6Mk...)
    /// - Works with did:peer:2
    /// - More efficient crypto
    V2Only,

    /// Prefer v2, fallback to v1 if recipient doesn't support v2 (RECOMMENDED)
    ///
    /// - Tries v2 first based on DID document capabilities
    /// - Falls back to v1 for legacy peers
    /// - Zero breaking changes
    /// - Best for mixed environments
    #[default]
    V2WithV1Fallback,

    /// Auto-negotiate based on recipient's DID document capabilities
    ///
    /// - Analyzes DID document service endpoints and key formats
    /// - Chooses optimal version for each peer
    /// - Most flexible but requires DID resolution
    Auto,
}

impl DIDCommVersion {
    /// Check if this version can use v1
    pub fn can_use_v1(&self) -> bool {
        matches!(
            self,
            DIDCommVersion::V1Only | DIDCommVersion::V2WithV1Fallback | DIDCommVersion::Auto
        )
    }

    /// Check if this version can use v2
    pub fn can_use_v2(&self) -> bool {
        matches!(
            self,
            DIDCommVersion::V2Only | DIDCommVersion::V2WithV1Fallback | DIDCommVersion::Auto
        )
    }

    /// Check if this version requires negotiation
    pub fn requires_negotiation(&self) -> bool {
        matches!(
            self,
            DIDCommVersion::V2WithV1Fallback | DIDCommVersion::Auto
        )
    }
}

/// Options for packing a DIDComm message
#[derive(Debug, Clone)]
pub struct PackOptions {
    /// Preferred DIDComm version
    pub version: DIDCommVersion,

    /// Whether to protect sender identity (authcrypt vs anoncrypt)
    ///
    /// - `true`: Authcrypt - receiver can verify sender
    /// - `false`: Anoncrypt - sender is anonymous
    pub protect_sender: bool,

    /// Whether to include a separate signature (v2 only)
    ///
    /// DIDComm v2 supports signed messages in addition to encryption.
    /// If true, the message will be signed with the sender's key.
    pub sign_message: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            version: DIDCommVersion::default(),
            protect_sender: true, // Default to authcrypt for sender authentication
            sign_message: false,  // Encryption provides authentication, signing optional
        }
    }
}

impl PackOptions {
    /// Create options for v1-only packing
    pub fn v1_only() -> Self {
        Self {
            version: DIDCommVersion::V1Only,
            protect_sender: true,
            sign_message: false,
        }
    }

    /// Create options for v2-only packing
    pub fn v2_only() -> Self {
        Self {
            version: DIDCommVersion::V2Only,
            protect_sender: true,
            sign_message: false,
        }
    }

    /// Create options with smart fallback (v2 preferred, v1 fallback)
    pub fn with_fallback() -> Self {
        Self {
            version: DIDCommVersion::V2WithV1Fallback,
            protect_sender: true,
            sign_message: false,
        }
    }

    /// Create options with auto-negotiation
    pub fn auto() -> Self {
        Self {
            version: DIDCommVersion::Auto,
            protect_sender: true,
            sign_message: false,
        }
    }

    /// Set whether to protect sender identity
    pub fn with_sender_protection(mut self, protect: bool) -> Self {
        self.protect_sender = protect;
        self
    }

    /// Set whether to sign the message (v2 only)
    pub fn with_signature(mut self, sign: bool) -> Self {
        self.sign_message = sign;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_capabilities() {
        assert!(DIDCommVersion::V1Only.can_use_v1());
        assert!(!DIDCommVersion::V1Only.can_use_v2());

        assert!(!DIDCommVersion::V2Only.can_use_v1());
        assert!(DIDCommVersion::V2Only.can_use_v2());

        assert!(DIDCommVersion::V2WithV1Fallback.can_use_v1());
        assert!(DIDCommVersion::V2WithV1Fallback.can_use_v2());

        assert!(DIDCommVersion::Auto.can_use_v1());
        assert!(DIDCommVersion::Auto.can_use_v2());
    }

    #[test]
    fn test_negotiation_required() {
        assert!(!DIDCommVersion::V1Only.requires_negotiation());
        assert!(!DIDCommVersion::V2Only.requires_negotiation());
        assert!(DIDCommVersion::V2WithV1Fallback.requires_negotiation());
        assert!(DIDCommVersion::Auto.requires_negotiation());
    }

    #[test]
    fn test_default_version() {
        assert_eq!(DIDCommVersion::default(), DIDCommVersion::V2WithV1Fallback);
    }

    #[test]
    fn test_pack_options_builders() {
        let v1_opts = PackOptions::v1_only();
        assert_eq!(v1_opts.version, DIDCommVersion::V1Only);
        assert!(v1_opts.protect_sender);

        let v2_opts = PackOptions::v2_only();
        assert_eq!(v2_opts.version, DIDCommVersion::V2Only);

        let fallback_opts = PackOptions::with_fallback();
        assert_eq!(fallback_opts.version, DIDCommVersion::V2WithV1Fallback);

        let auto_opts = PackOptions::auto();
        assert_eq!(auto_opts.version, DIDCommVersion::Auto);
    }

    #[test]
    fn test_pack_options_modifiers() {
        let opts = PackOptions::default()
            .with_sender_protection(false)
            .with_signature(true);

        assert!(!opts.protect_sender);
        assert!(opts.sign_message);
    }
}
