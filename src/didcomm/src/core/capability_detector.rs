/// Capability detection for DIDComm version support
///
/// Analyzes DID documents to determine which DIDComm protocol versions
/// a peer supports based on service endpoints and key formats.
use did::core::document::DidDocument;
use tracing::{debug, trace};

/// Detected DIDComm capabilities for a DID
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DIDCommCapabilities {
    /// Whether the DID supports DIDComm v1
    pub supports_v1: bool,

    /// Whether the DID supports DIDComm v2
    pub supports_v2: bool,
}

impl DIDCommCapabilities {
    /// Check if v2 is preferred over v1
    pub fn prefers_v2(&self) -> bool {
        self.supports_v2
    }

    /// Check if only v1 is supported
    pub fn only_v1(&self) -> bool {
        self.supports_v1 && !self.supports_v2
    }

    /// Check if only v2 is supported
    pub fn only_v2(&self) -> bool {
        self.supports_v2 && !self.supports_v1
    }

    /// Check if both versions are supported
    pub fn supports_both(&self) -> bool {
        self.supports_v1 && self.supports_v2
    }
}

/// Detects which DIDComm versions a DID supports
pub struct CapabilityDetector;

impl CapabilityDetector {
    /// Detect DIDComm version support from DID document
    ///
    /// Detection strategy:
    /// 1. Check service endpoints for version hints
    /// 2. Check verification method key formats
    /// 3. Default to supporting both if ambiguous
    pub fn detect_didcomm_support(did_doc: &DidDocument) -> DIDCommCapabilities {
        let mut caps = DIDCommCapabilities::default();

        // Check service endpoints
        for service in &did_doc.service {
            // Check service type - service.type_ is a String
            let svc_type = &service.type_;
            {
                trace!("Checking service type: {}", svc_type);

                // Modern DIDComm v2 service types
                if svc_type.contains("DIDCommMessaging") || svc_type.contains("DIDComm") {
                    debug!("Detected v2 support from service type: {}", svc_type);
                    caps.supports_v2 = true;
                }

                // Legacy DIDComm v1 service types
                if svc_type.contains("IndyAgent")
                    || svc_type.contains("did-communication")
                    || svc_type.contains("didcomm")
                {
                    // lowercase didcomm often v1
                    debug!("Detected v1 support from service type: {}", svc_type);
                    caps.supports_v1 = true;
                }
            }
        }

        // Check verification method key formats
        for vm in &did_doc.verification_method {
            trace!("Checking verification method: {:?}", vm.id);

            // Legacy base58 format indicates v1 support
            if vm.public_key_base58.is_some() {
                debug!("Detected v1 support from public_key_base58");
                caps.supports_v1 = true;
            }

            // Modern multibase format indicates v2 support
            if let Some(multibase) = &vm.public_key_multibase {
                // z6Mk... is Ed25519, z6LS... is X25519
                if multibase.starts_with("z6Mk") || multibase.starts_with("z6LS") {
                    debug!(
                        "Detected v2 support from publicKeyMultibase: {}",
                        &multibase[..8]
                    );
                    caps.supports_v2 = true;
                }
            }

            // JWK format can work with both
            if vm.public_key_jwk.is_some() {
                debug!("Detected JWK format (supports both v1 and v2)");
                caps.supports_v1 = true;
                caps.supports_v2 = true;
            }

            // Check verification method type - type_ is a String
            let vm_type = &vm.type_;
            // Modern types indicate v2
            if vm_type.contains("Multikey") || vm_type.contains("JsonWebKey2020") {
                debug!("Detected v2 support from VM type: {}", vm_type);
                caps.supports_v2 = true;
            }

            // Legacy types indicate v1
            if vm_type.contains("Ed25519VerificationKey2018")
                || vm_type.contains("X25519KeyAgreementKey2019")
            {
                debug!("Detected v1 support from VM type: {}", vm_type);
                caps.supports_v1 = true;
            }
        }

        // If no clear indicators, assume both for maximum compatibility
        // This is safer than assuming only one version
        if !caps.supports_v1 && !caps.supports_v2 {
            debug!("No clear version indicators found, assuming both v1 and v2 support");
            caps.supports_v1 = true;
            caps.supports_v2 = true;
        }

        debug!(
            "Capability detection complete: v1={}, v2={}",
            caps.supports_v1, caps.supports_v2
        );

        caps
    }

    /// Detect from a DID string by checking the DID method
    ///
    /// This is a fast heuristic based on DID method alone,
    /// without resolving the full DID document.
    pub fn detect_from_did_string(did: &str) -> DIDCommCapabilities {
        let mut caps = DIDCommCapabilities::default();

        if did.starts_with("did:peer:2") {
            // did:peer:2 is self-resolving — inspect the embedded `.S` service
            // TYPE instead of assuming v2 from the DID method. An Aries
            // `did-communication` service is DIDComm v1 (credo advertises exactly
            // this over a peer:2 DID); `dm` / DIDCommMessaging is v2. This mirrors
            // the service-type mapping in `detect_from_did_document` — the DID
            // method alone does not determine the protocol version.
            match peer2_service_type(did).as_deref() {
                Some(t) if t.contains("did-communication") || t == "IndyAgent" => {
                    debug!("did:peer:2 with v1 did-communication service detected");
                    caps.supports_v1 = true;
                    caps.supports_v2 = false;
                }
                _ => {
                    debug!("did:peer:2 (dm/DIDCommMessaging or undecodable) — preferring v2");
                    caps.supports_v2 = true;
                    caps.supports_v1 = true; // can fall back
                }
            }
        } else if did.starts_with("did:peer:") {
            // Other did:peer methods may use v1
            debug!("DID method did:peer detected, preferring v1");
            caps.supports_v1 = true;
            caps.supports_v2 = false;
        } else if did.starts_with("did:key:") {
            // did:key is modern, supports v2
            debug!("DID method did:key detected, preferring v2");
            caps.supports_v2 = true;
            caps.supports_v1 = true;
        } else if did.starts_with("did:sov:") || did.starts_with("did:indy:") {
            // Sovrin/Indy are legacy, likely v1 only
            debug!("DID method did:sov/indy detected, v1 only");
            caps.supports_v1 = true;
            caps.supports_v2 = false;
        } else {
            // Unknown method, assume both
            debug!("Unknown DID method, assuming both v1 and v2");
            caps.supports_v1 = true;
            caps.supports_v2 = true;
        }

        caps
    }
}

/// The service `type` of a did:peer:2 (`did-communication` for DIDComm v1,
/// `dm` / `DIDCommMessaging` for v2). Thin wrapper over the canonical
/// [`did::methods::peer::parse_peer2`] decoder.
fn peer2_service_type(did: &str) -> Option<String> {
    did::methods::peer::parse_peer2(did).and_then(|p| p.service_type)
}
