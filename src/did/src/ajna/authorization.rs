//! Authorization Engine for did:ajna
//!
//! This module implements the authorization logic for did:ajna operations,
//! including policy evaluation, quorum checking, and controller authorization.

use crate::ajna::{
    document::AjnaDocument,
    operation_v2::{Delta, Operation},
    Result,
};
use std::collections::HashSet;

/// Authorization context for evaluating operations
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    /// The DID being updated
    pub did: String,

    /// The actor performing the operation
    pub actor: String,

    /// Additional signatures (for multi-sig operations)
    pub additional_signatures: Vec<String>,

    /// Current document state
    pub document: AjnaDocument,
}

/// Authorization result
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizationResult {
    /// Operation is authorized
    Allowed,

    /// Operation is denied
    Denied(String),

    /// Operation requires additional signatures
    RequiresQuorum {
        required: usize,
        current: usize,
        missing: usize,
    },
}

impl AuthorizationResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthorizationResult::Allowed)
    }
}

/// Authorization engine for did:ajna operations
pub struct AuthorizationEngine;

impl AuthorizationEngine {
    /// Authorize an operation against a document's policy
    ///
    /// # Arguments
    /// * `operation` - The operation to authorize
    /// * `context` - Authorization context
    ///
    /// # Returns
    /// Authorization result
    pub fn authorize(
        operation: &Operation,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationResult> {
        let doc = &context.document;

        // Check if document is deactivated
        if doc.is_deactivated() {
            return Ok(AuthorizationResult::Denied(
                "Cannot modify deactivated DID".to_string(),
            ));
        }

        // Check actor is authorized
        if !Self::is_actor_authorized(&context.actor, doc, &operation.delta) {
            return Ok(AuthorizationResult::Denied(format!(
                "Actor {} is not authorized",
                context.actor
            )));
        }

        // Check quorum requirements
        let quorum_result = Self::check_quorum(operation, context)?;
        if !quorum_result.is_allowed() {
            return Ok(quorum_result);
        }

        // Check operation-specific authorization
        Self::authorize_delta(&operation.delta, context)
    }

    /// Check if an actor is authorized to perform an operation
    fn is_actor_authorized(actor: &str, doc: &AjnaDocument, delta: &Delta) -> bool {
        // Self-controlled: actor must be the DID itself
        if !doc.controller.is_some() {
            return actor == doc.id;
        }

        // Multi-controlled: actor must be a controller
        if doc.is_controller(actor) {
            return true;
        }

        // For some operations, the DID itself is always authorized
        match delta {
            Delta::VmAdd { .. }
            | Delta::VmRemove { .. }
            | Delta::RefAdd { .. }
            | Delta::RefRemove { .. } => {
                // Key management: DID or controllers
                actor == doc.id || doc.is_controller(actor)
            }
            Delta::ServiceAdd { .. } | Delta::ServiceRemove { .. } => {
                // Service management: DID or controllers
                actor == doc.id || doc.is_controller(actor)
            }
            Delta::ControllerAdd { .. } | Delta::ControllerRemove { .. } => {
                // Controller changes: requires controller authorization
                doc.is_controller(actor)
            }
            Delta::PropSet { .. } => {
                // Policy changes: requires controller authorization
                doc.is_controller(actor)
            }
            Delta::Deactivate { .. } => {
                // Deactivation: DID or controllers
                actor == doc.id || doc.is_controller(actor)
            }
        }
    }

    /// Check quorum requirements for multi-sig operations
    fn check_quorum(
        operation: &Operation,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationResult> {
        let doc = &context.document;

        // Get quorum requirements from policy
        let quorum_required = Self::get_quorum_requirement(&operation.delta, doc)?;

        if quorum_required <= 1 {
            // No quorum required
            return Ok(AuthorizationResult::Allowed);
        }

        // Count signatures (actor + additional)
        let mut signers = HashSet::new();
        signers.insert(context.actor.clone());
        for sig in &context.additional_signatures {
            signers.insert(sig.clone());
        }

        let current_signatures = signers.len();

        if current_signatures >= quorum_required {
            Ok(AuthorizationResult::Allowed)
        } else {
            Ok(AuthorizationResult::RequiresQuorum {
                required: quorum_required,
                current: current_signatures,
                missing: quorum_required - current_signatures,
            })
        }
    }

    /// Get quorum requirement for an operation from policy
    fn get_quorum_requirement(delta: &Delta, doc: &AjnaDocument) -> Result<usize> {
        // Check policy for operation-specific quorum
        let policy_key = match delta {
            Delta::VmAdd { .. } | Delta::VmRemove { .. } => "auth.quorum.vm",
            Delta::RefAdd { .. } | Delta::RefRemove { .. } => "auth.quorum.vm",
            Delta::ServiceAdd { .. } | Delta::ServiceRemove { .. } => "auth.quorum.service",
            Delta::ControllerAdd { .. } | Delta::ControllerRemove { .. } => {
                "auth.quorum.controller"
            }
            Delta::PropSet { .. } => "auth.quorum.policy",
            Delta::Deactivate { .. } => "auth.quorum.deactivate",
        };

        // Check specific policy first
        if let Some(quorum) = doc.get_policy_int(policy_key) {
            return Ok(quorum as usize);
        }

        // Check general update quorum
        if let Some(quorum) = doc.get_policy_int("auth.quorum.update") {
            return Ok(quorum as usize);
        }

        // Default: single signature
        Ok(1)
    }

    /// Authorize specific delta type
    fn authorize_delta(
        delta: &Delta,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationResult> {
        let doc = &context.document;

        match delta {
            Delta::VmAdd { entry } => {
                // Verify the verification method references this DID
                if !entry.id.starts_with(&doc.id) {
                    return Ok(AuthorizationResult::Denied(
                        "Verification method must reference this DID".to_string(),
                    ));
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::VmRemove { id } => {
                // Verify the verification method exists
                if doc.get_verification_method(id).is_none() {
                    return Ok(AuthorizationResult::Denied(
                        "Verification method not found".to_string(),
                    ));
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::RefAdd { purpose: _, ref_ } => {
                // Verify the referenced verification method exists
                if doc.get_verification_method(ref_).is_none() {
                    return Ok(AuthorizationResult::Denied(format!(
                        "Referenced verification method not found: {}",
                        ref_
                    )));
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::RefRemove { .. } => {
                // Always allow removing references
                Ok(AuthorizationResult::Allowed)
            }

            Delta::ServiceAdd { entry } => {
                // Verify service ID is valid
                if entry.id.is_empty() {
                    return Ok(AuthorizationResult::Denied(
                        "Service ID cannot be empty".to_string(),
                    ));
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::ServiceRemove { .. } => {
                // Always allow removing services
                Ok(AuthorizationResult::Allowed)
            }

            Delta::PropSet { key, .. } => {
                // Check if policy modifications are restricted
                if key.starts_with("auth.") {
                    // Authorization policies require controller permission
                    if !doc.is_controller(&context.actor) {
                        return Ok(AuthorizationResult::Denied(
                            "Only controllers can modify auth policies".to_string(),
                        ));
                    }
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::ControllerAdd { did } => {
                // Verify new controller DID is valid
                if !did.starts_with("did:") {
                    return Ok(AuthorizationResult::Denied(
                        "Invalid controller DID format".to_string(),
                    ));
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::ControllerRemove { did: _ } => {
                // Prevent removing all controllers
                if let Some(controllers) = &doc.controller {
                    if controllers.len() <= 1 {
                        return Ok(AuthorizationResult::Denied(
                            "Cannot remove last controller".to_string(),
                        ));
                    }
                }
                Ok(AuthorizationResult::Allowed)
            }

            Delta::Deactivate { .. } => {
                // Always allow deactivation if actor is authorized
                Ok(AuthorizationResult::Allowed)
            }
        }
    }

    /// Check if an operation can be applied to a document
    ///
    /// This performs authorization checks (but not signature verification)
    /// Note: Signature verification must be done separately by the caller
    /// using operation.verify_signature(verifying_key)
    pub fn can_apply(
        operation: &Operation,
        document: &AjnaDocument,
    ) -> Result<AuthorizationResult> {
        // Note: Signature verification is skipped here because it requires
        // resolving the actor's DID to get their public key. The caller
        // should verify the signature before calling this method.

        // Create authorization context
        let context = AuthorizationContext {
            did: operation.doc.clone(),
            actor: operation.actor.clone(),
            additional_signatures: vec![],
            document: document.clone(),
        };

        // Authorize operation
        Self::authorize(operation, &context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ajna::document::VerificationMethod;
    use crate::ajna::operation_v2::ClockEntry;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn create_test_context(did: &str, actor: &str) -> AuthorizationContext {
        let doc = AjnaDocument::new(did.to_string(), "node1".to_string());
        AuthorizationContext {
            did: did.to_string(),
            actor: actor.to_string(),
            additional_signatures: vec![],
            document: doc,
        }
    }

    fn create_test_operation(actor: &str, delta: Delta) -> Operation {
        let signing_key = SigningKey::generate(&mut OsRng);
        Operation::new(
            "did:ajna:test123".to_string(),
            vec![],
            actor.to_string(),
            ClockEntry {
                actor_id: 1, // Use numeric actor ID
                counter: 1,
            },
            delta,
            &signing_key,
            format!("{}#key-1", actor),
        )
        .unwrap()
    }

    #[test]
    fn test_self_controlled_authorization() {
        let did = "did:ajna:test123";
        let context = create_test_context(did, did);

        // Self-controlled DID can add verification method
        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(did, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn test_unauthorized_actor() {
        let did = "did:ajna:test123";
        let attacker = "did:ajna:attacker";
        let context = create_test_context(did, attacker);

        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(attacker, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_controller_authorization() {
        let did = "did:ajna:test123";
        let controller = "did:ajna:controller1";

        // Create document with controller
        let doc = AjnaDocument::new_with_genesis(
            did.to_string(),
            "node1".to_string(),
            vec![controller.to_string()],
            vec![],
        );

        let context = AuthorizationContext {
            did: did.to_string(),
            actor: controller.to_string(),
            additional_signatures: vec![],
            document: doc,
        };

        // Controller can add verification method
        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(controller, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn test_quorum_requirement() {
        let did = "did:ajna:test123";
        let controller1 = "did:ajna:controller1";

        // Create document with quorum requirement
        let doc = AjnaDocument::new_with_genesis(
            did.to_string(),
            "node1".to_string(),
            vec![controller1.to_string()],
            vec![("auth.quorum.update".to_string(), serde_json::json!(2))],
        );

        let context = AuthorizationContext {
            did: did.to_string(),
            actor: controller1.to_string(),
            additional_signatures: vec![], // No additional signatures
            document: doc,
        };

        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(controller1, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();

        // Should require quorum
        match result {
            AuthorizationResult::RequiresQuorum {
                required,
                current,
                missing,
            } => {
                assert_eq!(required, 2);
                assert_eq!(current, 1);
                assert_eq!(missing, 1);
            }
            _ => panic!("Expected RequiresQuorum"),
        }
    }

    #[test]
    fn test_quorum_satisfied() {
        let did = "did:ajna:test123";
        let controller1 = "did:ajna:controller1";
        let controller2 = "did:ajna:controller2";

        let doc = AjnaDocument::new_with_genesis(
            did.to_string(),
            "node1".to_string(),
            vec![controller1.to_string(), controller2.to_string()],
            vec![("auth.quorum.update".to_string(), serde_json::json!(2))],
        );

        let context = AuthorizationContext {
            did: did.to_string(),
            actor: controller1.to_string(),
            additional_signatures: vec![controller2.to_string()], // Second signature
            document: doc,
        };

        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(controller1, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn test_deactivated_document() {
        let did = "did:ajna:test123";
        let mut doc = AjnaDocument::new(did.to_string(), "node1".to_string());

        // Deactivate document
        doc.apply_delta_v2(&Delta::Deactivate { reason: None })
            .unwrap();

        let context = AuthorizationContext {
            did: did.to_string(),
            actor: did.to_string(),
            additional_signatures: vec![],
            document: doc,
        };

        // Cannot modify deactivated DID
        let delta = Delta::VmAdd {
            entry: VerificationMethod {
                id: format!("{}#key-1", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: "z6Mktest".to_string(),
                purpose: None,
            },
        };

        let op = create_test_operation(did, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_cannot_remove_last_controller() {
        let did = "did:ajna:test123";
        let controller = "did:ajna:controller1";

        let doc = AjnaDocument::new_with_genesis(
            did.to_string(),
            "node1".to_string(),
            vec![controller.to_string()],
            vec![],
        );

        let context = AuthorizationContext {
            did: did.to_string(),
            actor: controller.to_string(),
            additional_signatures: vec![],
            document: doc,
        };

        // Try to remove the only controller
        let delta = Delta::ControllerRemove {
            did: controller.to_string(),
        };

        let op = create_test_operation(controller, delta);
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_policy_modification_requires_controller() {
        let did = "did:ajna:test123";
        let controller = "did:ajna:controller1";

        let doc = AjnaDocument::new_with_genesis(
            did.to_string(),
            "node1".to_string(),
            vec![controller.to_string()],
            vec![],
        );

        // Non-controller tries to modify auth policy
        let context = AuthorizationContext {
            did: did.to_string(),
            actor: did.to_string(), // Not the controller
            additional_signatures: vec![],
            document: doc.clone(),
        };

        let delta = Delta::PropSet {
            key: "auth.quorum.update".to_string(),
            value: serde_json::json!(2),
            ts: 1000,
        };

        let op = create_test_operation(did, delta.clone());
        let result = AuthorizationEngine::authorize(&op, &context).unwrap();
        assert!(!result.is_allowed());

        // Controller can modify auth policy
        let context2 = AuthorizationContext {
            did: did.to_string(),
            actor: controller.to_string(),
            additional_signatures: vec![],
            document: doc,
        };

        let op2 = create_test_operation(controller, delta);
        let result2 = AuthorizationEngine::authorize(&op2, &context2).unwrap();
        assert!(result2.is_allowed());
    }
}
