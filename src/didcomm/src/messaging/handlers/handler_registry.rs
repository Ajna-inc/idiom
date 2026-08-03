//! Handler Registry
//!
//! Maps message types to their handlers for dynamic message routing.
//!
//! This module provides platform-aware handler storage:
//! - Native: Uses `Arc<dyn MessageHandler>` for thread-safe sharing
//! - WASM: Uses `Rc<dyn MessageHandler>` for single-threaded environments

use super::traits::MessageHandler;
use std::collections::HashMap;

// Platform-specific smart pointer type for handlers
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
pub type HandlerRef = Arc<dyn MessageHandler>;

#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
pub type HandlerRef = Rc<dyn MessageHandler>;

/// Handler registry that maps message types to handlers
pub struct HandlerRegistry {
    handlers: HashMap<String, HandlerRef>,
}

impl HandlerRegistry {
    /// Create a new empty handler registry
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for its supported message types
    ///
    /// # Arguments
    /// * `handler` - The handler to register
    ///
    /// # Example (Native)
    /// ```rust,ignore
    /// use crate::messaging::HandlerRegistry;
    /// use std::sync::Arc;
    ///
    /// let mut registry = HandlerRegistry::new();
    /// registry.register(Arc::new(MyHandler));
    /// ```
    ///
    /// # Example (WASM)
    /// ```rust,ignore
    /// use crate::messaging::HandlerRegistry;
    /// use std::rc::Rc;
    ///
    /// let mut registry = HandlerRegistry::new();
    /// registry.register(Rc::new(MyHandler));
    /// ```
    pub fn register(&mut self, handler: HandlerRef) {
        for msg_type in handler.supported_types() {
            self.handlers.insert(msg_type, handler.clone());
        }
    }

    /// Get a handler for a specific message type
    ///
    /// # Arguments
    /// * `msg_type` - The message type URI
    ///
    /// # Returns
    /// The handler if found, None otherwise
    pub fn get_handler(&self, msg_type: &str) -> Option<HandlerRef> {
        self.handlers.get(msg_type).cloned()
    }

    /// Check if a handler is registered for a message type
    ///
    /// # Arguments
    /// * `msg_type` - The message type URI
    ///
    /// # Returns
    /// true if a handler is registered
    pub fn has_handler(&self, msg_type: &str) -> bool {
        self.handlers.contains_key(msg_type)
    }

    /// Get all registered message types
    pub fn registered_types(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Get the number of registered message types
    pub fn count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::traits::*;
    use super::*;
    use async_trait::async_trait;

    struct TestHandler {
        message_types: Vec<String>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[async_trait]
    impl MessageHandler for TestHandler {
        fn supported_types(&self) -> Vec<String> {
            self.message_types.clone()
        }

        async fn handle(&self, _message: InboundMessage) -> Result<Option<OutboundMessage>> {
            Ok(None)
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[async_trait(?Send)]
    impl MessageHandler for TestHandler {
        fn supported_types(&self) -> Vec<String> {
            self.message_types.clone()
        }

        async fn handle(&self, _message: InboundMessage) -> Result<Option<OutboundMessage>> {
            Ok(None)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn create_handler(types: Vec<String>) -> HandlerRef {
        Arc::new(TestHandler {
            message_types: types,
        })
    }

    #[cfg(target_arch = "wasm32")]
    fn create_handler(types: Vec<String>) -> HandlerRef {
        Rc::new(TestHandler {
            message_types: types,
        })
    }

    #[test]
    fn test_handler_registry_register() {
        let mut registry = HandlerRegistry::new();

        let handler = create_handler(vec![
            "https://didcomm.org/test/1.0/message".to_string(),
            "https://didcomm.org/test/1.0/response".to_string(),
        ]);

        registry.register(handler);

        assert_eq!(registry.count(), 2);
        assert!(registry.has_handler("https://didcomm.org/test/1.0/message"));
        assert!(registry.has_handler("https://didcomm.org/test/1.0/response"));
        assert!(!registry.has_handler("https://didcomm.org/other/1.0/message"));
    }

    #[test]
    fn test_handler_registry_get_handler() {
        let mut registry = HandlerRegistry::new();

        let handler = create_handler(vec!["https://didcomm.org/test/1.0/message".to_string()]);

        registry.register(handler);

        let retrieved = registry.get_handler("https://didcomm.org/test/1.0/message");
        assert!(retrieved.is_some());

        let not_found = registry.get_handler("https://didcomm.org/other/1.0/message");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_registered_types() {
        let mut registry = HandlerRegistry::new();

        let handler = create_handler(vec![
            "https://didcomm.org/test/1.0/message".to_string(),
            "https://didcomm.org/test/1.0/response".to_string(),
        ]);

        registry.register(handler);

        let types = registry.registered_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"https://didcomm.org/test/1.0/message".to_string()));
        assert!(types.contains(&"https://didcomm.org/test/1.0/response".to_string()));
    }
}
