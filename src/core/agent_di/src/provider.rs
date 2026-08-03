//! Service provider trait and implementations

use crate::{Lifecycle, Result};
use std::any::Any;
use std::sync::Arc;

/// Service provider trait
///
/// Providers are responsible for creating instances of services.
pub trait Provider: Send + Sync {
    /// Get the service type name
    fn type_name(&self) -> &str;

    /// Get the lifecycle
    fn lifecycle(&self) -> Lifecycle;

    /// Provide an instance
    fn provide(&self) -> Result<Arc<dyn Any + Send + Sync>>;
}

/// Singleton provider - creates instance once and caches it
pub struct SingletonProvider<T: Send + Sync + 'static> {
    type_name: String,
    instance: Arc<parking_lot::Mutex<Option<Arc<T>>>>,
    factory: Box<dyn Fn() -> Result<Arc<T>> + Send + Sync>,
}

impl<T: Send + Sync + 'static> SingletonProvider<T> {
    pub fn new<F>(factory: F) -> Self
    where
        F: Fn() -> Result<Arc<T>> + Send + Sync + 'static,
    {
        Self {
            type_name: std::any::type_name::<T>().to_string(),
            instance: Arc::new(parking_lot::Mutex::new(None)),
            factory: Box::new(factory),
        }
    }

    pub fn from_instance(instance: Arc<T>) -> Self {
        let instance_cell = Arc::new(parking_lot::Mutex::new(Some(instance.clone())));

        Self {
            type_name: std::any::type_name::<T>().to_string(),
            instance: instance_cell,
            factory: Box::new(move || Ok(instance.clone())),
        }
    }
}

impl<T: Send + Sync + 'static> Provider for SingletonProvider<T> {
    fn type_name(&self) -> &str {
        &self.type_name
    }

    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::Singleton
    }

    fn provide(&self) -> Result<Arc<dyn Any + Send + Sync>> {
        let mut guard = self.instance.lock();
        if let Some(instance) = guard.as_ref() {
            return Ok(instance.clone() as Arc<dyn Any + Send + Sync>);
        }

        // Create instance
        let instance = (self.factory)()?;
        *guard = Some(instance.clone());
        Ok(instance as Arc<dyn Any + Send + Sync>)
    }
}

/// Transient provider - creates new instance on each call
pub struct TransientProvider<T: Send + Sync + 'static> {
    type_name: String,
    factory: Box<dyn Fn() -> Result<Arc<T>> + Send + Sync>,
}

impl<T: Send + Sync + 'static> TransientProvider<T> {
    pub fn new<F>(factory: F) -> Self
    where
        F: Fn() -> Result<Arc<T>> + Send + Sync + 'static,
    {
        Self {
            type_name: std::any::type_name::<T>().to_string(),
            factory: Box::new(factory),
        }
    }
}

impl<T: Send + Sync + 'static> Provider for TransientProvider<T> {
    fn type_name(&self) -> &str {
        &self.type_name
    }

    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::Transient
    }

    fn provide(&self) -> Result<Arc<dyn Any + Send + Sync>> {
        let instance = (self.factory)()?;
        Ok(instance as Arc<dyn Any + Send + Sync>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DependencyError;

    struct TestService {
        value: String,
    }

    #[test]
    fn test_singleton_provider() {
        let provider = SingletonProvider::new(|| {
            Ok(Arc::new(TestService {
                value: "test".to_string(),
            }))
        });

        assert_eq!(provider.lifecycle(), Lifecycle::Singleton);

        // First call creates instance
        let instance1 = provider.provide().unwrap();
        let service1 = instance1.downcast::<TestService>().unwrap();
        assert_eq!(service1.value, "test");

        // Second call returns same instance
        let instance2 = provider.provide().unwrap();
        let service2 = instance2.downcast::<TestService>().unwrap();

        // Should be same Arc
        assert!(Arc::ptr_eq(&service1, &service2));
    }

    #[test]
    fn test_singleton_from_instance() {
        let instance = Arc::new(TestService {
            value: "test".to_string(),
        });
        let provider = SingletonProvider::from_instance(instance.clone());

        let resolved = provider.provide().unwrap();
        let service = resolved.downcast::<TestService>().unwrap();

        assert!(Arc::ptr_eq(&instance, &service));
    }

    #[test]
    fn test_transient_provider() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let provider = TransientProvider::new(move || {
            let value = counter_clone.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(TestService {
                value: format!("test-{}", value),
            }))
        });

        assert_eq!(provider.lifecycle(), Lifecycle::Transient);

        // Each call creates new instance
        let instance1 = provider.provide().unwrap();
        let instance2 = provider.provide().unwrap();

        // Should be different Arcs
        assert!(!Arc::ptr_eq(
            &instance1.downcast::<TestService>().unwrap(),
            &instance2.downcast::<TestService>().unwrap()
        ));
    }

    #[test]
    fn test_provider_error() {
        let provider: SingletonProvider<TestService> =
            SingletonProvider::new(|| Err(DependencyError::resolution_failed("test error")));

        let result = provider.provide();
        assert!(result.is_err());
    }
}
