//! Dependency injection container

use crate::{
    provider::{SingletonProvider, TransientProvider},
    DependencyError, Lifecycle, Provider, Result,
};
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Dependency injection container
///
/// The container manages service registration and resolution with lifecycle support.
///
/// # Example
///
/// ```rust
/// use agent_di::Container;
/// use std::sync::Arc;
///
/// struct MyService {
///     name: String,
/// }
///
/// impl Default for MyService {
///     fn default() -> Self {
///         Self { name: "test".to_string() }
///     }
/// }
///
/// let mut container = Container::new();
/// container.register_singleton::<MyService, MyService>();
///
/// let service = container.resolve::<MyService>().unwrap();
/// assert_eq!(service.name, "test");
/// ```
///
/// # Trait Objects
///
/// The container can be keyed by trait objects, but resolution works with concrete types:
///
/// ```rust
/// # use agent_di::Container;
/// # use std::sync::Arc;
/// trait MyTrait: Send + Sync {
///     fn name(&self) -> &str;
/// }
///
/// struct MyImpl;
/// impl MyTrait for MyImpl {
///     fn name(&self) -> &str { "test" }
/// }
///
/// let mut container = Container::new();
/// // Register with trait object key
/// container.register_singleton_with_factory::<dyn MyTrait, MyImpl, _>(|| {
///     Ok(Arc::new(MyImpl))
/// });
///
/// assert!(container.is_registered::<dyn MyTrait>());
/// ```
pub struct Container {
    providers: Arc<RwLock<HashMap<TypeId, Box<dyn Provider>>>>,
    resolution_stack: Arc<RwLock<Vec<TypeId>>>,
}

impl Container {
    /// Create a new container
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            resolution_stack: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a singleton service with a factory
    ///
    /// The factory will be called once to create the instance.
    pub fn register_singleton<T, I>(&mut self)
    where
        T: ?Sized + Send + Sync + 'static,
        I: Default + Send + Sync + 'static,
    {
        self.register_singleton_with_factory::<T, I, _>(|| Ok(Arc::new(I::default())))
    }

    /// Register a singleton service with a custom factory
    pub fn register_singleton_with_factory<T, I, F>(&mut self, factory: F)
    where
        T: ?Sized + Send + Sync + 'static,
        I: Send + Sync + 'static,
        F: Fn() -> Result<Arc<I>> + Send + Sync + 'static,
    {
        let provider = SingletonProvider::new(factory);
        let type_id = TypeId::of::<T>();

        let mut providers = self.providers.write().unwrap();
        providers.insert(type_id, Box::new(provider));
    }

    /// Register a singleton instance
    pub fn register_instance<T, I>(&mut self, instance: I)
    where
        T: ?Sized + Send + Sync + 'static,
        I: Send + Sync + 'static,
    {
        let provider = SingletonProvider::from_instance(Arc::new(instance));
        let type_id = TypeId::of::<T>();

        let mut providers = self.providers.write().unwrap();
        providers.insert(type_id, Box::new(provider));
    }

    /// Register a transient service with a factory
    ///
    /// The factory will be called on each resolution.
    pub fn register_transient<T, I>(&mut self)
    where
        T: ?Sized + Send + Sync + 'static,
        I: Default + Send + Sync + 'static,
    {
        self.register_transient_with_factory::<T, I, _>(|| Ok(Arc::new(I::default())))
    }

    /// Register a transient service with a custom factory
    pub fn register_transient_with_factory<T, I, F>(&mut self, factory: F)
    where
        T: ?Sized + Send + Sync + 'static,
        I: Send + Sync + 'static,
        F: Fn() -> Result<Arc<I>> + Send + Sync + 'static,
    {
        let provider = TransientProvider::new(factory);
        let type_id = TypeId::of::<T>();

        let mut providers = self.providers.write().unwrap();
        providers.insert(type_id, Box::new(provider));
    }

    /// Check if a service is registered
    pub fn is_registered<T: ?Sized + 'static>(&self) -> bool {
        let type_id = TypeId::of::<T>();
        let providers = self.providers.read().unwrap();
        providers.contains_key(&type_id)
    }

    /// Resolve a service
    ///
    /// Note: T must be `Sized` due to limitations of `Arc::downcast`.
    /// For trait objects, register and resolve as `dyn Trait` which is sized.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The service is not registered
    /// - A circular dependency is detected
    /// - The service factory fails
    pub fn resolve<T: Send + Sync + 'static>(&self) -> Result<Arc<T>> {
        let type_id = TypeId::of::<T>();

        // Check for circular dependencies
        {
            let mut stack = self.resolution_stack.write().unwrap();
            if stack.contains(&type_id) {
                let path = stack
                    .iter()
                    .map(|id| format!("{:?}", id))
                    .collect::<Vec<_>>()
                    .join(" -> ");
                return Err(DependencyError::circular_dependency(path));
            }
            stack.push(type_id);
        }

        // Resolve
        let result = self.resolve_internal::<T>(type_id);

        // Pop from resolution stack
        {
            let mut stack = self.resolution_stack.write().unwrap();
            stack.pop();
        }

        result
    }

    fn resolve_internal<T: Send + Sync + 'static>(&self, type_id: TypeId) -> Result<Arc<T>> {
        let providers = self.providers.read().unwrap();

        let provider = providers
            .get(&type_id)
            .ok_or_else(|| DependencyError::not_registered(std::any::type_name::<T>()))?;

        let instance = provider.provide()?;

        // Downcast to the requested type
        instance.downcast::<T>().map_err(|_| {
            DependencyError::resolution_failed(format!(
                "Failed to downcast to {}",
                std::any::type_name::<T>()
            ))
        })
    }

    /// Try to resolve a service, returning None if not registered
    pub fn try_resolve<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.resolve().ok()
    }

    /// Get the lifecycle of a registered service
    pub fn get_lifecycle<T: 'static>(&self) -> Option<Lifecycle> {
        let type_id = TypeId::of::<T>();
        let providers = self.providers.read().unwrap();
        providers.get(&type_id).map(|p| p.lifecycle())
    }

    /// Clear all registrations
    pub fn clear(&mut self) {
        let mut providers = self.providers.write().unwrap();
        providers.clear();
    }

    /// Get the number of registered services
    pub fn len(&self) -> usize {
        let providers = self.providers.read().unwrap();
        providers.len()
    }

    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Container {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Container {
    fn clone(&self) -> Self {
        Self {
            providers: Arc::clone(&self.providers),
            resolution_stack: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Concrete test service types (not trait objects)
    #[derive(Default)]
    struct TestServiceImpl {
        value: u32,
    }

    impl TestServiceImpl {
        fn value(&self) -> u32 {
            self.value
        }
    }

    struct CustomTestService {
        value: u32,
    }

    impl CustomTestService {
        fn value(&self) -> u32 {
            self.value
        }
    }

    #[test]
    fn test_register_and_resolve_singleton() {
        let mut container = Container::new();
        container.register_singleton::<TestServiceImpl, TestServiceImpl>();

        assert!(container.is_registered::<TestServiceImpl>());
        assert_eq!(container.len(), 1);

        let service1 = container.resolve::<TestServiceImpl>().unwrap();
        let service2 = container.resolve::<TestServiceImpl>().unwrap();

        // Should be same instance (singleton)
        assert!(Arc::ptr_eq(&service1, &service2));
    }

    #[test]
    fn test_register_instance() {
        let mut container = Container::new();
        let instance = TestServiceImpl { value: 42 };

        container.register_instance::<TestServiceImpl, _>(instance);

        let service = container.resolve::<TestServiceImpl>().unwrap();
        assert_eq!(service.value(), 42);
    }

    #[test]
    fn test_register_singleton_with_factory() {
        let mut container = Container::new();
        container.register_singleton_with_factory::<CustomTestService, CustomTestService, _>(
            || Ok(Arc::new(CustomTestService { value: 100 })),
        );

        let service = container.resolve::<CustomTestService>().unwrap();
        assert_eq!(service.value(), 100);
    }

    #[test]
    fn test_register_and_resolve_transient() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let mut container = Container::new();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        container.register_transient_with_factory::<CustomTestService, CustomTestService, _>(
            move || {
                let value = counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(CustomTestService { value }))
            },
        );

        let service1 = container.resolve::<CustomTestService>().unwrap();
        let service2 = container.resolve::<CustomTestService>().unwrap();

        // Should be different instances (transient)
        assert!(!Arc::ptr_eq(&service1, &service2));

        // Verify values are different (incremented)
        assert_eq!(service1.value(), 0);
        assert_eq!(service2.value(), 1);
    }

    #[test]
    fn test_not_registered_error() {
        let container = Container::new();
        let result = container.resolve::<TestServiceImpl>();

        assert!(result.is_err());
        if let Err(DependencyError::NotRegistered(_)) = result {
            // Test passed
        } else {
            panic!("Expected NotRegistered error");
        }
    }

    #[test]
    fn test_try_resolve() {
        let mut container = Container::new();
        container.register_singleton::<TestServiceImpl, TestServiceImpl>();

        assert!(container.try_resolve::<TestServiceImpl>().is_some());
        assert!(container.try_resolve::<String>().is_none());
    }

    #[test]
    fn test_get_lifecycle() {
        let mut container = Container::new();
        container.register_singleton::<TestServiceImpl, TestServiceImpl>();

        assert_eq!(
            container.get_lifecycle::<TestServiceImpl>(),
            Some(Lifecycle::Singleton)
        );
        assert_eq!(container.get_lifecycle::<String>(), None);
    }

    #[test]
    fn test_clear() {
        let mut container = Container::new();
        container.register_singleton::<TestServiceImpl, TestServiceImpl>();
        assert_eq!(container.len(), 1);

        container.clear();
        assert_eq!(container.len(), 0);
        assert!(container.is_empty());
    }

    #[test]
    fn test_container_clone() {
        let mut container = Container::new();
        container.register_singleton::<TestServiceImpl, TestServiceImpl>();

        let cloned = container.clone();

        // Both should be able to resolve
        assert!(container.resolve::<TestServiceImpl>().is_ok());
        assert!(cloned.resolve::<TestServiceImpl>().is_ok());
    }

    #[test]
    fn test_register_trait_object() {
        // Demonstrate how to use trait objects with the container
        trait TestService: Send + Sync {
            #[allow(dead_code)] // demonstrates trait-object registration; not called
            fn name(&self) -> &str;
        }

        struct ConcreteService;
        impl TestService for ConcreteService {
            fn name(&self) -> &str {
                "concrete"
            }
        }

        let mut container = Container::new();

        // Register concrete type, keyed by trait object TypeId
        // The factory returns the concrete type
        container.register_singleton_with_factory::<dyn TestService, ConcreteService, _>(|| {
            Ok(Arc::new(ConcreteService))
        });

        // Note: Due to Rust's type system limitations with Arc::downcast,
        // we cannot directly resolve as `Arc<dyn TestService>`.
        // The registration works, but resolution requires concrete types.
        // In real usage, modules will resolve their concrete dependencies.

        assert!(container.is_registered::<dyn TestService>());
    }

    // Note: Circular dependency test would require a more complex setup
    // with services that depend on each other. This is best tested with
    // real modules that have actual dependencies.
}
