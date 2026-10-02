//! Dependency injection container

use crate::{
    provider::{SingletonProvider, TransientProvider},
    DependencyError, Lifecycle, Provider, Result,
};
use std::any::TypeId;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// One frame of a resolution chain: which container is resolving which type.
///
/// The container is identified by its registration table, which clones share,
/// so a factory that resolves through a clone of its own container is still
/// in the same chain.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Frame {
    container: usize,
    type_id: TypeId,
    type_name: &'static str,
}

thread_local! {
    /// The resolution chains in flight on this thread, innermost last.
    ///
    /// Cycle detection is per chain, not per container: a chain only ever
    /// grows through a factory calling `resolve` again, and factories are
    /// synchronous, so a chain lives entirely on the thread that started it.
    /// Two concurrent `resolve`s of the same type on different threads are
    /// independent chains and must never see each other.
    static RESOLUTION_STACK: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

/// Pops the frame pushed for one `resolve` call when that call ends, however
/// it ends — a factory that panics must not leave its frame behind.
struct FrameGuard;

impl Drop for FrameGuard {
    fn drop(&mut self) {
        // `try_with`: the thread may be tearing its locals down already.
        let _ = RESOLUTION_STACK.try_with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

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
}

impl Container {
    /// Create a new container
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Identity shared by this container and its clones.
    fn identity(&self) -> usize {
        Arc::as_ptr(&self.providers) as *const () as usize
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
        let frame = Frame {
            container: self.identity(),
            type_id,
            type_name: std::any::type_name::<T>(),
        };

        // A cycle is this container asking for a type that is already being
        // resolved further up this very chain.
        let cycle = RESOLUTION_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.contains(&frame) {
                let path = stack
                    .iter()
                    .filter(|f| f.container == frame.container)
                    .chain(std::iter::once(&frame))
                    .map(|f| f.type_name)
                    .collect::<Vec<_>>()
                    .join(" -> ");
                Some(path)
            } else {
                stack.push(frame);
                None
            }
        });
        if let Some(path) = cycle {
            return Err(DependencyError::circular_dependency(path));
        }
        let _frame = FrameGuard;

        self.resolve_internal::<T>(type_id)
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

    /// Two tasks resolving the same registered type at the same time are
    /// independent resolution chains, not a cycle. The first caller is parked
    /// inside the factory until the second has resolved, so the two calls are
    /// guaranteed to overlap.
    #[test]
    fn concurrent_resolves_of_the_same_type_are_not_a_cycle() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let calls = AtomicUsize::new(0);

        let mut container = Container::new();
        container.register_transient_with_factory::<CustomTestService, CustomTestService, _>(
            move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered_tx.send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                }
                Ok(Arc::new(CustomTestService { value: 7 }))
            },
        );
        let container = Arc::new(container);

        let first = {
            let container = Arc::clone(&container);
            std::thread::spawn(move || container.resolve::<CustomTestService>())
        };
        entered_rx.recv().unwrap();

        // Overlaps the first resolve, which is still inside its factory.
        let second = container.resolve::<CustomTestService>();
        release_tx.send(()).unwrap();

        assert!(
            second.is_ok(),
            "a concurrent resolve of the same type must not be reported as a cycle: {:?}",
            second.err()
        );
        assert!(first.join().unwrap().is_ok());
        // Both chains finished; nothing may be left behind for the next resolve.
        assert!(container.resolve::<CustomTestService>().is_ok());
    }

    /// A factory that resolves a dependency of its own is a nested chain on
    /// the same thread and resolves normally.
    #[test]
    fn a_nested_dependency_resolves() {
        #[derive(Default)]
        struct Leaf;
        struct Root(#[allow(dead_code)] Arc<Leaf>);

        let handle: Arc<std::sync::OnceLock<Container>> = Arc::new(std::sync::OnceLock::new());
        let mut container = Container::new();
        container.register_singleton::<Leaf, Leaf>();
        let h = Arc::clone(&handle);
        container.register_singleton_with_factory::<Root, Root, _>(move || {
            Ok(Arc::new(Root(h.get().unwrap().resolve::<Leaf>()?)))
        });
        handle.set(container.clone()).ok();

        assert!(container.resolve::<Root>().is_ok());
        assert!(container.resolve::<Root>().is_ok());
    }

    /// A genuine A -> B -> A cycle is still reported, including through a
    /// clone of the container (clones share the registrations, so they are
    /// the same container for cycle purposes).
    #[test]
    fn a_genuine_cycle_is_still_detected() {
        struct A;
        struct B;

        let handle: Arc<std::sync::OnceLock<Container>> = Arc::new(std::sync::OnceLock::new());
        let mut container = Container::new();
        let h = Arc::clone(&handle);
        container.register_transient_with_factory::<A, A, _>(move || {
            h.get().unwrap().resolve::<B>()?;
            Ok(Arc::new(A))
        });
        let h = Arc::clone(&handle);
        container.register_transient_with_factory::<B, B, _>(move || {
            h.get().unwrap().resolve::<A>()?;
            Ok(Arc::new(B))
        });
        handle.set(container.clone()).ok();

        match container.resolve::<A>() {
            Err(DependencyError::CircularDependency { path }) => {
                assert!(path.contains("::A"), "path names the cycle: {path}");
                assert!(path.contains("::B"), "path names the cycle: {path}");
            }
            other => panic!("expected CircularDependency, got {:?}", other.map(|_| ())),
        }
        // The failed chain unwound cleanly: the same report again, not a
        // stale frame breaking the next chain in a different way.
        assert!(matches!(
            container.resolve::<B>(),
            Err(DependencyError::CircularDependency { .. })
        ));
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
