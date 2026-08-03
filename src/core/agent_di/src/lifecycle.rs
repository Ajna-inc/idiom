//! Service lifecycle management

/// Service lifecycle types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lifecycle {
    /// Single instance shared across all resolutions
    #[default]
    Singleton,

    /// Single instance per scope
    Scoped,

    /// New instance on each resolution
    Transient,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_default() {
        assert_eq!(Lifecycle::default(), Lifecycle::Singleton);
    }

    #[test]
    fn test_lifecycle_equality() {
        assert_eq!(Lifecycle::Singleton, Lifecycle::Singleton);
        assert_ne!(Lifecycle::Singleton, Lifecycle::Transient);
    }
}
