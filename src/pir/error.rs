//! Error handling for PIR module
//!
//! Provides a stable `PirError` type that works across all feature configurations.
//! This ensures the public API doesn't change based on enabled features.

use std::fmt;

/// PIR operation error
///
/// A simple, stable error type for PIR operations that works in all environments
/// including WASM. This type is always the same regardless of feature flags.
#[derive(Debug)]
pub struct PirError(pub String);

impl fmt::Display for PirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PirError {}

impl PirError {
    /// Create a new PIR error with the given message
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl From<std::io::Error> for PirError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<bincode::Error> for PirError {
    fn from(err: bincode::Error) -> Self {
        Self(err.to_string())
    }
}

/// Result type for PIR operations
///
/// Always uses `PirError` regardless of feature flags for API stability.
pub type Result<T> = std::result::Result<T, PirError>;

/// Create a PirError with format string support
macro_rules! pir_err {
    ($($arg:tt)*) => {
        $crate::pir::error::PirError(format!($($arg)*))
    };
}

pub(crate) use pir_err;
