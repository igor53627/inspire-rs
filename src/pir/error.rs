//! Error handling for PIR module
//!
//! Uses eyre when the cli feature is enabled, otherwise uses a simple error type.

#[cfg(feature = "cli")]
pub use eyre::Result;

#[cfg(feature = "cli")]
macro_rules! pir_err {
    ($($arg:tt)*) => {
        eyre::eyre!($($arg)*)
    };
}

#[cfg(not(feature = "cli"))]
pub type Result<T> = std::result::Result<T, PirError>;

#[cfg(not(feature = "cli"))]
#[derive(Debug)]
pub struct PirError(pub String);

#[cfg(not(feature = "cli"))]
impl std::fmt::Display for PirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(not(feature = "cli"))]
impl std::error::Error for PirError {}

#[cfg(not(feature = "cli"))]
macro_rules! pir_err {
    ($($arg:tt)*) => {
        $crate::pir::error::PirError(format!($($arg)*))
    };
}

pub(crate) use pir_err;
