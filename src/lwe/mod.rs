//! LWE (Learning With Errors) encryption module
//!
//! This module implements LWE encryption for the InsPIRe PIR protocol.
//!
//! # Key Types
//! - [`LweSecretKey`]: Secret key vector sampled from error distribution
//! - [`LweCiphertext`]: Ciphertext pair (a, b) supporting homomorphic operations
//!
//! # CRS Model
//! In the Common Reference String model, the random vector `a` is fixed
//! and publicly known. This enables query compression where clients only
//! send the `b` component of each ciphertext.

mod enc;
mod types;

pub use types::{LweCiphertext, LweSecretKey};
