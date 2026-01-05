//! LWE (Learning With Errors) encryption module.
//!
//! This module implements LWE encryption for the InsPIRe PIR protocol.
//! LWE is the foundation for extracting scalar ciphertexts from RLWE
//! ring ciphertexts during the PIR response phase.
//!
//! # Overview
//!
//! LWE encryption works over vectors in Z_q^d rather than polynomial rings.
//! A ciphertext (a, b) encrypts message m as:
//!
//! ```text
//! b = -<a, s> + e + Δ·m
//! ```
//!
//! where s is the secret key, e is a small error, and Δ = ⌊q/p⌋ is the
//! scaling factor for plaintext space Z_p.
//!
//! # Key Types
//!
//! - [`LweSecretKey`]: Secret key vector sampled from error distribution
//! - [`LweCiphertext`]: Ciphertext pair (a, b) supporting homomorphic operations
//!
//! # CRS Model
//!
//! In the Common Reference String model, the random vector `a` is fixed
//! and publicly known. This enables query compression where clients only
//! send the `b` component of each ciphertext.
//!
//! # Example
//!
//! ```
//! use inspire_pir::lwe::{LweSecretKey, LweCiphertext};
//! use inspire_pir::math::GaussianSampler;
//! use inspire_pir::math::mod_q::DEFAULT_Q;
//!
//! let mut sampler = GaussianSampler::new(3.2);
//! let sk = LweSecretKey::generate(256, DEFAULT_Q, &mut sampler);
//! ```

mod enc;
mod types;

pub use types::{LweCiphertext, LweSecretKey};
