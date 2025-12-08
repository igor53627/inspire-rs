//! RLWE (Ring Learning With Errors) encryption module
//!
//! This module implements RLWE encryption over the ring R_q = Z_q[X]/(X^d + 1).
//!
//! # Overview
//!
//! RLWE is a lattice-based cryptosystem where:
//! - Secret key s is a polynomial sampled from error distribution
//! - Ciphertext (a, b) encrypts message m as b = -a·s + e + Δ·m
//! - Δ = ⌊q/p⌋ is the scaling factor
//!
//! # Galois Automorphisms
//!
//! Automorphisms τ_g: R → R defined by τ_g(X) = X^g are used for:
//! - Rotating coefficients within ciphertexts
//! - The InsPIRe packing algorithm (LWE → RLWE)
//!
//! # Example
//!
//! ```ignore
//! use inspire_pir::rlwe::{RlweSecretKey, RlweCiphertext};
//! use inspire_pir::params::InspireParams;
//! use inspire_pir::math::{Poly, GaussianSampler};
//!
//! let params = InspireParams::default();
//! let mut sampler = GaussianSampler::new(params.sigma);
//!
//! // Generate key
//! let sk = RlweSecretKey::generate(&params, &mut sampler);
//!
//! // Encrypt message
//! let message = Poly::zero(params.ring_dim, params.q);
//! let a = Poly::random(params.ring_dim, params.q);
//! let error = Poly::sample_gaussian(params.ring_dim, params.q, &mut sampler);
//! let ct = RlweCiphertext::encrypt(&sk, &message, params.delta(), a, &error);
//!
//! // Decrypt
//! let decrypted = ct.decrypt(&sk, params.delta(), params.p);
//! ```

mod types;
mod enc;
mod galois;

pub use types::{RlweCiphertext, RlweSecretKey};
pub use galois::{
    apply_automorphism,
    automorphism_ciphertext,
    automorphism_order,
    compose_automorphisms,
    galois_generators,
    inverse_automorphism,
    is_valid_galois_element,
};
