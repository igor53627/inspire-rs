//! RLWE ciphertext and key types
//!
//! Ring-LWE over R_q = Z_q[X]/(X^d + 1)

use crate::math::Poly;
use serde::{Deserialize, Serialize};

/// RLWE secret key: polynomial in R_q sampled from error distribution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RlweSecretKey {
    pub poly: Poly,
}

/// RLWE ciphertext: (a, b) ∈ R_q × R_q where b = -a·s + e + Δ·m
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RlweCiphertext {
    pub a: Poly,
    pub b: Poly,
}

impl RlweSecretKey {
    /// Create a secret key from a polynomial
    pub fn from_poly(poly: Poly) -> Self {
        Self { poly }
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.poly.dimension()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.poly.modulus()
    }
}

impl RlweCiphertext {
    /// Create a ciphertext from components
    pub fn from_parts(a: Poly, b: Poly) -> Self {
        debug_assert_eq!(a.dimension(), b.dimension(), "Ciphertext polynomials must have same dimension");
        debug_assert_eq!(a.modulus(), b.modulus(), "Ciphertext polynomials must have same modulus");
        Self { a, b }
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.a.dimension()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.a.modulus()
    }
}
