//! LWE ciphertext and key types

use serde::{Deserialize, Serialize};

/// LWE secret key: vector in Z_q^d sampled from error distribution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LweSecretKey {
    /// Secret key coefficients
    pub coeffs: Vec<u64>,
    /// Dimension of the key
    pub dim: usize,
    /// Ciphertext modulus
    pub q: u64,
}

/// LWE ciphertext: (a, b) where b = -<a, s> + e + Δ·m
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LweCiphertext {
    /// Random vector in Z_q^d
    pub a: Vec<u64>,
    /// Scalar in Z_q: b = -<a, s> + e + Δ·m
    pub b: u64,
    /// Ciphertext modulus
    pub q: u64,
}
