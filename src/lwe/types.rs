//! LWE ciphertext and key types.

use serde::{Deserialize, Serialize};

/// LWE secret key: vector in Z_q^d sampled from error distribution.
///
/// The secret key is a vector of small integers (typically from a Gaussian
/// distribution) used for encryption and decryption.
///
/// # Fields
///
/// * `coeffs` - Secret key coefficients in Z_q
/// * `dim` - Dimension of the key (typically matches ring dimension)
/// * `q` - Ciphertext modulus
///
/// # Example
///
/// ```
/// use inspire_pir::lwe::LweSecretKey;
/// use inspire_pir::math::GaussianSampler;
/// use inspire_pir::math::mod_q::DEFAULT_Q;
///
/// let mut sampler = GaussianSampler::new(3.2);
/// let sk = LweSecretKey::generate(256, DEFAULT_Q, &mut sampler);
/// assert_eq!(sk.dim, 256);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LweSecretKey {
    /// Secret key coefficients in Z_q.
    pub coeffs: Vec<u64>,
    /// Dimension of the key.
    pub dim: usize,
    /// Ciphertext modulus.
    pub q: u64,
}

/// LWE ciphertext: (a, b) where b = -<a, s> + e + Δ·m.
///
/// Encrypts a message m in Z_p using the LWE encryption scheme.
/// Supports homomorphic addition, subtraction, and scalar multiplication.
///
/// # Fields
///
/// * `a` - Random vector in Z_q^d
/// * `b` - Scalar in Z_q: b = -<a, s> + e + Δ·m
/// * `q` - Ciphertext modulus
///
/// # Decryption
///
/// To decrypt, compute `b + <a, s> = e + Δ·m`, then round to recover m.
///
/// # Example
///
/// ```
/// use inspire_pir::lwe::{LweSecretKey, LweCiphertext};
/// use inspire_pir::math::mod_q::DEFAULT_Q;
///
/// let sk = LweSecretKey::from_coeffs(vec![1, 2, 3, 4], DEFAULT_Q);
/// let ct = LweCiphertext::zero(4, DEFAULT_Q);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LweCiphertext {
    /// Random vector in Z_q^d.
    pub a: Vec<u64>,
    /// Scalar in Z_q: b = -<a, s> + e + Δ·m.
    pub b: u64,
    /// Ciphertext modulus.
    pub q: u64,
}
