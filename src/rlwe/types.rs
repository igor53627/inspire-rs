//! RLWE ciphertext and key types.
//!
//! Ring-LWE over R_q = Z_q[X]/(X^d + 1).

use crate::math::Poly;
use serde::{Deserialize, Serialize};

/// RLWE secret key: polynomial in R_q sampled from error distribution.
///
/// The secret key is a polynomial with small coefficients (typically from
/// a Gaussian distribution) used for encryption and decryption.
///
/// # Fields
///
/// * `poly` - Secret polynomial in R_q
///
/// # Example
///
/// ```
/// use inspire_pir::rlwe::RlweSecretKey;
/// use inspire_pir::math::Poly;
/// use inspire_pir::math::mod_q::DEFAULT_Q;
///
/// let poly = Poly::zero(256, DEFAULT_Q);
/// let sk = RlweSecretKey::from_poly(poly);
/// assert_eq!(sk.ring_dim(), 256);
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RlweSecretKey {
    /// Secret polynomial in R_q.
    pub poly: Poly,
}

/// RLWE ciphertext: (a, b) ∈ R_q × R_q where b = -a·s + e + Δ·m.
///
/// Encrypts a message polynomial m using the RLWE encryption scheme.
/// Supports homomorphic addition and multiplication operations.
///
/// # Fields
///
/// * `a` - Random polynomial in R_q
/// * `b` - Encrypted polynomial: b = -a·s + e + Δ·m
///
/// # Decryption
///
/// To decrypt, compute `b + a·s = e + Δ·m`, then round to recover m.
///
/// # Example
///
/// ```
/// use inspire_pir::rlwe::RlweCiphertext;
/// use inspire_pir::math::Poly;
/// use inspire_pir::math::mod_q::DEFAULT_Q;
///
/// let a = Poly::zero(256, DEFAULT_Q);
/// let b = Poly::zero(256, DEFAULT_Q);
/// let ct = RlweCiphertext::from_parts(a, b);
/// assert_eq!(ct.ring_dim(), 256);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RlweCiphertext {
    /// Random polynomial in R_q.
    pub a: Poly,
    /// Encrypted polynomial: b = -a·s + e + Δ·m.
    pub b: Poly,
}

impl RlweSecretKey {
    /// Creates a secret key from a polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - The secret polynomial
    ///
    /// # Returns
    ///
    /// A new `RlweSecretKey` wrapping the polynomial.
    pub fn from_poly(poly: Poly) -> Self {
        Self { poly }
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The dimension d of the polynomial ring R_q.
    pub fn ring_dim(&self) -> usize {
        self.poly.dimension()
    }

    /// Returns the modulus q.
    ///
    /// # Returns
    ///
    /// The modulus used for this secret key.
    pub fn modulus(&self) -> u64 {
        self.poly.modulus()
    }
}

impl RlweCiphertext {
    /// Creates a ciphertext from component polynomials.
    ///
    /// # Arguments
    ///
    /// * `a` - Random polynomial in R_q
    /// * `b` - Encrypted polynomial
    ///
    /// # Returns
    ///
    /// A new `RlweCiphertext` with the given components.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `a` and `b` have the same dimension and modulus.
    pub fn from_parts(a: Poly, b: Poly) -> Self {
        debug_assert_eq!(
            a.dimension(),
            b.dimension(),
            "Ciphertext polynomials must have same dimension"
        );
        debug_assert_eq!(
            a.modulus(),
            b.modulus(),
            "Ciphertext polynomials must have same modulus"
        );
        Self { a, b }
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The dimension d of the polynomial ring R_q.
    pub fn ring_dim(&self) -> usize {
        self.a.dimension()
    }

    /// Returns the modulus q.
    ///
    /// # Returns
    ///
    /// The modulus used for this ciphertext.
    pub fn modulus(&self) -> u64 {
        self.a.modulus()
    }
}

/// Seeded RLWE ciphertext: stores 32-byte seed instead of full `a` polynomial.
///
/// Reduces ciphertext size by ~50% by storing only a seed for the random
/// polynomial `a`. The server expands the seed to recover `a` during processing.
///
/// # Fields
///
/// * `seed` - 32-byte seed for deterministic generation of `a`
/// * `b` - The `b` polynomial (encrypted value)
///
/// # Size Comparison (d=2048)
///
/// | Format | Size | Reduction |
/// |--------|------|-----------|
/// | Full RLWE | 32 KB | - |
/// | Seeded RLWE | 16 KB | 50% |
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededRlweCiphertext {
    /// 32-byte seed for deterministic generation of `a`.
    pub seed: [u8; 32],
    /// The `b` polynomial (encrypted value).
    pub b: Poly,
}

impl SeededRlweCiphertext {
    /// Creates a seeded ciphertext from seed and b polynomial.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for generating `a`
    /// * `b` - The encrypted polynomial
    ///
    /// # Returns
    ///
    /// A new `SeededRlweCiphertext`.
    pub fn new(seed: [u8; 32], b: Poly) -> Self {
        Self { seed, b }
    }

    /// Expands to full `RlweCiphertext` by regenerating `a` from seed.
    ///
    /// # Returns
    ///
    /// A full `RlweCiphertext` with `a` regenerated from the seed.
    pub fn expand(&self) -> RlweCiphertext {
        let dim = self.b.dimension();
        let a = Poly::from_seed_moduli(&self.seed, dim, self.b.moduli());
        RlweCiphertext::from_parts(a, self.b.clone())
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The dimension d of the polynomial ring R_q.
    pub fn ring_dim(&self) -> usize {
        self.b.dimension()
    }

    /// Returns the modulus q.
    ///
    /// # Returns
    ///
    /// The modulus used for this ciphertext.
    pub fn modulus(&self) -> u64 {
        self.b.modulus()
    }
}
