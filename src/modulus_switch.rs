//! Modulus switching for ciphertext compression
//!
//! Implements modulus switching to reduce ciphertext sizes during transmission.
//! Coefficients are rescaled from large modulus q to smaller q', reducing
//! per-coefficient storage from 8 bytes to 4 bytes (or less).
//!
//! # Theory
//!
//! Given a ciphertext with coefficients in Z_q, modulus switching rescales to Z_q':
//!
//! ```text
//! c' = round(c * q' / q)
//! ```
//!
//! This introduces a small rounding error bounded by 1/2, which translates to
//! noise increase of at most q/(2*q') in the original domain.
//!
//! # Size Reduction
//!
//! | Original q | Switched q' | Reduction |
//! |------------|-------------|-----------|
//! | 2^60 (8B)  | 2^32 (4B)   | 50%       |
//! | 2^60 (8B)  | 2^28 (4B)   | 50%       |
//!
//! The actual bit savings come from packing coefficients more tightly during
//! serialization.
//!
//! # Limitations for RGSW Queries
//!
//! **Warning**: Modulus switching on RGSW ciphertexts used in external products
//! introduces significant noise that may exceed decryption thresholds.
//!
//! The rounding error from q → q' → q is amplified by the external product:
//!
//! ```text
//! added_error ≈ ℓ × B × (q / q')
//! ```
//!
//! Where ℓ is gadget length and B is gadget base. With typical parameters
//! (q ≈ 2^60, q' = 2^30, B = 2^20, ℓ = 3), this error is ~3×2^50, which exceeds
//! the decryption margin q/(2p) ≈ 2^43.
//!
//! **Recommended usage**:
//! - Use modulus switching for RLWE responses (no external product)
//! - For query compression, use seed expansion only (SeededRgswCiphertext)
//! - If RGSW modulus switching is needed, use q' ≳ 2^38 (requires custom serialization)

use serde::{Deserialize, Serialize};

use crate::math::Poly;
use crate::rgsw::{GadgetVector, SeededRgswCiphertext};
use crate::rlwe::SeededRlweCiphertext;

/// Default switched modulus (2^30).
///
/// This value comfortably fits in u32 with room for overflow during intermediate
/// operations. Using 2^30 instead of 2^32 provides headroom for additions.
pub const DEFAULT_SWITCHED_Q: u64 = 1 << 30;

/// Polynomial with coefficients reduced to a smaller modulus.
///
/// Stores coefficients as `u32` instead of `u64`, halving storage requirements.
/// The original modulus is preserved for expansion back to full precision.
///
/// # Fields
///
/// * `coeffs` - Coefficients reduced to q' (stored as u32)
/// * `original_q` - Original modulus q (for switching back)
/// * `switched_q` - Switched modulus q'
///
/// # Example
///
/// ```
/// use inspire_pir::modulus_switch::SwitchedPoly;
/// use inspire_pir::math::Poly;
///
/// let poly = Poly::random(256, 1152921504606830593);
/// let switched = SwitchedPoly::from_poly(&poly, 1 << 30);
///
/// // Coefficients are now stored as u32
/// assert_eq!(switched.dimension(), 256);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchedPoly {
    /// Coefficients reduced to q' (stored as u32).
    pub coeffs: Vec<u32>,
    /// Original modulus q (for switching back).
    pub original_q: u64,
    /// Switched modulus q'.
    pub switched_q: u64,
}

impl SwitchedPoly {
    /// Creates a switched polynomial from a full polynomial.
    ///
    /// Rescales each coefficient from the original modulus q to the switched
    /// modulus q': `c' = round(c * q' / q)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - The polynomial to switch (must be in coefficient domain, not NTT)
    /// * `switched_q` - The target modulus q' (must fit in u32)
    ///
    /// # Returns
    ///
    /// A new `SwitchedPoly` with coefficients reduced to q'.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The polynomial is in NTT domain
    /// - `switched_q` exceeds `u32::MAX`
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::modulus_switch::SwitchedPoly;
    /// use inspire_pir::math::Poly;
    ///
    /// let poly = Poly::random(256, 1152921504606830593);
    /// let switched = SwitchedPoly::from_poly(&poly, 1 << 30);
    /// assert_eq!(switched.dimension(), 256);
    /// ```
    pub fn from_poly(poly: &Poly, switched_q: u64) -> Self {
        assert!(!poly.is_ntt(), "Cannot switch polynomial in NTT domain");
        assert!(
            switched_q <= u32::MAX as u64,
            "Switched modulus must fit in u32"
        );

        let original_q = poly.modulus();
        let coeffs: Vec<u32> = poly
            .coeffs()
            .iter()
            .map(|&c| rescale(c, original_q, switched_q) as u32)
            .collect();

        Self {
            coeffs,
            original_q,
            switched_q,
        }
    }

    /// Expands back to a full polynomial with the original modulus.
    ///
    /// Rescales each coefficient from q' back to q: `c = round(c' * q / q')`.
    /// Note that this introduces rounding error bounded by `q / q'`.
    ///
    /// # Arguments
    ///
    /// * `dim` - The expected dimension (for validation)
    ///
    /// # Returns
    ///
    /// A `Poly` with coefficients in the original modulus q.
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::modulus_switch::SwitchedPoly;
    /// use inspire_pir::math::Poly;
    ///
    /// let poly = Poly::random(256, 1152921504606830593);
    /// let switched = SwitchedPoly::from_poly(&poly, 1 << 30);
    /// let recovered = switched.expand(256);
    /// assert_eq!(recovered.dimension(), 256);
    /// ```
    pub fn expand(&self, dim: usize) -> Poly {
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&c| rescale(c as u64, self.switched_q, self.original_q))
            .collect();

        debug_assert_eq!(coeffs.len(), dim);
        Poly::from_coeffs(coeffs, self.original_q)
    }

    /// Returns the dimension (number of coefficients) of the polynomial.
    ///
    /// # Returns
    ///
    /// The number of coefficients in the polynomial.
    pub fn dimension(&self) -> usize {
        self.coeffs.len()
    }
}

/// Seeded RLWE ciphertext with modulus-switched b polynomial.
///
/// Combines seed expansion (~50% reduction) with modulus switching (~50% reduction)
/// for maximum compression. The `a` polynomial is regenerated from a 32-byte seed,
/// while the `b` polynomial is stored with reduced precision.
///
/// # Size Comparison (d=2048)
///
/// | Format | Size | Reduction |
/// |--------|------|-----------|
/// | Full RLWE | 32 KB | - |
/// | Seeded RLWE | 16 KB | 50% |
/// | Seeded + Switched | 8 KB | 75% |
///
/// # Fields
///
/// * `seed` - 32-byte seed for deterministic generation of `a`
/// * `b` - Modulus-switched `b` polynomial
///
/// # Example
///
/// ```ignore
/// use inspire_pir::modulus_switch::{SwitchedSeededRlweCiphertext, DEFAULT_SWITCHED_Q};
/// use inspire_pir::rlwe::SeededRlweCiphertext;
///
/// let switched = SwitchedSeededRlweCiphertext::from_seeded(&seeded_ct, DEFAULT_SWITCHED_Q);
/// let recovered = switched.expand();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchedSeededRlweCiphertext {
    /// 32-byte seed for deterministic generation of `a`.
    pub seed: [u8; 32],
    /// Modulus-switched `b` polynomial.
    pub b: SwitchedPoly,
}

impl SwitchedSeededRlweCiphertext {
    /// Creates a switched seeded RLWE ciphertext from a seeded RLWE ciphertext.
    ///
    /// Applies modulus switching to the `b` polynomial while preserving the seed.
    ///
    /// # Arguments
    ///
    /// * `ct` - The seeded RLWE ciphertext to switch
    /// * `switched_q` - The target modulus q' (must fit in u32)
    ///
    /// # Returns
    ///
    /// A new `SwitchedSeededRlweCiphertext` with reduced storage.
    pub fn from_seeded(ct: &SeededRlweCiphertext, switched_q: u64) -> Self {
        Self {
            seed: ct.seed,
            b: SwitchedPoly::from_poly(&ct.b, switched_q),
        }
    }

    /// Expands to a full `SeededRlweCiphertext` with the original modulus.
    ///
    /// The `b` polynomial is rescaled back to the original modulus q.
    /// Note that this introduces rounding error bounded by `q / q'`.
    ///
    /// # Returns
    ///
    /// A `SeededRlweCiphertext` with the original modulus.
    pub fn expand(&self) -> SeededRlweCiphertext {
        let dim = self.b.dimension();
        SeededRlweCiphertext::new(self.seed, self.b.expand(dim))
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The number of coefficients in the polynomial ring.
    pub fn ring_dim(&self) -> usize {
        self.b.dimension()
    }

    /// Returns the original modulus q.
    ///
    /// # Returns
    ///
    /// The modulus before switching.
    pub fn original_modulus(&self) -> u64 {
        self.b.original_q
    }

    /// Returns the switched modulus q'.
    ///
    /// # Returns
    ///
    /// The modulus after switching.
    pub fn switched_modulus(&self) -> u64 {
        self.b.switched_q
    }
}

/// Seeded RGSW ciphertext with modulus-switched polynomials.
///
/// Provides maximum compression for query transmission by combining seed expansion
/// with modulus switching. Each row is a switched seeded RLWE ciphertext.
///
/// # Size Comparison (d=2048, ℓ=3)
///
/// | Format | Size | Reduction |
/// |--------|------|-----------|
/// | Full RGSW | 196 KB | - |
/// | Seeded RGSW | 98 KB | 50% |
/// | Seeded + Switched | ~50 KB | 75% |
///
/// # Warning
///
/// Modulus switching on RGSW ciphertexts used in external products introduces
/// significant noise. See module documentation for details on noise bounds.
///
/// # Fields
///
/// * `rows` - 2ℓ switched seeded RLWE ciphertexts
/// * `gadget` - Gadget parameters for decomposition
///
/// # Example
///
/// ```ignore
/// use inspire_pir::modulus_switch::{SwitchedSeededRgswCiphertext, DEFAULT_SWITCHED_Q};
/// use inspire_pir::rgsw::SeededRgswCiphertext;
///
/// let switched = SwitchedSeededRgswCiphertext::from_seeded(&seeded_rgsw, DEFAULT_SWITCHED_Q);
/// let recovered = switched.expand();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchedSeededRgswCiphertext {
    /// 2ℓ switched seeded RLWE ciphertexts.
    pub rows: Vec<SwitchedSeededRlweCiphertext>,
    /// Gadget parameters for decomposition.
    pub gadget: GadgetVector,
}

impl SwitchedSeededRgswCiphertext {
    /// Creates a switched seeded RGSW ciphertext from a seeded RGSW ciphertext.
    ///
    /// Applies modulus switching to all row polynomials while preserving seeds.
    ///
    /// # Arguments
    ///
    /// * `ct` - The seeded RGSW ciphertext to switch
    /// * `switched_q` - The target modulus q' (must fit in u32)
    ///
    /// # Returns
    ///
    /// A new `SwitchedSeededRgswCiphertext` with reduced storage.
    pub fn from_seeded(ct: &SeededRgswCiphertext, switched_q: u64) -> Self {
        let rows = ct
            .rows
            .iter()
            .map(|r| SwitchedSeededRlweCiphertext::from_seeded(r, switched_q))
            .collect();

        Self {
            rows,
            gadget: ct.gadget.clone(),
        }
    }

    /// Expands to a full `SeededRgswCiphertext` with the original modulus.
    ///
    /// All row polynomials are rescaled back to the original modulus q.
    /// Note that this introduces rounding error bounded by `q / q'`.
    ///
    /// # Returns
    ///
    /// A `SeededRgswCiphertext` with the original modulus.
    pub fn expand(&self) -> SeededRgswCiphertext {
        let rows = self.rows.iter().map(|r| r.expand()).collect();
        SeededRgswCiphertext {
            rows,
            gadget: self.gadget.clone(),
        }
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The number of coefficients in the polynomial ring.
    ///
    /// # Panics
    ///
    /// Debug-asserts if the ciphertext has no rows.
    pub fn ring_dim(&self) -> usize {
        debug_assert!(
            !self.rows.is_empty(),
            "SwitchedSeededRgswCiphertext has no rows"
        );
        self.rows[0].ring_dim()
    }

    /// Returns the original modulus q.
    ///
    /// # Returns
    ///
    /// The modulus before switching.
    ///
    /// # Panics
    ///
    /// Debug-asserts if the ciphertext has no rows.
    pub fn original_modulus(&self) -> u64 {
        debug_assert!(
            !self.rows.is_empty(),
            "SwitchedSeededRgswCiphertext has no rows"
        );
        self.rows[0].original_modulus()
    }

    /// Returns the switched modulus q'.
    ///
    /// # Returns
    ///
    /// The modulus after switching.
    ///
    /// # Panics
    ///
    /// Debug-asserts if the ciphertext has no rows.
    pub fn switched_modulus(&self) -> u64 {
        debug_assert!(
            !self.rows.is_empty(),
            "SwitchedSeededRgswCiphertext has no rows"
        );
        self.rows[0].switched_modulus()
    }

    /// Returns the gadget length ℓ.
    ///
    /// # Returns
    ///
    /// The number of gadget digits used in decomposition.
    pub fn gadget_len(&self) -> usize {
        self.gadget.len
    }
}

/// Rescale a coefficient from one modulus to another
///
/// Computes: round(c * q_new / q_old)
///
/// Uses u128 for intermediate computation to avoid overflow.
#[inline]
fn rescale(c: u64, q_old: u64, q_new: u64) -> u64 {
    // c' = round(c * q_new / q_old) = floor((c * q_new + q_old/2) / q_old)
    let c = c as u128;
    let q_old = q_old as u128;
    let q_new = q_new as u128;

    let numerator = c * q_new + q_old / 2;
    (numerator / q_old) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{GaussianSampler, NttContext, Poly};
    use crate::params::InspireParams;
    use crate::rgsw::SeededRgswCiphertext;
    use crate::rlwe::{RlweSecretKey, SeededRlweCiphertext};

    fn test_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593, // ~2^60
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    #[test]
    fn test_rescale_basic() {
        // Simple case: 50 in mod 100 -> mod 10 should be ~5
        assert_eq!(rescale(50, 100, 10), 5);

        // Test rounding
        assert_eq!(rescale(55, 100, 10), 6); // rounds up
        assert_eq!(rescale(54, 100, 10), 5); // rounds down
    }

    #[test]
    fn test_rescale_large_modulus() {
        let q = 1152921504606830593u64; // ~2^60
        let q_prime = 1u64 << 32;

        // Value at q/2 should map to q'/2
        let c = q / 2;
        let c_prime = rescale(c, q, q_prime);

        // Should be approximately q_prime / 2
        let expected = q_prime / 2;
        let error = (c_prime as i64 - expected as i64).abs();
        assert!(error <= 1, "Rescaling error too large: {}", error);
    }

    #[test]
    fn test_switched_poly_roundtrip() {
        let params = test_params();
        let poly = Poly::random(params.ring_dim, params.q);

        let switched = SwitchedPoly::from_poly(&poly, DEFAULT_SWITCHED_Q);
        let recovered = switched.expand(params.ring_dim);

        // Check dimensions match
        assert_eq!(recovered.dimension(), poly.dimension());
        assert_eq!(recovered.modulus(), poly.modulus());

        // Coefficients should be close (within rounding error scaled back)
        for i in 0..poly.dimension() {
            let orig = poly.coeff(i);
            let rec = recovered.coeff(i);

            // Error bound: at most q / q' from double rescaling
            let max_error = params.q / DEFAULT_SWITCHED_Q + 1;
            let error = if orig > rec { orig - rec } else { rec - orig };
            assert!(
                error <= max_error,
                "Coefficient {} error too large: {} vs {} (error: {})",
                i,
                orig,
                rec,
                error
            );
        }
    }

    #[test]
    fn test_switched_seeded_rlwe_size() {
        let params = test_params();

        // Create a seeded RLWE ciphertext directly
        let seed = [42u8; 32];
        let b = Poly::random(params.ring_dim, params.q);
        let seeded = SeededRlweCiphertext::new(seed, b);

        // Switch modulus
        let switched = SwitchedSeededRlweCiphertext::from_seeded(&seeded, DEFAULT_SWITCHED_Q);

        // Serialize both and compare sizes
        let seeded_bytes = bincode::serialize(&seeded).unwrap();
        let switched_bytes = bincode::serialize(&switched).unwrap();

        // Switched should be smaller (u32 vs u64 coefficients)
        assert!(
            switched_bytes.len() < seeded_bytes.len(),
            "Switched ({}) should be smaller than seeded ({})",
            switched_bytes.len(),
            seeded_bytes.len()
        );

        // Roughly 50% of the polynomial part
        let expected_reduction = params.ring_dim * 4; // 4 bytes saved per coeff
        let actual_reduction = seeded_bytes.len() - switched_bytes.len();
        assert!(
            actual_reduction >= expected_reduction - 100, // allow some overhead
            "Expected ~{} byte reduction, got {}",
            expected_reduction,
            actual_reduction
        );
    }

    #[test]
    fn test_switched_seeded_rgsw_roundtrip() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        let ctx = NttContext::new(params.ring_dim, params.q);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget =
            crate::rgsw::GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Create seeded RGSW
        let msg = Poly::constant(1, params.ring_dim, params.q);
        let seeded = SeededRgswCiphertext::encrypt(&sk, &msg, &gadget, &mut sampler, &ctx);

        // Switch modulus
        let switched = SwitchedSeededRgswCiphertext::from_seeded(&seeded, DEFAULT_SWITCHED_Q);

        // Expand back
        let recovered = switched.expand();

        // Check structure
        assert_eq!(recovered.rows.len(), seeded.rows.len());
        assert_eq!(recovered.gadget_len(), seeded.gadget_len());
    }

    #[test]
    fn test_switched_rgsw_size_reduction() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        let ctx = NttContext::new(params.ring_dim, params.q);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget =
            crate::rgsw::GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let msg = Poly::constant(1, params.ring_dim, params.q);
        let seeded = SeededRgswCiphertext::encrypt(&sk, &msg, &gadget, &mut sampler, &ctx);
        let switched = SwitchedSeededRgswCiphertext::from_seeded(&seeded, DEFAULT_SWITCHED_Q);

        let seeded_bytes = bincode::serialize(&seeded).unwrap();
        let switched_bytes = bincode::serialize(&switched).unwrap();

        println!("Seeded RGSW size: {} bytes", seeded_bytes.len());
        println!("Switched RGSW size: {} bytes", switched_bytes.len());
        println!(
            "Reduction: {:.1}%",
            100.0 * (1.0 - switched_bytes.len() as f64 / seeded_bytes.len() as f64)
        );

        // Should achieve significant reduction
        assert!(
            switched_bytes.len() < seeded_bytes.len() * 3 / 4,
            "Expected at least 25% reduction"
        );
    }
}
