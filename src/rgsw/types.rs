//! RGSW ciphertext and gadget types.
//!
//! Provides types for RGSW encryption and gadget decomposition.

use crate::math::{GaussianSampler, ModQ, NttContext, Poly};
use crate::rlwe::{RlweCiphertext, RlweSecretKey, SeededRlweCiphertext};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Samples a polynomial with coefficients from discrete Gaussian.
fn sample_error_poly(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Poly {
    let coeffs: Vec<u64> = (0..dim)
        .map(|_| {
            let sample = sampler.sample();
            ModQ::from_signed(sample, q)
        })
        .collect();
    Poly::from_coeffs(coeffs, q)
}

/// Gadget vector g_z = [1, z, z², ..., z^(ℓ-1)]^T.
///
/// Used for decomposing polynomials into small-norm components,
/// enabling noise-controlled homomorphic operations. The gadget
/// decomposition breaks a polynomial into ℓ pieces with coefficients
/// bounded by z, reducing noise growth in external products.
///
/// # Fields
///
/// * `base` - Gadget base z (typically 2^20)
/// * `len` - Number of digits ℓ = ⌈log_z(q)⌉
/// * `q` - Ciphertext modulus
///
/// # Example
///
/// ```
/// use inspire_pir::rgsw::GadgetVector;
/// use inspire_pir::math::mod_q::DEFAULT_Q;
///
/// let gadget = GadgetVector::new(1 << 20, 3, DEFAULT_Q);
/// assert_eq!(gadget.len, 3);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GadgetVector {
    /// Gadget base z (typically 2^20).
    pub base: u64,
    /// Number of digits ℓ = ⌈log_z(q)⌉.
    pub len: usize,
    /// Ciphertext modulus q.
    pub q: u64,
}

impl GadgetVector {
    /// Create a new gadget vector
    ///
    /// # Arguments
    /// * `base` - Gadget base z (e.g., 2^20)
    /// * `len` - Number of digits ℓ
    /// * `q` - Ciphertext modulus
    pub fn new(base: u64, len: usize, q: u64) -> Self {
        debug_assert!(base > 1, "Gadget base must be > 1");
        debug_assert!(len > 0, "Gadget length must be > 0");
        Self { base, len, q }
    }

    /// Create gadget vector with automatically computed length
    pub fn from_base(base: u64, q: u64) -> Self {
        let len = ((q as f64).log2() / (base as f64).log2()).ceil() as usize;
        Self::new(base, len, q)
    }

    /// Get the i-th power of the base: z^i mod q
    pub fn power(&self, i: usize) -> u64 {
        let mut result = 1u128;
        let base = self.base as u128;
        let q = self.q as u128;

        for _ in 0..i {
            result = (result * base) % q;
        }
        result as u64
    }

    /// Get all powers [1, z, z², ..., z^(ℓ-1)] mod q
    pub fn powers(&self) -> Vec<u64> {
        let mut powers = Vec::with_capacity(self.len);
        let mut current = 1u128;
        let base = self.base as u128;
        let q = self.q as u128;

        for _ in 0..self.len {
            powers.push(current as u64);
            current = (current * base) % q;
        }
        powers
    }
}

/// RGSW ciphertext: 2ℓ × 2 matrix of ring elements
///
/// Encrypts a small message m (typically 0, 1, or ±X^k).
/// The structure is:
/// ```text
/// [ Row 0..ℓ-1:   RLWE encryptions that decrypt to m·z^i·s  (message × secret key)
///   Row ℓ..2ℓ-1: RLWE encryptions that decrypt to m·z^i    (plain message) ]
/// ```
///
/// where s is the secret key polynomial and z is the gadget base.
/// This encoding enables the external product: RLWE(m₀) ⊡ RGSW(m₁) = RLWE(m₀·m₁).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RgswCiphertext {
    /// 2ℓ RLWE ciphertexts arranged as described above
    pub rows: Vec<RlweCiphertext>,
    /// Gadget parameters
    pub gadget: GadgetVector,
}

impl RgswCiphertext {
    /// Create an RGSW ciphertext from component rows
    pub fn from_rows(rows: Vec<RlweCiphertext>, gadget: GadgetVector) -> Self {
        debug_assert_eq!(rows.len(), 2 * gadget.len, "RGSW must have 2ℓ rows");
        Self { rows, gadget }
    }

    /// Encrypt a message polynomial under the given secret key
    ///
    /// The RGSW ciphertext structure is:
    /// - First ℓ rows: RLWE(0) with m·z^i added to the 'a' component
    /// - Next ℓ rows: RLWE(0) with m·z^i added to the 'b' component
    ///
    /// This encoding allows the external product to compute RLWE(m₀) ⊡ RGSW(m₁) = RLWE(m₀·m₁)
    ///
    /// # Arguments
    /// * `sk` - RLWE secret key
    /// * `message` - Message polynomial (typically small, e.g., constant 0, 1, or monomial X^k)
    /// * `gadget` - Gadget vector parameters
    /// * `sampler` - Gaussian sampler for error
    /// * `ctx` - NTT context
    pub fn encrypt(
        sk: &RlweSecretKey,
        message: &Poly,
        gadget: &GadgetVector,
        sampler: &mut GaussianSampler,
        ctx: &NttContext,
    ) -> Self {
        let d = sk.ring_dim();
        let q = sk.modulus();
        let ell = gadget.len;

        let mut rows = Vec::with_capacity(2 * ell);
        let powers = gadget.powers();

        // First ℓ rows: RLWE(0) + (m·z^i, 0)
        // Row i = (a + m·z^i, b) where (a, b) encrypts 0
        // Decrypts to: (a + m·z^i)·s + b = a·s + b + m·z^i·s ≈ m·z^i·s
        for i in 0..ell {
            let a_rand = Poly::random(d, q);
            let error = sample_error_poly(d, q, sampler);

            // b = -a·s + e (encrypts 0)
            let a_s = a_rand.mul_ntt(&sk.poly, ctx);
            let b = &(-a_s) + &error;

            // Add m·z^i to the 'a' component
            let scaled_msg = message.scalar_mul(powers[i]);
            let a = &a_rand + &scaled_msg;

            rows.push(RlweCiphertext::from_parts(a, b));
        }

        // Next ℓ rows: RLWE(0) + (0, m·z^i)
        // Row ℓ+i = (a, b + m·z^i) where (a, b) encrypts 0
        // Decrypts to: a·s + b + m·z^i ≈ m·z^i
        for i in 0..ell {
            let a = Poly::random(d, q);
            let error = sample_error_poly(d, q, sampler);

            // b_base = -a·s + e (encrypts 0)
            let a_s = a.mul_ntt(&sk.poly, ctx);
            let b_base = &(-a_s) + &error;

            // Add m·z^i to the 'b' component
            let scaled_msg = message.scalar_mul(powers[i]);
            let b = &b_base + &scaled_msg;

            rows.push(RlweCiphertext::from_parts(a, b));
        }

        Self {
            rows,
            gadget: gadget.clone(),
        }
    }

    /// Encrypt a scalar message (constant polynomial)
    pub fn encrypt_scalar(
        sk: &RlweSecretKey,
        message: u64,
        gadget: &GadgetVector,
        sampler: &mut GaussianSampler,
        ctx: &NttContext,
    ) -> Self {
        let msg_poly = Poly::constant(message, sk.ring_dim(), sk.modulus());
        Self::encrypt(sk, &msg_poly, gadget, sampler, ctx)
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.rows[0].ring_dim()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.rows[0].modulus()
    }

    /// Get the gadget length ℓ
    pub fn gadget_len(&self) -> usize {
        self.gadget.len
    }
}

/// Seeded RGSW ciphertext: stores seeds instead of full `a` polynomials
///
/// RGSW has 2ℓ rows, each an RLWE ciphertext. By storing seeds instead of
/// full `a` polynomials, we reduce size by ~50%.
///
/// For d=2048, q=60-bit:
/// - Full RGSW: 2×3 rows × 2 polys × 2048 coeffs × 8 bytes ≈ 196 KB
/// - Seeded RGSW: 2×3 rows × (32 bytes + 1 poly) ≈ 98 KB
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededRgswCiphertext {
    /// 2ℓ seeded RLWE ciphertexts
    pub rows: Vec<SeededRlweCiphertext>,
    /// Gadget parameters
    pub gadget: GadgetVector,
}

impl SeededRgswCiphertext {
    /// Encrypt a message polynomial, storing seeds instead of full `a` polynomials
    pub fn encrypt(
        sk: &RlweSecretKey,
        message: &Poly,
        gadget: &GadgetVector,
        sampler: &mut GaussianSampler,
        ctx: &NttContext,
    ) -> Self {
        let d = sk.ring_dim();
        let q = sk.modulus();
        let ell = gadget.len;

        let mut rows = Vec::with_capacity(2 * ell);
        let powers = gadget.powers();
        let mut rng = rand::thread_rng();

        // First ℓ rows: RLWE(0) + (m·z^i, 0)
        // Original: (a_rand + m·z^i, b) where b = -a_rand·s + e
        // Decrypts to: (a_rand + m·z^i)·s + b = m·z^i·s + e
        //
        // Seeded: we store (seed, b_adjusted), expand gives (a_rand, b_adjusted)
        // For equivalent decrypt: a_rand·s + b_adjusted = m·z^i·s + e
        // Therefore: b_adjusted = b + m·z^i·s
        for i in 0..ell {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            let a_rand = Poly::from_seed(&seed, d, q);
            let error = sample_error_poly(d, q, sampler);

            // b = -a·s + e (encrypts 0)
            let a_s = a_rand.mul_ntt(&sk.poly, ctx);
            let b = &(-a_s) + &error;

            // Adjust b to compensate for missing m·z^i in a component
            // b_adjusted = b + (m·z^i)·s so that decrypt gives m·z^i·s + e
            let scaled_msg = message.scalar_mul(powers[i]);
            let msg_s = scaled_msg.mul_ntt(&sk.poly, ctx);
            let b_adjusted = &b + &msg_s;

            rows.push(SeededRlweCiphertext::new(seed, b_adjusted));
        }

        // Next ℓ rows: RLWE(0) + (0, m·z^i)
        for i in 0..ell {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            let a = Poly::from_seed(&seed, d, q);
            let error = sample_error_poly(d, q, sampler);

            // b_base = -a·s + e (encrypts 0)
            let a_s = a.mul_ntt(&sk.poly, ctx);
            let b_base = &(-a_s) + &error;

            // Add m·z^i to the 'b' component
            let scaled_msg = message.scalar_mul(powers[i]);
            let b = &b_base + &scaled_msg;

            rows.push(SeededRlweCiphertext::new(seed, b));
        }

        Self {
            rows,
            gadget: gadget.clone(),
        }
    }

    /// Encrypt a scalar message
    pub fn encrypt_scalar(
        sk: &RlweSecretKey,
        message: u64,
        gadget: &GadgetVector,
        sampler: &mut GaussianSampler,
        ctx: &NttContext,
    ) -> Self {
        let msg_poly = Poly::constant(message, sk.ring_dim(), sk.modulus());
        Self::encrypt(sk, &msg_poly, gadget, sampler, ctx)
    }

    /// Expand to full RgswCiphertext by regenerating all `a` polynomials
    pub fn expand(&self) -> RgswCiphertext {
        let rows: Vec<RlweCiphertext> = self.rows.iter().map(|r| r.expand()).collect();
        RgswCiphertext::from_rows(rows, self.gadget.clone())
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.rows[0].ring_dim()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.rows[0].modulus()
    }

    /// Get the gadget length ℓ
    pub fn gadget_len(&self) -> usize {
        self.gadget.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::InspireParams;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        NttContext::new(params.ring_dim, params.q)
    }

    #[test]
    fn test_gadget_vector_creation() {
        let q = 1152921504606830593u64;
        let gadget = GadgetVector::new(1 << 20, 3, q);

        assert_eq!(gadget.base, 1 << 20);
        assert_eq!(gadget.len, 3);
        assert_eq!(gadget.q, q);
    }

    #[test]
    fn test_gadget_powers() {
        let q = 1152921504606830593u64;
        let base = 1 << 20;
        let gadget = GadgetVector::new(base, 3, q);

        let powers = gadget.powers();
        assert_eq!(powers.len(), 3);
        assert_eq!(powers[0], 1);
        assert_eq!(powers[1], base);
        assert_eq!(
            powers[2],
            ((base as u128 * base as u128) % q as u128) as u64
        );
    }

    #[test]
    fn test_gadget_from_base() {
        let q = 1152921504606830593u64;
        let gadget = GadgetVector::from_base(1 << 20, q);

        // log_2(q) ≈ 60, log_2(2^20) = 20, so ℓ = ceil(60/20) = 3
        assert_eq!(gadget.len, 3);
    }

    #[test]
    fn test_rgsw_encryption_structure() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let rgsw = RgswCiphertext::encrypt_scalar(&sk, 1, &gadget, &mut sampler, &ctx);

        assert_eq!(rgsw.rows.len(), 2 * params.gadget_len);
        assert_eq!(rgsw.ring_dim(), params.ring_dim);
        assert_eq!(rgsw.modulus(), params.q);
    }

    #[test]
    fn test_rgsw_encrypt_zero() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let rgsw = RgswCiphertext::encrypt_scalar(&sk, 0, &gadget, &mut sampler, &ctx);

        // RGSW(0) should have all rows as valid RLWE ciphertexts
        assert_eq!(rgsw.rows.len(), 6); // 2 * 3
    }
}
