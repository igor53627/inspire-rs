//! Number-Theoretic Transform (NTT) for fast polynomial multiplication.
//!
//! Implements Cooley-Tukey radix-2 NTT for negacyclic convolution over
//! R_q = Z_q[X]/(X^d + 1). The NTT enables O(n log n) polynomial multiplication
//! instead of O(n²) naive multiplication.
//!
//! # Theory
//!
//! For negacyclic convolution (multiplication modulo X^n + 1), we use a
//! primitive 2n-th root of unity ψ where ψ^n = -1. The NTT evaluates a
//! polynomial at powers of ψ, enabling pointwise multiplication in the
//! evaluation domain.
//!
//! # Requirements
//!
//! The modulus q must satisfy q ≡ 1 (mod 2n) for a primitive 2n-th root
//! of unity to exist. The default modulus `DEFAULT_Q` supports n up to 2048.
//!
//! # Example
//!
//! ```
//! use inspire_pir::math::ntt::NttContext;
//!
//! let ctx = NttContext::with_default_q(256);
//!
//! // Forward NTT
//! let mut coeffs = vec![1u64; 256];
//! ctx.forward(&mut coeffs);
//!
//! // Inverse NTT recovers original
//! ctx.inverse(&mut coeffs);
//! assert_eq!(coeffs[0], 1);
//! ```

use super::mod_q::DEFAULT_Q;

/// Precomputed NTT context with twiddle factors.
///
/// Stores precomputed roots of unity and Montgomery constants for efficient
/// NTT operations. Create once and reuse for all polynomial operations with
/// the same dimension and modulus.
///
/// # Fields
///
/// * `n` - Ring dimension (must be a power of two)
/// * `q` - Modulus (must satisfy q ≡ 1 mod 2n)
/// * `psi_powers` - Forward twiddle factors (powers of ψ)
/// * `psi_inv_powers` - Inverse twiddle factors (powers of ψ^(-1))
/// * `n_inv` - n^(-1) mod q for inverse NTT scaling
///
/// # Example
///
/// ```
/// use inspire_pir::math::ntt::NttContext;
///
/// let ctx = NttContext::with_default_q(2048);
/// assert_eq!(ctx.dimension(), 2048);
/// ```
#[derive(Clone)]
pub struct NttContext {
    /// Ring dimension (power of two).
    n: usize,
    /// Modulus q.
    q: u64,
    /// Precomputed values for Montgomery arithmetic.
    q_inv_neg: u64,
    r_squared: u64,
    /// Forward twiddle factors (powers of ψ where ψ^(2n) = 1 and ψ^n = -1).
    psi_powers: Vec<u64>,
    /// Inverse twiddle factors (powers of ψ^(-1)).
    psi_inv_powers: Vec<u64>,
    /// n^(-1) mod q in Montgomery form for inverse NTT scaling.
    n_inv: u64,
}

impl NttContext {
    /// Creates an NTT context for the given dimension and modulus.
    ///
    /// Precomputes twiddle factors and Montgomery constants for efficient
    /// NTT operations.
    ///
    /// # Arguments
    ///
    /// * `n` - Ring dimension (must be a power of two)
    /// * `q` - Modulus (must satisfy q ≡ 1 mod 2n)
    ///
    /// # Returns
    ///
    /// A new `NttContext` with precomputed values.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `n` is not a power of two
    /// - `q` does not satisfy q ≡ 1 (mod 2n)
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::math::ntt::NttContext;
    /// use inspire_pir::math::mod_q::DEFAULT_Q;
    ///
    /// let ctx = NttContext::new(2048, DEFAULT_Q);
    /// assert_eq!(ctx.dimension(), 2048);
    /// ```
    pub fn new(n: usize, q: u64) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of two");
        assert!(q % (2 * n as u64) == 1, "q must be ≡ 1 (mod 2n)");

        let q_inv_neg = Self::compute_q_inv_neg(q);
        let r_squared = Self::compute_r_squared(q);

        // Find primitive 2n-th root of unity ψ
        let psi = Self::find_primitive_root(2 * n as u64, q);
        let psi_mont = Self::to_montgomery(psi, q, r_squared, q_inv_neg);

        // Precompute forward twiddle factors in bit-reversed order
        let psi_powers = Self::compute_twiddle_factors(n, psi_mont, q, q_inv_neg, r_squared);

        // Compute inverse: ψ^(-1) mod q
        let psi_inv = Self::mod_pow(psi, q - 2, q);
        let psi_inv_mont = Self::to_montgomery(psi_inv, q, r_squared, q_inv_neg);
        let psi_inv_powers =
            Self::compute_twiddle_factors(n, psi_inv_mont, q, q_inv_neg, r_squared);

        // Compute n^(-1) mod q
        let n_inv = Self::mod_pow(n as u64, q - 2, q);
        let n_inv = Self::to_montgomery(n_inv, q, r_squared, q_inv_neg);

        Self {
            n,
            q,
            q_inv_neg,
            r_squared,
            psi_powers,
            psi_inv_powers,
            n_inv,
        }
    }

    /// Creates an NTT context with the default modulus.
    ///
    /// # Arguments
    ///
    /// * `n` - Ring dimension (must be a power of two, at most 2048)
    ///
    /// # Returns
    ///
    /// A new `NttContext` using `DEFAULT_Q` as the modulus.
    pub fn with_default_q(n: usize) -> Self {
        Self::new(n, DEFAULT_Q)
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The dimension n of the polynomial ring.
    pub fn dimension(&self) -> usize {
        self.n
    }

    /// Returns the modulus q.
    ///
    /// # Returns
    ///
    /// The modulus used for this NTT context.
    pub fn modulus(&self) -> u64 {
        self.q
    }

    /// Performs forward NTT in-place using Cooley-Tukey decimation-in-time.
    ///
    /// Converts polynomial coefficients to NTT representation (evaluations
    /// at powers of ψ). Input coefficients are automatically converted to
    /// Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Polynomial coefficients (modified in-place)
    ///
    /// # Panics
    ///
    /// Panics if `coeffs.len() != n`.
    pub fn forward(&self, coeffs: &mut [u64]) {
        assert_eq!(coeffs.len(), self.n, "Input length must match dimension");

        // Convert to Montgomery form
        for c in coeffs.iter_mut() {
            *c = Self::to_montgomery(*c, self.q, self.r_squared, self.q_inv_neg);
        }

        self.forward_inplace(coeffs);
    }

    /// Performs forward NTT assuming input is already in Montgomery form.
    ///
    /// Use this when coefficients are already in Montgomery representation
    /// to avoid redundant conversions.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Polynomial coefficients in Montgomery form (modified in-place)
    pub fn forward_inplace(&self, coeffs: &mut [u64]) {
        let n = self.n;
        let q = self.q;

        let mut t = n;
        let mut m = 1;

        while m < n {
            t >>= 1;
            for i in 0..m {
                let j1 = 2 * i * t;
                let j2 = j1 + t;
                let w = self.psi_powers[m + i];

                for j in j1..j2 {
                    let u = coeffs[j];
                    let v = self.montgomery_mul(coeffs[j + t], w);

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    coeffs[j + t] = if u >= v { u - v } else { q - v + u };
                }
            }
            m <<= 1;
        }
    }

    /// Performs inverse NTT in-place using Gentleman-Sande decimation-in-frequency.
    ///
    /// Converts NTT representation back to polynomial coefficients.
    /// Output is automatically converted from Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - NTT representation (modified in-place)
    ///
    /// # Panics
    ///
    /// Panics if `coeffs.len() != n`.
    pub fn inverse(&self, coeffs: &mut [u64]) {
        assert_eq!(coeffs.len(), self.n, "Input length must match dimension");

        self.inverse_inplace(coeffs);

        // Convert from Montgomery form
        for c in coeffs.iter_mut() {
            *c = self.montgomery_mul(*c, 1);
        }
    }

    /// Performs inverse NTT, output remains in Montgomery form.
    ///
    /// Use this when you need to continue operations in Montgomery form
    /// after the inverse NTT.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - NTT representation in Montgomery form (modified in-place)
    pub fn inverse_inplace(&self, coeffs: &mut [u64]) {
        let n = self.n;
        let q = self.q;

        let mut t = 1;
        let mut m = n;

        while m > 1 {
            m >>= 1;
            let j1 = 0;
            for i in 0..m {
                let j2 = j1 + i * 2 * t;
                let w = self.psi_inv_powers[m + i];

                for j in j2..(j2 + t) {
                    let u = coeffs[j];
                    let v = coeffs[j + t];

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    let diff = if u >= v { u - v } else { q - v + u };
                    coeffs[j + t] = self.montgomery_mul(diff, w);
                }
            }
            t <<= 1;
        }

        // Scale by n^(-1)
        for c in coeffs.iter_mut() {
            *c = self.montgomery_mul(*c, self.n_inv);
        }
    }

    /// Performs pointwise multiplication in NTT domain.
    ///
    /// Both inputs must be in Montgomery form (as produced by `forward`).
    ///
    /// # Arguments
    ///
    /// * `a` - First polynomial in NTT domain
    /// * `b` - Second polynomial in NTT domain
    /// * `result` - Output buffer for the product
    ///
    /// # Panics
    ///
    /// Panics if any array length does not equal n.
    pub fn pointwise_mul(&self, a: &[u64], b: &[u64], result: &mut [u64]) {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        assert_eq!(result.len(), self.n);

        for i in 0..self.n {
            result[i] = self.montgomery_mul(a[i], b[i]);
        }
    }

    /// Performs a single pointwise multiplication.
    ///
    /// Useful for fused multiply-add operations.
    ///
    /// # Arguments
    ///
    /// * `a` - First value in Montgomery form
    /// * `b` - Second value in Montgomery form
    ///
    /// # Returns
    ///
    /// The product `(a * b) mod q` in Montgomery form.
    #[inline]
    pub fn pointwise_mul_single(&self, a: u64, b: u64) -> u64 {
        self.montgomery_mul(a, b)
    }

    /// Converts a value to Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `a` - Value in standard representation
    ///
    /// # Returns
    ///
    /// The value in Montgomery form.
    pub fn to_mont(&self, a: u64) -> u64 {
        Self::to_montgomery(a, self.q, self.r_squared, self.q_inv_neg)
    }

    /// Converts a value from Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `a` - Value in Montgomery form
    ///
    /// # Returns
    ///
    /// The value in standard representation.
    pub fn from_mont(&self, a: u64) -> u64 {
        self.montgomery_mul(a, 1)
    }

    fn montgomery_mul(&self, a: u64, b: u64) -> u64 {
        let ab = (a as u128) * (b as u128);
        let m = ((ab as u64).wrapping_mul(self.q_inv_neg)) as u128;
        let t = ((ab + m * (self.q as u128)) >> 64) as u64;
        if t >= self.q {
            t - self.q
        } else {
            t
        }
    }

    fn to_montgomery(a: u64, q: u64, r_squared: u64, q_inv_neg: u64) -> u64 {
        let ab = (a as u128) * (r_squared as u128);
        let m = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
        let t = ((ab + m * (q as u128)) >> 64) as u64;
        if t >= q {
            t - q
        } else {
            t
        }
    }

    fn compute_q_inv_neg(q: u64) -> u64 {
        let mut y: u64 = 1;
        for i in 1..64 {
            let yi = y.wrapping_mul(q) & (1u64 << i);
            y |= yi;
        }
        y.wrapping_neg()
    }

    fn compute_r_squared(q: u64) -> u64 {
        let r_mod_q = (1u128 << 64) % (q as u128);
        ((r_mod_q * r_mod_q) % (q as u128)) as u64
    }

    fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 {
                result = ((result as u128 * base as u128) % m as u128) as u64;
            }
            exp >>= 1;
            base = ((base as u128 * base as u128) % m as u128) as u64;
        }
        result
    }

    /// Find a primitive n-th root of unity modulo q
    fn find_primitive_root(n: u64, q: u64) -> u64 {
        // g is a generator of Z_q^*, find ψ = g^((q-1)/n)
        let exp = (q - 1) / n;

        // Try small generators
        for g in 2..q {
            let candidate = Self::mod_pow(g, exp, q);
            // Check that ψ^n = 1 and ψ^(n/2) ≠ 1
            if Self::mod_pow(candidate, n, q) == 1 && Self::mod_pow(candidate, n / 2, q) != 1 {
                return candidate;
            }
        }
        panic!("No primitive root found (should not happen for valid parameters)");
    }

    /// Compute twiddle factors in the order needed for NTT
    fn compute_twiddle_factors(
        n: usize,
        psi: u64,
        q: u64,
        q_inv_neg: u64,
        r_squared: u64,
    ) -> Vec<u64> {
        let mut factors = vec![0u64; n];

        // factors[0] is unused, factors[1] = ψ^0 = 1
        factors[1] = Self::to_montgomery(1, q, r_squared, q_inv_neg);

        // Build in bit-reversed order for efficient access
        for m in 1..n {
            if m.is_power_of_two() {
                // New level: compute ψ^(n/(2m))
                let exp = n / (2 * m);

                // ψ^exp in Montgomery form
                let mut pow = Self::to_montgomery(1, q, r_squared, q_inv_neg);
                for _ in 0..exp {
                    let ab = (pow as u128) * (psi as u128);
                    let mm = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
                    pow = ((ab + mm * (q as u128)) >> 64) as u64;
                    if pow >= q {
                        pow -= q;
                    }
                }
                factors[m] = pow;
            } else {
                // Multiply previous by ψ^(n/m) computed from factors[m - (m & -m as isize as usize)]
                let prev_idx = m & (m - 1); // Clear lowest set bit
                let step_idx = m & (!m + 1); // Lowest set bit

                let ab = (factors[prev_idx] as u128) * (factors[step_idx] as u128);
                let mm = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
                let t = ((ab + mm * (q as u128)) >> 64) as u64;
                factors[m] = if t >= q { t - q } else { t };
            }
        }

        factors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_inverse_roundtrip_small() {
        let n = 16;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_1024() {
        let n = 1024;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_2048() {
        let n = 2048;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).map(|i| i * 1000 % DEFAULT_Q).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_4096() {
        let n = 4096;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).map(|i| (i * 12345) % DEFAULT_Q).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_zero_polynomial() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        let mut coeffs = vec![0u64; n];
        ctx.forward(&mut coeffs);

        assert!(coeffs.iter().all(|&c| c == 0));

        ctx.inverse(&mut coeffs);
        assert!(coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_ntt_constant_polynomial() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        let mut coeffs = vec![0u64; n];
        coeffs[0] = 42;
        let original = coeffs.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_pointwise_multiplication() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        // a(x) = 1, b(x) = 1 => a*b = 1
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        a[0] = 1;
        b[0] = 1;

        ctx.forward(&mut a);
        ctx.forward(&mut b);

        let mut result = vec![0u64; n];
        ctx.pointwise_mul(&a, &b, &mut result);

        ctx.inverse(&mut result);

        assert_eq!(result[0], 1);
        assert!(result[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_negacyclic_convolution() {
        // For R_q = Z_q[X]/(X^n + 1), x^n = -1
        // So x * x^(n-1) = x^n = -1 (mod X^n + 1)
        let n = 256;
        let q = DEFAULT_Q;
        let ctx = NttContext::with_default_q(n);

        // a(x) = x (coefficient at index 1)
        let mut a = vec![0u64; n];
        a[1] = 1;

        // b(x) = x^(n-1) (coefficient at index n-1)
        let mut b = vec![0u64; n];
        b[n - 1] = 1;

        ctx.forward(&mut a);
        ctx.forward(&mut b);

        let mut result = vec![0u64; n];
        ctx.pointwise_mul(&a, &b, &mut result);

        ctx.inverse(&mut result);

        // Result should be x^n = -1 (mod X^n + 1) = q - 1 in coefficient 0
        assert_eq!(result[0], q - 1);
        assert!(result[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_linearity() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);
        let q = DEFAULT_Q;

        let a: Vec<u64> = (0..n as u64).collect();
        let b: Vec<u64> = (0..n as u64).map(|i| (i * 2) % q).collect();

        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();
        ctx.forward(&mut a_ntt);
        ctx.forward(&mut b_ntt);

        // NTT(a + b) should equal NTT(a) + NTT(b)
        let mut sum: Vec<u64> = a.iter().zip(b.iter()).map(|(&x, &y)| (x + y) % q).collect();
        ctx.forward(&mut sum);

        for i in 0..n {
            let expected = (a_ntt[i] + b_ntt[i]) % q;
            assert_eq!(sum[i], expected);
        }
    }
}
