//! Polynomial operations over R_q = Z_q[X]/(X^d + 1)
//!
//! Provides polynomial arithmetic using NTT for efficient multiplication.

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use super::mod_q::{ModQ, DEFAULT_Q};
use super::ntt::NttContext;
use super::sampler::GaussianSampler;
use rand::Rng;

/// Polynomial in R_q = Z_q[X]/(X^d + 1)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Poly {
    /// Coefficients in coefficient or NTT domain
    coeffs: Vec<u64>,
    /// Modulus q
    q: u64,
    /// Whether coefficients are in NTT domain
    is_ntt: bool,
}

impl Poly {
    /// Create zero polynomial with given dimension and modulus
    pub fn zero(dim: usize, q: u64) -> Self {
        Self {
            coeffs: vec![0; dim],
            q,
            is_ntt: false,
        }
    }

    /// Create zero polynomial with default modulus
    pub fn zero_default(dim: usize) -> Self {
        Self::zero(dim, DEFAULT_Q)
    }

    /// Create polynomial from coefficient vector
    pub fn from_coeffs(coeffs: Vec<u64>, q: u64) -> Self {
        let mut p = Self {
            coeffs,
            q,
            is_ntt: false,
        };
        p.reduce();
        p
    }

    /// Create polynomial from coefficients with default modulus
    pub fn from_coeffs_default(coeffs: Vec<u64>) -> Self {
        Self::from_coeffs(coeffs, DEFAULT_Q)
    }

    /// Create polynomial with a single coefficient (constant polynomial)
    pub fn constant(value: u64, dim: usize, q: u64) -> Self {
        let mut coeffs = vec![0; dim];
        coeffs[0] = value % q;
        Self {
            coeffs,
            q,
            is_ntt: false,
        }
    }

    /// Sample polynomial with coefficients from discrete Gaussian distribution
    pub fn sample_gaussian(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Self {
        let coeffs = sampler.sample_vec_centered(dim, q);
        Self {
            coeffs,
            q,
            is_ntt: false,
        }
    }

    /// Generate a uniformly random polynomial
    pub fn random(dim: usize, q: u64) -> Self {
        let mut rng = rand::thread_rng();
        let coeffs: Vec<u64> = (0..dim).map(|_| rng.gen_range(0..q)).collect();
        Self {
            coeffs,
            q,
            is_ntt: false,
        }
    }

    /// Generate a uniformly random polynomial with given RNG
    pub fn random_with_rng<R: Rng>(dim: usize, q: u64, rng: &mut R) -> Self {
        let coeffs: Vec<u64> = (0..dim).map(|_| rng.gen_range(0..q)).collect();
        Self {
            coeffs,
            q,
            is_ntt: false,
        }
    }

    /// Get polynomial dimension
    pub fn dimension(&self) -> usize {
        self.coeffs.len()
    }

    /// Get polynomial length (alias for dimension)
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Check if polynomial has zero length
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Get modulus
    pub fn modulus(&self) -> u64 {
        self.q
    }

    /// Check if in NTT domain
    pub fn is_ntt(&self) -> bool {
        self.is_ntt
    }

    /// Get coefficient at index (only valid if not in NTT domain)
    pub fn coeff(&self, i: usize) -> u64 {
        assert!(!self.is_ntt, "Cannot access coefficients in NTT domain");
        self.coeffs[i]
    }

    /// Set coefficient at index (only valid if not in NTT domain)
    pub fn set_coeff(&mut self, i: usize, value: u64) {
        assert!(!self.is_ntt, "Cannot set coefficients in NTT domain");
        self.coeffs[i] = value % self.q;
    }

    /// Get reference to coefficient/NTT vector
    pub fn coeffs(&self) -> &[u64] {
        &self.coeffs
    }

    /// Get mutable reference to coefficient/NTT vector
    pub fn coeffs_mut(&mut self) -> &mut [u64] {
        &mut self.coeffs
    }

    /// Reduce all coefficients modulo q
    fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c %= self.q;
        }
    }

    /// Convert to NTT domain
    pub fn to_ntt(&mut self, ctx: &NttContext) {
        if !self.is_ntt {
            ctx.forward(&mut self.coeffs);
            self.is_ntt = true;
        }
    }

    /// Convert from NTT domain to coefficient domain
    pub fn from_ntt(&mut self, ctx: &NttContext) {
        if self.is_ntt {
            ctx.inverse(&mut self.coeffs);
            self.is_ntt = false;
        }
    }

    /// Create a copy in NTT domain
    pub fn to_ntt_new(&self, ctx: &NttContext) -> Self {
        let mut result = self.clone();
        result.to_ntt(ctx);
        result
    }

    /// Create a copy in coefficient domain
    pub fn from_ntt_new(&self, ctx: &NttContext) -> Self {
        let mut result = self.clone();
        result.from_ntt(ctx);
        result
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: u64) -> Self {
        let scalar = scalar % self.q;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&c| ((c as u128 * scalar as u128) % self.q as u128) as u64)
            .collect();

        Self {
            coeffs,
            q: self.q,
            is_ntt: self.is_ntt,
        }
    }

    /// In-place scalar multiplication
    pub fn scalar_mul_assign(&mut self, scalar: u64) {
        let scalar = scalar % self.q;
        for c in &mut self.coeffs {
            *c = ((*c as u128 * scalar as u128) % self.q as u128) as u64;
        }
    }

    /// Scalar multiplication with ModQ
    pub fn scalar_mul_modq(&self, scalar: ModQ) -> Self {
        self.scalar_mul(scalar.value())
    }

    /// Polynomial multiplication using NTT (negacyclic for X^d + 1)
    pub fn mul_ntt(&self, other: &Self, ctx: &NttContext) -> Self {
        assert_eq!(self.q, other.q, "Moduli must match");
        assert_eq!(self.coeffs.len(), other.coeffs.len(), "Dimensions must match");

        let mut a = self.clone();
        let mut b = other.clone();

        a.to_ntt(ctx);
        b.to_ntt(ctx);

        let mut result = vec![0u64; self.coeffs.len()];
        ctx.pointwise_mul(&a.coeffs, &b.coeffs, &mut result);

        let mut poly = Self {
            coeffs: result,
            q: self.q,
            is_ntt: true,
        };
        poly.from_ntt(ctx);
        poly
    }

    /// Polynomial multiplication when both are already in NTT domain
    pub fn mul_ntt_domain(&self, other: &Self, ctx: &NttContext) -> Self {
        assert!(self.is_ntt && other.is_ntt, "Both polynomials must be in NTT domain");
        assert_eq!(self.q, other.q, "Moduli must match");

        let mut result = vec![0u64; self.coeffs.len()];
        ctx.pointwise_mul(&self.coeffs, &other.coeffs, &mut result);

        Self {
            coeffs: result,
            q: self.q,
            is_ntt: true,
        }
    }

    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|&c| c == 0)
    }

    /// L-infinity norm (maximum absolute coefficient value)
    /// For centered representation: returns max(|c|, |q - c|) for each c
    pub fn linf_norm(&self) -> u64 {
        assert!(!self.is_ntt, "Cannot compute norm in NTT domain");
        self.coeffs
            .iter()
            .map(|&c| {
                if c <= self.q / 2 {
                    c
                } else {
                    self.q - c
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// L2 norm squared (sum of squared coefficients in centered representation)
    pub fn l2_norm_squared(&self) -> u128 {
        assert!(!self.is_ntt, "Cannot compute norm in NTT domain");
        self.coeffs
            .iter()
            .map(|&c| {
                let centered = if c <= self.q / 2 {
                    c as i64
                } else {
                    c as i64 - self.q as i64
                };
                (centered as i128 * centered as i128) as u128
            })
            .sum()
    }

    /// Polynomial multiplication (method style, uses NTT internally)
    pub fn mul(&self, other: &Self) -> Self {
        let ctx = NttContext::new(self.coeffs.len(), self.q);
        self.mul_ntt(other, &ctx)
    }

    /// Polynomial addition (method style)
    pub fn add(&self, other: &Self) -> Self {
        self + other
    }

    /// Polynomial subtraction (method style)
    pub fn sub(&self, other: &Self) -> Self {
        self - other
    }

    /// Negate polynomial (method style)
    pub fn negate(&self) -> Self {
        -self
    }
}

impl PartialEq for Poly {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q && self.is_ntt == other.is_ntt && self.coeffs == other.coeffs
    }
}

impl Eq for Poly {}

impl Add for Poly {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl Add for &Poly {
    type Output = Poly;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(self.q, rhs.q, "Moduli must match");
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");

        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(&a, &b)| {
                let sum = a + b;
                if sum >= self.q {
                    sum - self.q
                } else {
                    sum
                }
            })
            .collect();

        Poly {
            coeffs,
            q: self.q,
            is_ntt: self.is_ntt,
        }
    }
}

impl AddAssign for Poly {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl AddAssign<&Poly> for Poly {
    fn add_assign(&mut self, rhs: &Self) {
        *self = &*self + rhs;
    }
}

impl Sub for Poly {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl Sub for &Poly {
    type Output = Poly;

    fn sub(self, rhs: Self) -> Self::Output {
        assert_eq!(self.q, rhs.q, "Moduli must match");
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");

        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(&a, &b)| {
                if a >= b {
                    a - b
                } else {
                    self.q - b + a
                }
            })
            .collect();

        Poly {
            coeffs,
            q: self.q,
            is_ntt: self.is_ntt,
        }
    }
}

impl SubAssign for Poly {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl SubAssign<&Poly> for Poly {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = &*self - rhs;
    }
}

impl Neg for Poly {
    type Output = Self;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl Neg for &Poly {
    type Output = Poly;

    fn neg(self) -> Self::Output {
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&c| if c == 0 { 0 } else { self.q - c })
            .collect();

        Poly {
            coeffs,
            q: self.q,
            is_ntt: self.is_ntt,
        }
    }
}

impl Mul for Poly {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");
        assert!(self.is_ntt, "Use mul_ntt for coefficient domain multiplication");

        let ctx = NttContext::new(self.coeffs.len(), self.q);
        self.mul_ntt_domain(&rhs, &ctx)
    }
}

impl MulAssign for Poly {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(n: usize) -> NttContext {
        NttContext::with_default_q(n)
    }

    #[test]
    fn test_zero_polynomial() {
        let p = Poly::zero_default(256);
        assert!(p.is_zero());
        assert_eq!(p.dimension(), 256);
    }

    #[test]
    fn test_constant_polynomial() {
        let p = Poly::constant(42, 256, DEFAULT_Q);
        assert_eq!(p.coeff(0), 42);
        assert!(p.coeffs()[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_addition() {
        let a = Poly::from_coeffs_default(vec![1, 2, 3, 4]);
        let b = Poly::from_coeffs_default(vec![5, 6, 7, 8]);
        let c = &a + &b;

        assert_eq!(c.coeff(0), 6);
        assert_eq!(c.coeff(1), 8);
        assert_eq!(c.coeff(2), 10);
        assert_eq!(c.coeff(3), 12);
    }

    #[test]
    fn test_subtraction() {
        let q = DEFAULT_Q;
        let a = Poly::from_coeffs(vec![10, 20, 30, 40], q);
        let b = Poly::from_coeffs(vec![5, 6, 7, 8], q);
        let c = &a - &b;

        assert_eq!(c.coeff(0), 5);
        assert_eq!(c.coeff(1), 14);
        assert_eq!(c.coeff(2), 23);
        assert_eq!(c.coeff(3), 32);
    }

    #[test]
    fn test_subtraction_underflow() {
        let q = DEFAULT_Q;
        let a = Poly::from_coeffs(vec![5, 6, 7, 8], q);
        let b = Poly::from_coeffs(vec![10, 20, 30, 40], q);
        let c = &a - &b;

        assert_eq!(c.coeff(0), q - 5);
        assert_eq!(c.coeff(1), q - 14);
    }

    #[test]
    fn test_negation() {
        let q = DEFAULT_Q;
        let a = Poly::from_coeffs(vec![1, 2, 3, 0], q);
        let neg_a = -&a;

        assert_eq!(neg_a.coeff(0), q - 1);
        assert_eq!(neg_a.coeff(1), q - 2);
        assert_eq!(neg_a.coeff(2), q - 3);
        assert_eq!(neg_a.coeff(3), 0);

        let sum = &a + &neg_a;
        assert!(sum.is_zero());
    }

    #[test]
    fn test_scalar_multiplication() {
        let a = Poly::from_coeffs_default(vec![1, 2, 3, 4]);
        let b = a.scalar_mul(10);

        assert_eq!(b.coeff(0), 10);
        assert_eq!(b.coeff(1), 20);
        assert_eq!(b.coeff(2), 30);
        assert_eq!(b.coeff(3), 40);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let ctx = make_ctx(256);
        let mut p = Poly::from_coeffs_default((0..256).collect());

        let original = p.clone();
        p.to_ntt(&ctx);
        assert!(p.is_ntt());
        p.from_ntt(&ctx);
        assert!(!p.is_ntt());

        assert_eq!(p, original);
    }

    #[test]
    fn test_poly_mul_ntt_identity() {
        let n = 256;
        let ctx = make_ctx(n);

        // a(x) * 1 = a(x)
        let a = Poly::from_coeffs_default((0..n as u64).collect());
        let one = Poly::constant(1, n, DEFAULT_Q);

        let result = a.mul_ntt(&one, &ctx);
        assert_eq!(result, a);
    }

    #[test]
    fn test_poly_mul_ntt_zero() {
        let n = 256;
        let ctx = make_ctx(n);

        let a = Poly::from_coeffs_default((0..n as u64).collect());
        let zero = Poly::zero_default(n);

        let result = a.mul_ntt(&zero, &ctx);
        assert!(result.is_zero());
    }

    #[test]
    fn test_poly_mul_ntt_simple() {
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        // (1 + x) * (1 + x) = 1 + 2x + x^2
        let mut coeffs = vec![0u64; n];
        coeffs[0] = 1;
        coeffs[1] = 1;
        let a = Poly::from_coeffs(coeffs, q);

        let result = a.mul_ntt(&a, &ctx);

        assert_eq!(result.coeff(0), 1);
        assert_eq!(result.coeff(1), 2);
        assert_eq!(result.coeff(2), 1);
        assert!(result.coeffs()[3..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_poly_mul_ntt_negacyclic() {
        // In R_q = Z_q[X]/(X^n + 1), x^n = -1
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        // x * x^(n-1) = x^n = -1 (mod X^n + 1)
        let mut a_coeffs = vec![0u64; n];
        a_coeffs[1] = 1; // x
        let a = Poly::from_coeffs(a_coeffs, q);

        let mut b_coeffs = vec![0u64; n];
        b_coeffs[n - 1] = 1; // x^(n-1)
        let b = Poly::from_coeffs(b_coeffs, q);

        let result = a.mul_ntt(&b, &ctx);

        assert_eq!(result.coeff(0), q - 1); // -1 mod q
        assert!(result.coeffs()[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_poly_mul_associativity() {
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        let a = Poly::from_coeffs((0..n as u64).map(|i| i % 100).collect(), q);
        let b = Poly::from_coeffs((0..n as u64).map(|i| (i * 7) % 100).collect(), q);
        let c = Poly::from_coeffs((0..n as u64).map(|i| (i * 13) % 100).collect(), q);

        // (a * b) * c
        let ab = a.mul_ntt(&b, &ctx);
        let ab_c = ab.mul_ntt(&c, &ctx);

        // a * (b * c)
        let bc = b.mul_ntt(&c, &ctx);
        let a_bc = a.mul_ntt(&bc, &ctx);

        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_poly_mul_commutativity() {
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        let a = Poly::from_coeffs((0..n as u64).map(|i| i % 100).collect(), q);
        let b = Poly::from_coeffs((0..n as u64).map(|i| (i * 7) % 100).collect(), q);

        let ab = a.mul_ntt(&b, &ctx);
        let ba = b.mul_ntt(&a, &ctx);

        assert_eq!(ab, ba);
    }

    #[test]
    fn test_poly_mul_distributivity() {
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        let a = Poly::from_coeffs((0..n as u64).map(|i| i % 50).collect(), q);
        let b = Poly::from_coeffs((0..n as u64).map(|i| (i * 3) % 50).collect(), q);
        let c = Poly::from_coeffs((0..n as u64).map(|i| (i * 5) % 50).collect(), q);

        // a * (b + c)
        let b_plus_c = &b + &c;
        let left = a.mul_ntt(&b_plus_c, &ctx);

        // a * b + a * c
        let ab = a.mul_ntt(&b, &ctx);
        let ac = a.mul_ntt(&c, &ctx);
        let right = &ab + &ac;

        assert_eq!(left, right);
    }

    #[test]
    fn test_linf_norm() {
        let q = DEFAULT_Q;
        let mut coeffs = vec![0u64; 16];
        coeffs[0] = 100;
        coeffs[1] = q - 50; // represents -50
        let p = Poly::from_coeffs(coeffs, q);

        assert_eq!(p.linf_norm(), 100);
    }

    #[test]
    fn test_l2_norm() {
        let q = DEFAULT_Q;
        let mut coeffs = vec![0u64; 4];
        coeffs[0] = 3;
        coeffs[1] = 4;
        let p = Poly::from_coeffs(coeffs, q);

        // 3^2 + 4^2 = 9 + 16 = 25
        assert_eq!(p.l2_norm_squared(), 25);
    }

    #[test]
    fn test_ntt_domain_multiplication() {
        let n = 256;
        let ctx = make_ctx(n);
        let q = DEFAULT_Q;

        let a = Poly::from_coeffs((0..n as u64).map(|i| i % 100).collect(), q);
        let b = Poly::from_coeffs((0..n as u64).map(|i| (i * 7) % 100).collect(), q);

        // Standard multiplication
        let result1 = a.mul_ntt(&b, &ctx);

        // NTT domain multiplication
        let a_ntt = a.to_ntt_new(&ctx);
        let b_ntt = b.to_ntt_new(&ctx);
        let mut result2 = a_ntt.mul_ntt_domain(&b_ntt, &ctx);
        result2.from_ntt(&ctx);

        assert_eq!(result1, result2);
    }
}
