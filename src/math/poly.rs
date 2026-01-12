//! Polynomial operations over R_q = Z_q[X]/(X^d + 1).
//!
//! Provides polynomial arithmetic using NTT for efficient multiplication.
//! Polynomials can exist in either coefficient domain or NTT domain.
//!
//! # Overview
//!
//! The polynomial ring R_q = Z_q[X]/(X^d + 1) is fundamental to lattice-based
//! cryptography. This module provides:
//!
//! - Basic arithmetic: addition, subtraction, negation, scalar multiplication
//! - NTT-based multiplication for O(n log n) performance
//! - Domain conversion between coefficient and NTT representations
//! - Random and Gaussian polynomial sampling
//!
//! # Example
//!
//! ```
//! use inspire::math::{Poly, NttContext};
//! use inspire::math::mod_q::DEFAULT_Q;
//!
//! let ctx = NttContext::with_default_q(256);
//!
//! // Create polynomials
//! let a = Poly::random(256, DEFAULT_Q);
//! let b = Poly::random(256, DEFAULT_Q);
//!
//! // Multiply using NTT
//! let product = a.mul_ntt(&b, &ctx);
//! ```

use super::crt::{crt_compose_2, crt_decompose_2, crt_modulus, mod_inverse};
use super::gaussian::GaussianSampler;
use super::mod_q::{ModQ, DEFAULT_Q};
use super::ntt::NttContext;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Polynomial in R_q = Z_q[X]/(X^d + 1).
///
/// Represents a polynomial with coefficients in Z_q, reduced modulo X^d + 1.
/// Polynomials can be in coefficient domain or NTT domain for efficient
/// multiplication.
///
/// # Fields
///
/// * `coeffs` - Coefficients in coefficient or NTT domain
/// * `q` - Modulus q
/// * `is_ntt` - Whether coefficients are in NTT domain
///
/// # Example
///
/// ```
/// use inspire::math::Poly;
/// use inspire::math::mod_q::DEFAULT_Q;
///
/// let poly = Poly::constant(42, 256, DEFAULT_Q);
/// assert_eq!(poly.coeff(0), 42);
/// assert_eq!(poly.dimension(), 256);
/// ```
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Poly {
    /// Coefficients in coefficient or NTT domain.
    coeffs: Vec<u64>,
    /// CRT moduli (length 1 for single-modulus).
    moduli: Vec<u64>,
    /// Composite modulus q (product of CRT moduli).
    q: u64,
    /// Ring dimension (number of coefficients per modulus).
    dim: usize,
    /// Cached inverse of moduli[0] modulo moduli[1] (for CRT compose).
    crt_q0_inv_mod_q1: u64,
    /// Whether coefficients are in NTT domain.
    is_ntt: bool,
}

impl Poly {
    fn init_moduli(moduli: &[u64]) -> (Vec<u64>, u64, u64) {
        assert!(!moduli.is_empty(), "moduli must be non-empty");
        if moduli.len() > 2 {
            panic!("CRT with more than 2 moduli not supported");
        }
        let moduli_vec = moduli.to_vec();
        let q = crt_modulus(&moduli_vec);
        let inv = if moduli_vec.len() == 2 {
            mod_inverse(moduli_vec[0], moduli_vec[1])
        } else {
            0
        };
        (moduli_vec, q, inv)
    }

    /// Create zero polynomial with given dimension and modulus
    pub fn zero(dim: usize, q: u64) -> Self {
        Self::zero_moduli(dim, &[q])
    }

    /// Create zero polynomial with CRT moduli.
    pub fn zero_moduli(dim: usize, moduli: &[u64]) -> Self {
        let (moduli_vec, q, inv) = Self::init_moduli(moduli);
        let crt_count = moduli_vec.len();
        Self {
            coeffs: vec![0; dim * crt_count],
            moduli: moduli_vec,
            q,
            dim,
            crt_q0_inv_mod_q1: inv,
            is_ntt: false,
        }
    }

    /// Create zero polynomial with default modulus
    pub fn zero_default(dim: usize) -> Self {
        Self::zero(dim, DEFAULT_Q)
    }

    /// Create polynomial from coefficient vector
    pub fn from_coeffs(coeffs: Vec<u64>, q: u64) -> Self {
        Self::from_coeffs_moduli(coeffs, &[q])
    }

    /// Create polynomial from coefficients with CRT moduli.
    ///
    /// `coeffs` are interpreted modulo the composite modulus and split into residues.
    pub fn from_coeffs_moduli(coeffs: Vec<u64>, moduli: &[u64]) -> Self {
        let dim = coeffs.len();
        let (moduli_vec, q, inv) = Self::init_moduli(moduli);
        let crt_count = moduli_vec.len();
        let mut crt_coeffs = vec![0u64; dim * crt_count];

        if crt_count == 1 {
            for (i, &c) in coeffs.iter().enumerate() {
                crt_coeffs[i] = c % moduli_vec[0];
            }
        } else if crt_count == 2 {
            let q0 = moduli_vec[0];
            let q1 = moduli_vec[1];
            for (i, &c) in coeffs.iter().enumerate() {
                let (c0, c1) = crt_decompose_2(c, q0, q1);
                crt_coeffs[i] = c0;
                crt_coeffs[i + dim] = c1;
            }
        } else {
            panic!("CRT with more than 2 moduli not supported");
        }

        let mut p = Self {
            coeffs: crt_coeffs,
            moduli: moduli_vec,
            q,
            dim,
            crt_q0_inv_mod_q1: inv,
            is_ntt: false,
        };
        p.reduce();
        p
    }

    /// Create polynomial from CRT-residue coefficients.
    ///
    /// `coeffs` must be length `dim * crt_count` with residues concatenated
    /// by modulus: [mod0_coeffs..., mod1_coeffs..., ...].
    pub fn from_crt_coeffs(coeffs: Vec<u64>, moduli: &[u64]) -> Self {
        let (moduli_vec, q, inv) = Self::init_moduli(moduli);
        let crt_count = moduli_vec.len();
        assert!(
            coeffs.len() % crt_count == 0,
            "CRT coeffs length must be a multiple of crt_count"
        );
        let dim = coeffs.len() / crt_count;
        let mut p = Self {
            coeffs,
            moduli: moduli_vec,
            q,
            dim,
            crt_q0_inv_mod_q1: inv,
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
        Self::constant_moduli(value, dim, &[q])
    }

    /// Create constant polynomial with CRT moduli.
    pub fn constant_moduli(value: u64, dim: usize, moduli: &[u64]) -> Self {
        let mut coeffs = vec![0u64; dim];
        coeffs[0] = value;
        Self::from_coeffs_moduli(coeffs, moduli)
    }

    /// Sample polynomial with coefficients from discrete Gaussian distribution
    pub fn sample_gaussian(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Self {
        Self::sample_gaussian_moduli(dim, &[q], sampler)
    }

    /// Sample polynomial with CRT moduli.
    pub fn sample_gaussian_moduli(
        dim: usize,
        moduli: &[u64],
        sampler: &mut GaussianSampler,
    ) -> Self {
        let (moduli_vec, q, inv) = Self::init_moduli(moduli);
        let crt_count = moduli_vec.len();
        let mut coeffs = vec![0u64; dim * crt_count];
        let samples = sampler.sample_vec(dim);
        for (m, &modulus) in moduli_vec.iter().enumerate() {
            let offset = m * dim;
            for i in 0..dim {
                coeffs[offset + i] = crate::math::ModQ::from_signed(samples[i], modulus);
            }
        }

        Self {
            coeffs,
            moduli: moduli_vec,
            q,
            dim,
            crt_q0_inv_mod_q1: inv,
            is_ntt: false,
        }
    }

    /// Generate a uniformly random polynomial
    pub fn random(dim: usize, q: u64) -> Self {
        Self::random_moduli(dim, &[q])
    }

    /// Generate a uniformly random polynomial with CRT moduli.
    pub fn random_moduli(dim: usize, moduli: &[u64]) -> Self {
        let mut rng = rand::thread_rng();
        Self::random_with_rng_moduli(dim, moduli, &mut rng)
    }

    /// Generate a uniformly random polynomial with given RNG
    pub fn random_with_rng<R: Rng>(dim: usize, q: u64, rng: &mut R) -> Self {
        Self::random_with_rng_moduli(dim, &[q], rng)
    }

    /// Generate a uniformly random polynomial with CRT moduli and given RNG.
    pub fn random_with_rng_moduli<R: Rng>(dim: usize, moduli: &[u64], rng: &mut R) -> Self {
        let (moduli_vec, q, inv) = Self::init_moduli(moduli);
        let crt_count = moduli_vec.len();
        let mut coeffs = vec![0u64; dim * crt_count];
        for (m, &modulus) in moduli_vec.iter().enumerate() {
            for i in 0..dim {
                coeffs[m * dim + i] = rng.gen_range(0..modulus);
            }
        }
        Self {
            coeffs,
            moduli: moduli_vec,
            q,
            dim,
            crt_q0_inv_mod_q1: inv,
            is_ntt: false,
        }
    }

    /// Generate a deterministic random polynomial from a 32-byte seed
    ///
    /// Uses ChaCha20 for expansion. The same seed always produces the same polynomial.
    pub fn from_seed(seed: &[u8; 32], dim: usize, q: u64) -> Self {
        Self::from_seed_moduli(seed, dim, &[q])
    }

    /// Generate a deterministic random polynomial from a 32-byte seed and CRT moduli.
    pub fn from_seed_moduli(seed: &[u8; 32], dim: usize, moduli: &[u64]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        Self::random_with_rng_moduli(dim, moduli, &mut rng)
    }

    /// Generate a deterministic random polynomial from seed and index
    ///
    /// Derives a unique seed by XORing the base seed with the index.
    /// Useful for generating multiple independent polynomials from one seed.
    pub fn from_seed_indexed(seed: &[u8; 32], index: usize, dim: usize, q: u64) -> Self {
        Self::from_seed_indexed_moduli(seed, index, dim, &[q])
    }

    /// Generate a deterministic random polynomial from seed and index for CRT moduli.
    pub fn from_seed_indexed_moduli(
        seed: &[u8; 32],
        index: usize,
        dim: usize,
        moduli: &[u64],
    ) -> Self {
        let mut derived_seed = *seed;
        let idx_bytes = (index as u64).to_le_bytes();
        for i in 0..8 {
            derived_seed[i] ^= idx_bytes[i];
        }
        Self::from_seed_moduli(&derived_seed, dim, moduli)
    }

    /// Get polynomial dimension
    pub fn dimension(&self) -> usize {
        self.dim
    }

    /// Get polynomial length (alias for dimension)
    pub fn len(&self) -> usize {
        self.dim
    }

    /// Check if polynomial has zero length
    pub fn is_empty(&self) -> bool {
        self.dim == 0
    }

    /// Get modulus
    pub fn modulus(&self) -> u64 {
        self.q
    }

    /// Returns CRT moduli.
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Number of CRT moduli.
    pub fn crt_count(&self) -> usize {
        self.moduli.len()
    }

    /// Check if in NTT domain
    pub fn is_ntt(&self) -> bool {
        self.is_ntt
    }

    /// Force polynomial to be marked as NTT domain
    ///
    /// **Warning**: Only use when you know the coefficients are already NTT values.
    /// Used by apply_automorphism_ntt which permutes NTT values directly.
    #[inline]
    pub fn force_ntt_domain(&mut self) {
        self.is_ntt = true;
    }

    /// Force polynomial to be marked as coefficient domain
    ///
    /// **Warning**: Only use when you know the values are already coefficients.
    #[inline]
    pub fn force_coeff_domain(&mut self) {
        self.is_ntt = false;
    }

    /// Get coefficient at index (only valid if not in NTT domain)
    pub fn coeff(&self, i: usize) -> u64 {
        assert!(!self.is_ntt, "Cannot access coefficients in NTT domain");
        match self.moduli.len() {
            1 => self.coeffs[i],
            2 => {
                let q0 = self.moduli[0];
                let q1 = self.moduli[1];
                let a0 = self.coeffs[i];
                let a1 = self.coeffs[i + self.dim];
                crt_compose_2(a0, a1, q0, q1, self.crt_q0_inv_mod_q1) % self.q
            }
            _ => panic!("CRT with more than 2 moduli not supported"),
        }
    }

    /// Set coefficient at index (only valid if not in NTT domain)
    pub fn set_coeff(&mut self, i: usize, value: u64) {
        assert!(!self.is_ntt, "Cannot set coefficients in NTT domain");
        match self.moduli.len() {
            1 => {
                self.coeffs[i] = value % self.moduli[0];
            }
            2 => {
                let (c0, c1) = crt_decompose_2(value, self.moduli[0], self.moduli[1]);
                self.coeffs[i] = c0;
                self.coeffs[i + self.dim] = c1;
            }
            _ => panic!("CRT with more than 2 moduli not supported"),
        }
    }

    /// Get reference to coefficient/NTT vector
    pub fn coeffs(&self) -> &[u64] {
        &self.coeffs
    }

    /// Get mutable reference to coefficient/NTT vector
    pub fn coeffs_mut(&mut self) -> &mut [u64] {
        &mut self.coeffs
    }

    /// Get coefficients slice for a specific CRT modulus.
    pub fn coeffs_modulus(&self, modulus_idx: usize) -> &[u64] {
        let start = modulus_idx * self.dim;
        let end = start + self.dim;
        &self.coeffs[start..end]
    }

    /// Get mutable coefficients slice for a specific CRT modulus.
    pub fn coeffs_modulus_mut(&mut self, modulus_idx: usize) -> &mut [u64] {
        let start = modulus_idx * self.dim;
        let end = start + self.dim;
        &mut self.coeffs[start..end]
    }

    /// Reduce all coefficients modulo q
    fn reduce(&mut self) {
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for c in &mut self.coeffs[start..end] {
                *c %= modulus;
            }
        }
    }

    /// Convert to NTT domain
    pub fn to_ntt(&mut self, ctx: &NttContext) {
        if !self.is_ntt {
            debug_assert_eq!(
                self.moduli,
                ctx.moduli(),
                "NTT context moduli must match polynomial moduli"
            );
            ctx.forward(&mut self.coeffs);
            self.is_ntt = true;
        }
    }

    /// Convert from NTT domain to coefficient domain
    pub fn from_ntt(&mut self, ctx: &NttContext) {
        if self.is_ntt {
            debug_assert_eq!(
                self.moduli,
                ctx.moduli(),
                "NTT context moduli must match polynomial moduli"
            );
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
        let mut coeffs = self.coeffs.clone();
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let scalar_mod = scalar % modulus;
            let start = m * self.dim;
            let end = start + self.dim;
            for c in &mut coeffs[start..end] {
                *c = ((*c as u128 * scalar_mod as u128) % modulus as u128) as u64;
            }
        }

        Self {
            coeffs,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
            is_ntt: self.is_ntt,
        }
    }

    /// In-place scalar multiplication
    pub fn scalar_mul_assign(&mut self, scalar: u64) {
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let scalar_mod = scalar % modulus;
            let start = m * self.dim;
            let end = start + self.dim;
            for c in &mut self.coeffs[start..end] {
                *c = ((*c as u128 * scalar_mod as u128) % modulus as u128) as u64;
            }
        }
    }

    /// Scalar multiplication with ModQ
    pub fn scalar_mul_modq(&self, scalar: ModQ) -> Self {
        self.scalar_mul(scalar.value())
    }

    /// Polynomial multiplication using NTT (negacyclic for X^d + 1)
    pub fn mul_ntt(&self, other: &Self, ctx: &NttContext) -> Self {
        assert_eq!(self.moduli, other.moduli, "Moduli must match");
        assert_eq!(
            self.coeffs.len(),
            other.coeffs.len(),
            "Dimensions must match"
        );

        let mut a = self.clone();
        let mut b = other.clone();

        a.to_ntt(ctx);
        b.to_ntt(ctx);

        let mut result = vec![0u64; self.coeffs.len()];
        ctx.pointwise_mul(&a.coeffs, &b.coeffs, &mut result);

        let mut poly = Self {
            coeffs: result,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
            is_ntt: true,
        };
        poly.from_ntt(ctx);
        poly
    }

    /// Polynomial multiplication when both are already in NTT domain
    pub fn mul_ntt_domain(&self, other: &Self, ctx: &NttContext) -> Self {
        assert!(
            self.is_ntt && other.is_ntt,
            "Both polynomials must be in NTT domain"
        );
        assert_eq!(self.moduli, other.moduli, "Moduli must match");

        let mut result = vec![0u64; self.coeffs.len()];
        ctx.pointwise_mul(&self.coeffs, &other.coeffs, &mut result);

        Self {
            coeffs: result,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
            is_ntt: true,
        }
    }

    /// Polynomial addition when both are already in NTT domain
    ///
    /// **Performance**: O(n) pointwise addition without domain conversion
    pub fn add_ntt_domain(&self, other: &Self) -> Self {
        assert!(
            self.is_ntt && other.is_ntt,
            "Both polynomials must be in NTT domain"
        );
        assert_eq!(self.moduli, other.moduli, "Moduli must match");
        assert_eq!(
            self.coeffs.len(),
            other.coeffs.len(),
            "Dimensions must match"
        );

        let mut coeffs = self.coeffs.clone();
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for i in start..end {
                let sum = coeffs[i] + other.coeffs[i];
                coeffs[i] = if sum >= modulus { sum - modulus } else { sum };
            }
        }

        Self {
            coeffs,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
            is_ntt: true,
        }
    }

    /// In-place addition when both are in NTT domain
    ///
    /// **Performance**: Avoids allocation, O(n) pointwise addition
    pub fn add_assign_ntt_domain(&mut self, other: &Self) {
        assert!(
            self.is_ntt && other.is_ntt,
            "Both polynomials must be in NTT domain"
        );
        assert_eq!(self.moduli, other.moduli, "Moduli must match");

        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for i in start..end {
                let sum = self.coeffs[i] + other.coeffs[i];
                self.coeffs[i] = if sum >= modulus { sum - modulus } else { sum };
            }
        }
    }

    /// In-place multiply-accumulate in NTT domain: self += a * b
    ///
    /// **Performance**: Single pass multiply-add without intermediate allocation
    pub fn mul_acc_ntt_domain(&mut self, a: &Self, b: &Self, ctx: &NttContext) {
        assert!(
            self.is_ntt && a.is_ntt && b.is_ntt,
            "All polynomials must be in NTT domain"
        );
        assert_eq!(self.moduli, a.moduli, "Moduli must match");
        assert_eq!(self.moduli, b.moduli, "Moduli must match");

        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for i in start..end {
                let prod = ctx.pointwise_mul_single_at(a.coeffs[i], b.coeffs[i], m);
                let sum = self.coeffs[i] + prod;
                self.coeffs[i] = if sum >= modulus { sum - modulus } else { sum };
            }
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
        let mut max_val = 0u64;
        for i in 0..self.dim {
            let c = self.coeff(i);
            let centered = if c <= self.q / 2 { c } else { self.q - c };
            if centered > max_val {
                max_val = centered;
            }
        }
        max_val
    }

    /// L2 norm squared (sum of squared coefficients in centered representation)
    pub fn l2_norm_squared(&self) -> u128 {
        assert!(!self.is_ntt, "Cannot compute norm in NTT domain");
        let mut sum = 0u128;
        for i in 0..self.dim {
            let c = self.coeff(i);
            let centered = if c <= self.q / 2 {
                c as i64
            } else {
                c as i64 - self.q as i64
            };
            sum += (centered as i128 * centered as i128) as u128;
        }
        sum
    }

    /// Polynomial multiplication (method style, uses NTT internally)
    pub fn mul(&self, other: &Self) -> Self {
        let ctx = NttContext::with_moduli(self.dim, &self.moduli);
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
        self.q == other.q
            && self.moduli == other.moduli
            && self.dim == other.dim
            && self.is_ntt == other.is_ntt
            && self.coeffs == other.coeffs
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
        assert_eq!(self.moduli, rhs.moduli, "Moduli must match");
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");

        let mut coeffs = self.coeffs.clone();
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for i in start..end {
                let sum = coeffs[i] + rhs.coeffs[i];
                coeffs[i] = if sum >= modulus { sum - modulus } else { sum };
            }
        }

        Poly {
            coeffs,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
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
        assert_eq!(self.moduli, rhs.moduli, "Moduli must match");
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");

        let mut coeffs = self.coeffs.clone();
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for i in start..end {
                let a = coeffs[i];
                let b = rhs.coeffs[i];
                coeffs[i] = if a >= b { a - b } else { modulus - b + a };
            }
        }

        Poly {
            coeffs,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
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
        let mut coeffs = self.coeffs.clone();
        for (m, &modulus) in self.moduli.iter().enumerate() {
            let start = m * self.dim;
            let end = start + self.dim;
            for c in &mut coeffs[start..end] {
                *c = if *c == 0 { 0 } else { modulus - *c };
            }
        }

        Poly {
            coeffs,
            moduli: self.moduli.clone(),
            q: self.q,
            dim: self.dim,
            crt_q0_inv_mod_q1: self.crt_q0_inv_mod_q1,
            is_ntt: self.is_ntt,
        }
    }
}

impl Mul for Poly {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        assert_eq!(self.is_ntt, rhs.is_ntt, "NTT domains must match");
        assert!(
            self.is_ntt,
            "Use mul_ntt for coefficient domain multiplication"
        );

        let ctx = NttContext::with_moduli(self.dim, &self.moduli);
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
