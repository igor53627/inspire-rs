//! Homomorphic polynomial evaluation (legacy module)
//!
//! This module contains polynomial evaluation functions using Horner's method.
//! These are currently NOT USED by the main PIR flow, which uses direct
//! coefficient encoding with monomial rotation instead.
//!
//! The functions are kept for potential future use or alternative schemes
//! that may require polynomial evaluation.

use crate::math::{NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{external_product, GadgetVector, RgswCiphertext};
use crate::rlwe::RlweCiphertext;

/// Homomorphic polynomial evaluation using Horner's method
///
/// Evaluates h(Z) at encrypted point Z using RLWE-RGSW external products.
///
/// h(Z) = h_0 + h_1·Z + h_2·Z² + ... = h_0 + Z·(h_1 + Z·(h_2 + ...))
///
/// Each step computes: RLWE(acc) ⊡ RGSW(Z) + RLWE(h_i)
///
/// # Arguments
/// * `poly_coeffs` - Plaintext polynomial h(Z) with coefficients [h_0, h_1, ..., h_{n-1}]
/// * `encrypted_point` - RGSW encryption of the evaluation point Z
/// * `params` - System parameters
///
/// # Returns
/// RLWE ciphertext encrypting h(Z)
#[allow(dead_code)]
pub fn eval_poly_homomorphic(
    poly_coeffs: &Poly,
    encrypted_point: &RgswCiphertext,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    let degree = find_degree(poly_coeffs);

    if degree == 0 {
        let const_coeff = poly_coeffs.coeff(0);
        return encrypt_constant(const_coeff, params);
    }

    let delta = params.delta();
    let mut acc = encrypt_scaled_constant(poly_coeffs.coeff(degree), delta, params);

    for i in (0..degree).rev() {
        let product = external_product(&acc, encrypted_point, &ctx);

        let h_i = poly_coeffs.coeff(i);
        let h_i_scaled = encrypt_scaled_constant(h_i, delta, params);

        acc = product.add(&h_i_scaled);
    }

    acc
}

/// Evaluate polynomial homomorphically with precomputed NTT context
///
/// Same as eval_poly_homomorphic but reuses an existing NTT context.
#[allow(dead_code)]
pub fn eval_poly_homomorphic_with_ctx(
    poly_coeffs: &Poly,
    encrypted_point: &RgswCiphertext,
    params: &InspireParams,
    ctx: &NttContext,
) -> RlweCiphertext {
    let degree = find_degree(poly_coeffs);

    if degree == 0 {
        let const_coeff = poly_coeffs.coeff(0);
        return encrypt_constant(const_coeff, params);
    }

    let delta = params.delta();
    let mut acc = encrypt_scaled_constant(poly_coeffs.coeff(degree), delta, params);

    for i in (0..degree).rev() {
        let product = external_product(&acc, encrypted_point, ctx);

        let h_i = poly_coeffs.coeff(i);
        let h_i_scaled = encrypt_scaled_constant(h_i, delta, params);

        acc = product.add(&h_i_scaled);
    }

    acc
}

/// Find the degree of a polynomial (index of highest non-zero coefficient)
fn find_degree(poly: &Poly) -> usize {
    for i in (0..poly.len()).rev() {
        if poly.coeff(i) != 0 {
            return i;
        }
    }
    0
}

/// Create RLWE ciphertext encrypting a constant (as noiseless trivial encryption)
fn encrypt_constant(value: u64, params: &InspireParams) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();

    let a = Poly::zero(d, q);
    let mut b_coeffs = vec![0u64; d];
    b_coeffs[0] = ((value as u128 * delta as u128) % q as u128) as u64;
    let b = Poly::from_coeffs(b_coeffs, q);

    RlweCiphertext::from_parts(a, b)
}

/// Create RLWE ciphertext with pre-scaled constant (trivial encryption)
fn encrypt_scaled_constant(value: u64, delta: u64, params: &InspireParams) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;

    let a = Poly::zero(d, q);
    let mut b_coeffs = vec![0u64; d];
    b_coeffs[0] = ((value as u128 * delta as u128) % q as u128) as u64;
    let b = Poly::from_coeffs(b_coeffs, q);

    RlweCiphertext::from_parts(a, b)
}

/// Generate scalar evaluation points for polynomial evaluation
///
/// Returns the t-th roots of unity ω^k ∈ Z_q as scalar values.
/// These match the roots used by `interpolate()` in encode_db.rs.
///
/// The root ω is found as the smallest generator g^((q-1)/t) that is
/// a primitive t-th root of unity.
///
/// # Arguments
/// * `t` - Number of evaluation points (must divide q-1)
/// * `q` - Modulus
///
/// # Returns
/// Vector of scalar roots of unity [1, ω, ω², ..., ω^(t-1)]
#[allow(dead_code)]
pub fn generate_scalar_eval_points(t: usize, q: u64) -> Vec<u64> {
    if t == 0 {
        return vec![];
    }

    // Find primitive t-th root of unity (same algorithm as in encode_db.rs)
    let omega = find_primitive_root(t, q);

    let mut points = Vec::with_capacity(t);
    let mut current = 1u64;
    for _ in 0..t {
        points.push(current);
        current = ((current as u128 * omega as u128) % q as u128) as u64;
    }
    points
}

/// Create polynomial for scalar evaluation point z = ω^k (constant polynomial)
#[allow(dead_code)]
pub fn scalar_eval_point_to_poly(value: u64, d: usize, q: u64) -> Poly {
    let mut coeffs = vec![0u64; d];
    coeffs[0] = value; // Constant polynomial
    Poly::from_coeffs(coeffs, q)
}

/// Encrypt a scalar evaluation point as RGSW ciphertext
#[allow(dead_code)]
pub fn encrypt_scalar_eval_point(
    value: u64, // The scalar ω^k
    sk: &crate::rlwe::RlweSecretKey,
    gadget: &GadgetVector,
    sampler: &mut crate::math::GaussianSampler,
    ctx: &NttContext,
) -> RgswCiphertext {
    let d = sk.ring_dim();
    let q = sk.modulus();

    let point_poly = scalar_eval_point_to_poly(value, d, q);
    RgswCiphertext::encrypt(sk, &point_poly, gadget, sampler, ctx)
}

/// Find primitive n-th root of unity modulo q
fn find_primitive_root(n: usize, q: u64) -> u64 {
    // Edge case: 1-st root is always 1
    if n == 1 {
        return 1;
    }

    assert!(
        (q - 1) % n as u64 == 0,
        "No {}-th root of unity exists mod {}",
        n,
        q
    );

    let exp = (q - 1) / n as u64;

    // For prime q, small generators usually work
    // Try first 1000 candidates (sufficient for cryptographic primes)
    for candidate in 2..1000.min(q) {
        let root = mod_pow(candidate, exp, q);
        if is_primitive_root(root, n, q) {
            return root;
        }
    }
    panic!("No primitive root found in first 1000 candidates");
}

fn is_primitive_root(g: u64, n: usize, q: u64) -> bool {
    if g == 0 || g == 1 {
        return false;
    }
    if mod_pow(g, n as u64, q) != 1 {
        return false;
    }
    if n > 1 && mod_pow(g, (n / 2) as u64, q) == 1 {
        return false;
    }
    true
}

fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut base = base as u128;
    let mut exp = exp;
    let m = modulus as u128;

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    result as u64
}

/// Generate evaluation points (unit monomials ±X^k)
///
/// z_k = ω^k where ω = X^(2d/t) is a primitive t-th root of unity in R_q.
///
/// For the ring R_q = Z_q[X]/(X^d + 1):
/// - X^d = -1, so X^(2d) = 1
/// - Thus X^(2d/t) is a primitive t-th root of unity when t | 2d
///
/// # Arguments
/// * `t` - Number of evaluation points (must divide 2d)
/// * `d` - Ring dimension
///
/// # Returns
/// Vector of pairs (coefficient_index, sign) representing z_k = ±X^index
#[deprecated(note = "Use generate_scalar_eval_points for correct NTT domain alignment")]
#[allow(dead_code)]
pub fn generate_monomial_eval_points(t: usize, d: usize) -> Vec<(usize, bool)> {
    if t == 0 {
        return vec![];
    }

    assert!(
        (2 * d) % t == 0,
        "t must divide 2d for roots of unity to exist"
    );

    let step = (2 * d) / t;
    let mut points = Vec::with_capacity(t);

    for k in 0..t {
        let power = (k * step) % (2 * d);

        if power < d {
            points.push((power, false));
        } else {
            points.push((power - d, true));
        }
    }

    points
}

/// Deprecated: Use generate_scalar_eval_points instead
#[deprecated(note = "Use generate_scalar_eval_points for correct NTT domain alignment")]
#[allow(deprecated)]
#[allow(dead_code)]
pub fn generate_eval_points(t: usize, d: usize) -> Vec<(usize, bool)> {
    generate_monomial_eval_points(t, d)
}

/// Create polynomial for evaluation point z_k = ±X^index
///
/// # Arguments
/// * `index` - Exponent in X^index
/// * `negate` - If true, returns -X^index
/// * `d` - Ring dimension
/// * `q` - Modulus
#[deprecated(note = "Use scalar_eval_point_to_poly for correct NTT domain alignment")]
#[allow(dead_code)]
pub fn eval_point_to_poly(index: usize, negate: bool, d: usize, q: u64) -> Poly {
    let mut coeffs = vec![0u64; d];

    if negate {
        coeffs[index] = q - 1;
    } else {
        coeffs[index] = 1;
    }

    Poly::from_coeffs(coeffs, q)
}

/// Encrypt an evaluation point as RGSW ciphertext
///
/// This is used in the query phase to encrypt z_k = ±X^index.
#[deprecated(note = "Use encrypt_scalar_eval_point for correct NTT domain alignment")]
#[allow(deprecated)]
#[allow(dead_code)]
pub fn encrypt_eval_point(
    index: usize,
    negate: bool,
    sk: &crate::rlwe::RlweSecretKey,
    gadget: &crate::rgsw::GadgetVector,
    sampler: &mut crate::math::GaussianSampler,
    ctx: &NttContext,
) -> RgswCiphertext {
    let d = sk.ring_dim();
    let q = sk.modulus();

    let point_poly = eval_point_to_poly(index, negate, d, q);
    RgswCiphertext::encrypt(sk, &point_poly, gadget, sampler, ctx)
}

/// Homomorphic polynomial selection using binary expansion
///
/// Given polynomials [h_0, h_1, ..., h_{t-1}] and encrypted index bits,
/// selects h_idx homomorphically.
///
/// Uses tree-based selection: at each level, use external product to
/// select between pairs based on a bit.
#[allow(dead_code)]
pub fn homomorphic_select(
    polynomials: &[Poly],
    index_bits: &[RgswCiphertext],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let delta = params.delta();
    let ctx = NttContext::new(d, q);

    if polynomials.is_empty() {
        return RlweCiphertext::zero(params);
    }

    if polynomials.len() == 1 {
        return poly_to_rlwe(&polynomials[0], delta, params);
    }

    let mut current: Vec<RlweCiphertext> = polynomials
        .iter()
        .map(|p| poly_to_rlwe(p, delta, params))
        .collect();

    for bit_ct in index_bits.iter() {
        if current.len() == 1 {
            break;
        }

        let mut next = Vec::with_capacity((current.len() + 1) / 2);

        for pair in current.chunks(2) {
            if pair.len() == 2 {
                let diff = pair[1].sub(&pair[0]);
                let selected = external_product(&diff, bit_ct, &ctx);
                let result = pair[0].add(&selected);
                next.push(result);
            } else {
                next.push(pair[0].clone());
            }
        }

        current = next;
    }

    current
        .into_iter()
        .next()
        .unwrap_or_else(|| RlweCiphertext::zero(params))
}

/// Convert plaintext polynomial to trivial RLWE encryption
#[allow(dead_code)]
fn poly_to_rlwe(poly: &Poly, delta: u64, params: &InspireParams) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;

    let a = Poly::zero(d, q);
    let b = poly.scalar_mul(delta);

    RlweCiphertext::from_parts(a, b)
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::rgsw::GadgetVector;
    use crate::rlwe::RlweSecretKey;

    fn test_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    #[test]
    fn test_generate_scalar_eval_points_count() {
        let q = 1152921504606830593u64;

        for t in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
            let points = generate_scalar_eval_points(t, q);
            assert_eq!(points.len(), t, "Wrong number of eval points for t={}", t);
        }
    }

    #[test]
    fn test_generate_scalar_eval_points_first_is_one() {
        let q = 1152921504606830593u64;
        let t = 16;

        let points = generate_scalar_eval_points(t, q);

        assert_eq!(points[0], 1, "First eval point should be ω^0 = 1");
    }

    #[test]
    fn test_generate_scalar_eval_points_are_roots() {
        let q = 1152921504606830593u64;
        let t = 16;

        let points = generate_scalar_eval_points(t, q);

        for (k, &omega_k) in points.iter().enumerate() {
            let omega_k_to_t = mod_pow(omega_k, t as u64, q);
            assert_eq!(omega_k_to_t, 1, "ω^{} raised to t={} should be 1", k, t);
        }
    }

    #[test]
    fn test_scalar_eval_point_to_poly() {
        let d = 256;
        let q = 1152921504606830593u64;
        let value = 42u64;

        let poly = scalar_eval_point_to_poly(value, d, q);

        assert_eq!(poly.coeff(0), value);
        for i in 1..d {
            assert_eq!(poly.coeff(i), 0);
        }
    }

    #[test]
    fn test_generate_eval_points_count() {
        let d = 256;

        for t in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
            let points = generate_eval_points(t, d);
            assert_eq!(points.len(), t, "Wrong number of eval points for t={}", t);
        }
    }

    #[test]
    fn test_generate_eval_points_first_is_one() {
        let d = 256;
        let t = 16;

        let points = generate_eval_points(t, d);

        assert_eq!(points[0], (0, false), "First eval point should be X^0 = 1");
    }

    #[test]
    fn test_eval_point_to_poly_positive() {
        let d = 256;
        let q = 1152921504606830593u64;

        let poly = eval_point_to_poly(5, false, d, q);

        assert_eq!(poly.coeff(5), 1);
        for i in 0..d {
            if i != 5 {
                assert_eq!(poly.coeff(i), 0);
            }
        }
    }

    #[test]
    fn test_eval_point_to_poly_negative() {
        let d = 256;
        let q = 1152921504606830593u64;

        let poly = eval_point_to_poly(3, true, d, q);

        assert_eq!(poly.coeff(3), q - 1);
        for i in 0..d {
            if i != 3 {
                assert_eq!(poly.coeff(i), 0);
            }
        }
    }

    #[test]
    fn test_find_degree() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;

        let mut coeffs = vec![0u64; d];
        coeffs[0] = 1;
        coeffs[5] = 2;
        coeffs[10] = 3;
        let poly = Poly::from_coeffs(coeffs, q);

        assert_eq!(find_degree(&poly), 10);
    }

    #[test]
    fn test_find_degree_constant() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;

        let mut coeffs = vec![0u64; d];
        coeffs[0] = 42;
        let poly = Poly::from_coeffs(coeffs, q);

        assert_eq!(find_degree(&poly), 0);
    }

    #[test]
    fn test_find_degree_zero() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;

        let poly = Poly::zero(d, q);

        assert_eq!(find_degree(&poly), 0);
    }

    #[test]
    fn test_encrypt_constant_decrypts_correctly() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        let ctx = NttContext::new(params.ring_dim, params.q);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let value = 42u64;
        let delta = params.delta();

        let ct = encrypt_constant(value, &params);
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        assert_eq!(decrypted.coeff(0), value);
    }

    #[test]
    fn test_eval_poly_homomorphic_constant() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let mut sampler = GaussianSampler::new(params.sigma);
        let ctx = NttContext::new(d, q);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

        let mut coeffs = vec![0u64; d];
        coeffs[0] = 100;
        let poly = Poly::from_coeffs(coeffs, q);

        let point_poly = eval_point_to_poly(0, false, d, q);
        let encrypted_point =
            RgswCiphertext::encrypt(&sk, &point_poly, &gadget, &mut sampler, &ctx);

        let result = eval_poly_homomorphic(&poly, &encrypted_point, &params);
        let decrypted = result.decrypt(&sk, params.delta(), params.p, &ctx);

        assert_eq!(decrypted.coeff(0), 100);
    }

    #[test]
    fn test_homomorphic_select_single() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;

        let mut coeffs = vec![0u64; d];
        coeffs[0] = 42;
        let poly = Poly::from_coeffs(coeffs, q);

        let result = homomorphic_select(&[poly], &[], &params);

        assert_eq!(result.ring_dim(), d);
    }

    #[test]
    fn test_homomorphic_select_empty() {
        let params = test_params();
        let d = params.ring_dim;

        let result = homomorphic_select(&[], &[], &params);

        assert_eq!(result.ring_dim(), d);
        assert!(result.a.is_zero());
        assert!(result.b.is_zero());
    }
}
