//! Collapse procedures for InspiRING
//!
//! Converts aggregated intermediate ciphertexts to standard RLWE ciphertexts
//! using key-switching matrices K_g and K_h.
//!
//! The key insight of InspiRING is that only 2 key-switching matrices are needed
//! (compared to log(d) in prior CDKS approach) by using Galois automorphisms.

use crate::ks::KeySwitchingMatrix;
use crate::math::{NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{gadget_decompose, GadgetVector};
use crate::rlwe::{apply_automorphism, galois_generators, RlweCiphertext};

use super::collapse_one::collapse_one;
use super::types::{AggregatedCiphertext, IntermediateCiphertext};

/// Collapse aggregated intermediate ciphertexts to RLWE
///
/// Uses key-switching matrices K_g and K_h where:
/// - K_g: key-switching for automorphism τ_g (cyclic generator)
/// - K_h: key-switching for automorphism τ_h (conjugation/negation)
///
/// The algorithm recursively halves the dimension using K_g, then
/// applies K_h for the final collapse.
///
/// # Arguments
/// * `aggregated` - The aggregated ciphertext to collapse
/// * `k_g` - Key-switching matrix for generator g
/// * `k_h` - Key-switching matrix for generator h (negation)
/// * `params` - System parameters
pub fn collapse(
    aggregated: &AggregatedCiphertext,
    k_g: &KeySwitchingMatrix,
    k_h: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let ctx = params.ntt_context();

    // Get Galois generators
    let (g, h) = galois_generators(d);

    // Convert to intermediate representation
    let mut current = aggregated.to_intermediate();

    // Number of collapse iterations: log2(d)
    let num_iterations = (d as f64).log2() as usize;

    // Recursively collapse using automorphisms
    // Each iteration halves the effective "dimension" by combining coefficients
    for iter in 0..num_iterations {
        let rho = compute_rotation_param(iter, d);
        current = collapse_iteration(&current, k_g, g, rho, &ctx, params);
    }

    // Final collapse using K_h to get standard RLWE
    let final_ct = final_collapse(&current, k_h, h, &ctx, params);

    final_ct
}

/// CollapseHalf: reduce dimension by half using K_g
///
/// Uses the automorphism τ_g to combine pairs of coefficients.
///
/// # Arguments
/// * `ct` - Intermediate ciphertext
/// * `k_g` - Key-switching matrix for generator g
/// * `rho` - Rotation parameter for this level
/// * `params` - System parameters
pub fn collapse_half(
    ct: &IntermediateCiphertext,
    k_g: &KeySwitchingMatrix,
    rho: usize,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let ctx = params.ntt_context();
    let (g, _) = galois_generators(d);

    let collapsed = collapse_iteration(ct, k_g, g, rho, &ctx, params);

    // Convert final intermediate to RLWE
    if collapsed.a_polys.is_empty() {
        RlweCiphertext::from_parts(Poly::zero_moduli(d, params.moduli()), collapsed.b_poly)
    } else {
        RlweCiphertext::from_parts(collapsed.a_polys[0].clone(), collapsed.b_poly)
    }
}

/// CollapsePartial: for γ ≤ d/2 ciphertexts
///
/// When packing fewer ciphertexts, we can use a simplified collapse
/// that only requires K_g (not K_h).
///
/// # Arguments
/// * `gamma` - Number of ciphertexts being packed
/// * `ct` - Intermediate ciphertext
/// * `k_g` - Key-switching matrix for generator g
/// * `params` - System parameters
pub fn collapse_partial(
    gamma: usize,
    ct: &IntermediateCiphertext,
    k_g: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let ctx = params.ntt_context();

    assert!(gamma <= d / 2, "gamma must be ≤ d/2 for partial collapse");

    // For partial packing, we need log2(gamma) iterations
    let num_iterations = (gamma as f64).log2().ceil() as usize;
    let (g, _) = galois_generators(d);

    let mut current = ct.clone();

    for iter in 0..num_iterations {
        let rho = compute_rotation_param(iter, gamma);
        current = collapse_iteration(&current, k_g, g, rho, &ctx, params);
    }

    // Convert to RLWE
    if current.a_polys.is_empty() {
        RlweCiphertext::from_parts(Poly::zero_moduli(d, params.moduli()), current.b_poly)
    } else {
        // Use key-switching to absorb remaining a components
        // Must track both a and b components from key-switching
        let mut final_a = Poly::zero_moduli(d, params.moduli());
        let mut final_b = current.b_poly.clone();
        for a_poly in &current.a_polys {
            let (ks_a, ks_b) = key_switch_absorb(a_poly, &final_b, k_g, &ctx, params);
            final_a = &final_a + &ks_a;
            final_b = ks_b;
        }
        RlweCiphertext::from_parts(final_a, final_b)
    }
}

/// Single iteration of collapse using automorphism τ_g
fn collapse_iteration(
    ct: &IntermediateCiphertext,
    k_g: &KeySwitchingMatrix,
    g: usize,
    rho: usize,
    ctx: &NttContext,
    params: &InspireParams,
) -> IntermediateCiphertext {
    let q = params.q;

    // Apply automorphism τ_g to get rotated version
    let ct_rotated = apply_automorphism_to_intermediate(ct, g);

    // Multiply rotated version by X^rho (rotation in coefficient space)
    let ct_shifted = shift_intermediate(&ct_rotated, rho, q);

    // Add original and shifted versions
    let ct_combined = add_intermediates(ct, &ct_shifted);

    // Key-switch to absorb the automorphism's effect on the secret key
    key_switch_intermediate(&ct_combined, k_g, ctx, params)
}

/// Final collapse step using K_h
fn final_collapse(
    ct: &IntermediateCiphertext,
    k_h: &KeySwitchingMatrix,
    h: usize,
    ctx: &NttContext,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;

    // Apply automorphism τ_h (conjugation)
    let ct_conj = apply_automorphism_to_intermediate(ct, h);

    // Add original and conjugated
    let ct_combined = add_intermediates(ct, &ct_conj);

    // Key-switch to get valid RLWE ciphertext
    let switched = key_switch_intermediate(&ct_combined, k_h, ctx, params);

    // Convert to RLWE
    if switched.a_polys.is_empty() {
        RlweCiphertext::from_parts(Poly::zero_moduli(d, params.moduli()), switched.b_poly)
    } else {
        // Absorb any remaining a components using proper key-switching
        let mut final_a = switched.a_polys[0].clone();
        let mut final_b = switched.b_poly.clone();

        for a_poly in &switched.a_polys[1..] {
            let (ks_a, ks_b) = key_switch_absorb(a_poly, &final_b, k_h, ctx, params);
            final_a = &final_a + &ks_a;
            final_b = ks_b;
        }

        RlweCiphertext::from_parts(final_a, final_b)
    }
}

/// Apply automorphism to all components of intermediate ciphertext
fn apply_automorphism_to_intermediate(
    ct: &IntermediateCiphertext,
    g: usize,
) -> IntermediateCiphertext {
    let a_polys: Vec<Poly> = ct
        .a_polys
        .iter()
        .map(|p| apply_automorphism(p, g))
        .collect();
    let b_poly = apply_automorphism(&ct.b_poly, g);

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Shift (multiply by X^k) all components of intermediate ciphertext
fn shift_intermediate(ct: &IntermediateCiphertext, k: usize, q: u64) -> IntermediateCiphertext {
    let a_polys: Vec<Poly> = ct
        .a_polys
        .iter()
        .map(|p| mul_by_monomial(p, k, q))
        .collect();
    let b_poly = mul_by_monomial(&ct.b_poly, k, q);

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Multiply polynomial by X^k in negacyclic ring
fn mul_by_monomial(poly: &Poly, k: usize, q: u64) -> Poly {
    let d = poly.dimension();
    let k = k % (2 * d);

    if k == 0 {
        return poly.clone();
    }

    let mut result_coeffs = vec![0u64; d];

    for i in 0..d {
        let coeff = poly.coeff(i);
        if coeff == 0 {
            continue;
        }

        let new_idx = i + k;
        if new_idx < d {
            result_coeffs[new_idx] = mod_add(result_coeffs[new_idx], coeff, q);
        } else if new_idx < 2 * d {
            let actual_idx = new_idx - d;
            let neg_coeff = mod_sub(0, coeff, q);
            result_coeffs[actual_idx] = mod_add(result_coeffs[actual_idx], neg_coeff, q);
        } else {
            let actual_idx = new_idx - 2 * d;
            result_coeffs[actual_idx] = mod_add(result_coeffs[actual_idx], coeff, q);
        }
    }

    Poly::from_coeffs_moduli(result_coeffs, poly.moduli())
}

/// Add two intermediate ciphertexts
fn add_intermediates(
    ct1: &IntermediateCiphertext,
    ct2: &IntermediateCiphertext,
) -> IntermediateCiphertext {
    assert_eq!(ct1.dimension(), ct2.dimension());

    let a_polys: Vec<Poly> = ct1
        .a_polys
        .iter()
        .zip(ct2.a_polys.iter())
        .map(|(p1, p2)| p1 + p2)
        .collect();
    let b_poly = &ct1.b_poly + &ct2.b_poly;

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Key-switch an intermediate ciphertext
fn key_switch_intermediate(
    ct: &IntermediateCiphertext,
    ks_matrix: &KeySwitchingMatrix,
    _ctx: &NttContext,
    params: &InspireParams,
) -> IntermediateCiphertext {
    if ct.a_polys.is_empty() {
        return ct.clone();
    }

    // Collapse the last a component using key-switching
    let (new_a, new_b) = collapse_one(&ct.a_polys, &ct.b_poly, ks_matrix, params);

    IntermediateCiphertext::new(new_a, new_b)
}

/// Key-switch to absorb an a component
///
/// Returns (new_a, new_b) where the key-switching result is properly computed
/// using BOTH ks_row.a and ks_row.b
fn key_switch_absorb(
    a_component: &Poly,
    b: &Poly,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
    params: &InspireParams,
) -> (Poly, Poly) {
    let d = params.ring_dim;
    let q = params.q;
    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
    let decomposed = gadget_decompose(a_component, &gadget);

    // Initialize: (a', b') = (0, b)
    let mut result_a = Poly::zero_moduli(d, params.moduli());
    let mut result_b = b.clone();

    // Accumulate: Σᵢ decomposed_i · K[i]
    for (i, digit_poly) in decomposed.iter().enumerate() {
        if i < ks_matrix.len() {
            let ks_row = ks_matrix.get_row(i);

            // digit_poly · K[i].a
            let term_a = digit_poly.mul_ntt(&ks_row.a, ctx);
            result_a = &result_a + &term_a;

            // digit_poly · K[i].b
            let term_b = digit_poly.mul_ntt(&ks_row.b, ctx);
            result_b = &result_b + &term_b;
        }
    }

    (result_a, result_b)
}

/// Compute the rotation parameter for a given iteration
fn compute_rotation_param(iteration: usize, d: usize) -> usize {
    // For iteration i, rotation is d / 2^(i+1)
    d >> (iteration + 1)
}

#[inline]
fn mod_add(a: u64, b: u64, q: u64) -> u64 {
    let sum = a as u128 + b as u128;
    (sum % q as u128) as u64
}

#[inline]
fn mod_sub(a: u64, b: u64, q: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        q - b + a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn random_poly<R: Rng>(rng: &mut R, d: usize, q: u64, moduli: &[u64]) -> Poly {
        let coeffs: Vec<u64> = (0..d).map(|_| rng.gen_range(0..q)).collect();
        Poly::from_coeffs_moduli(coeffs, moduli)
    }

    #[test]
    fn test_mul_by_monomial_identity() {
        let d = 256;
        let q = 1152921504606830593u64;
        let moduli = vec![q];
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
        let poly = random_poly(&mut rng, d, q, &moduli);

        let result = mul_by_monomial(&poly, 0, q);

        for i in 0..d {
            assert_eq!(result.coeff(i), poly.coeff(i));
        }
    }

    #[test]
    fn test_mul_by_monomial_single_shift() {
        let d = 256;
        let q = 1152921504606830593u64;
        let mut coeffs = vec![0u64; d];
        coeffs[0] = 1;
        let poly = Poly::from_coeffs_moduli(coeffs, &[q]);

        let result = mul_by_monomial(&poly, 1, q);

        assert_eq!(result.coeff(1), 1);
        assert_eq!(result.coeff(0), 0);
    }

    #[test]
    fn test_mul_by_monomial_wraparound() {
        let d = 256;
        let q = 1152921504606830593u64;
        let mut coeffs = vec![0u64; d];
        coeffs[d - 1] = 1;
        let poly = Poly::from_coeffs_moduli(coeffs, &[q]);

        // X^(d-1) * X = X^d = -1
        let result = mul_by_monomial(&poly, 1, q);

        assert_eq!(result.coeff(0), q - 1); // -1 mod q
    }

    #[test]
    fn test_add_intermediates() {
        let params = test_params();
        let moduli = params.moduli();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(54321);

        let a1 = vec![random_poly(&mut rng, params.ring_dim, params.q, moduli)];
        let b1 = random_poly(&mut rng, params.ring_dim, params.q, moduli);
        let ct1 = IntermediateCiphertext::new(a1.clone(), b1.clone());

        let a2 = vec![random_poly(&mut rng, params.ring_dim, params.q, moduli)];
        let b2 = random_poly(&mut rng, params.ring_dim, params.q, moduli);
        let ct2 = IntermediateCiphertext::new(a2.clone(), b2.clone());

        let sum = add_intermediates(&ct1, &ct2);

        assert_eq!(sum.dimension(), 1);
        for i in 0..params.ring_dim {
            let expected_a = (a1[0].coeff(i) as u128 + a2[0].coeff(i) as u128) % params.q as u128;
            assert_eq!(sum.a_polys[0].coeff(i), expected_a as u64);

            let expected_b = (b1.coeff(i) as u128 + b2.coeff(i) as u128) % params.q as u128;
            assert_eq!(sum.b_poly.coeff(i), expected_b as u64);
        }
    }

    #[test]
    fn test_compute_rotation_param() {
        let d = 2048;

        assert_eq!(compute_rotation_param(0, d), 1024); // d/2
        assert_eq!(compute_rotation_param(1, d), 512); // d/4
        assert_eq!(compute_rotation_param(2, d), 256); // d/8
        assert_eq!(compute_rotation_param(10, d), 1); // d/2048
    }

    #[test]
    fn test_apply_automorphism_to_intermediate() {
        let params = test_params();
        let (g, _) = galois_generators(params.ring_dim);
        let moduli = params.moduli();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99999);
        let a = vec![random_poly(&mut rng, params.ring_dim, params.q, moduli)];
        let b = random_poly(&mut rng, params.ring_dim, params.q, moduli);
        let ct = IntermediateCiphertext::new(a.clone(), b.clone());

        let rotated = apply_automorphism_to_intermediate(&ct, g);

        // Verify the automorphism was applied
        let expected_a = apply_automorphism(&a[0], g);
        let expected_b = apply_automorphism(&b, g);

        for i in 0..params.ring_dim {
            assert_eq!(rotated.a_polys[0].coeff(i), expected_a.coeff(i));
            assert_eq!(rotated.b_poly.coeff(i), expected_b.coeff(i));
        }
    }

    #[test]
    fn test_collapse_partial_dimensions() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11111);
        let moduli = params.moduli();

        let gamma = 4;
        let a_polys: Vec<Poly> = (0..gamma)
            .map(|_| random_poly(&mut rng, params.ring_dim, params.q, moduli))
            .collect();
        let b_poly = random_poly(&mut rng, params.ring_dim, params.q, moduli);
        let ct = IntermediateCiphertext::new(a_polys, b_poly);

        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.moduli(), params.gadget_len);

        let result = collapse_partial(gamma, &ct, &k_g, &params);

        assert_eq!(result.ring_dim(), params.ring_dim);
    }
}
