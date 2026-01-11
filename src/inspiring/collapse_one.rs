//! CollapseOne procedure for InspiRING
//!
//! Reduces the dimension of an intermediate ciphertext by 1 using key-switching.
//! This is the core building block for the Collapse procedure.

use crate::ks::KeySwitchingMatrix;
use crate::math::{NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::gadget_decompose as rgsw_gadget_decompose;
use crate::rgsw::GadgetVector;

/// CollapseOne: reduce dimension by 1 using key-switching
///
/// Input: (a, b) with a ∈ R_q^k where a = (a_0, ..., a_{k-1})
/// Output: (a', b') with a' ∈ R_q^{k-1}
///
/// The key-switching matrix K_s allows us to "absorb" one component of a
/// into b while maintaining the encryption relationship.
///
/// The correct key-switching algorithm (from ks/switch.rs):
/// 1. Decompose a_{k-1} using gadget: g⁻¹(a) = [a₀, a₁, ..., a_{ℓ-1}]
/// 2. Compute: (a', b') = (0, b) + Σᵢ aᵢ · K[i]
///    - MUST use BOTH ks_row.a and ks_row.b for each row
///
/// # Arguments
/// * `a` - Vector of k polynomials
/// * `b` - Single polynomial
/// * `ks_matrix` - Key-switching matrix for the k-th component
/// * `params` - System parameters
///
/// # Returns
/// Tuple of (a', b') where a' has k-1 polynomials
pub fn collapse_one(
    a: &[Poly],
    b: &Poly,
    ks_matrix: &KeySwitchingMatrix,
    params: &InspireParams,
) -> (Vec<Poly>, Poly) {
    let k = a.len();
    assert!(k >= 1, "Must have at least one polynomial to collapse");

    let d = params.ring_dim;
    let q = params.q;
    let ctx = params.ntt_context();
    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

    if k == 1 {
        // Base case: collapsing from 1 to 0 means fully absorbing into b
        let (result_a, new_b) = key_switch_component(&a[0], b, ks_matrix, &ctx, &gadget);
        // Consistency: only include result_a if non-zero (matches k > 1 case)
        if result_a.is_zero() {
            return (vec![], new_b);
        }
        return (vec![result_a], new_b);
    }

    // Key-switch the last component a_{k-1}
    let a_last = &a[k - 1];

    // Gadget decomposition of a_last
    let decomposed = rgsw_gadget_decompose(a_last, &gadget);

    // Apply key-switching using BOTH ks_row.a and ks_row.b
    // This is the correct algorithm from ks/switch.rs:
    //   (a', b') = (0, b) + Σᵢ decomposed_i · K[i]
    // where K[i] = (ks_row.a, ks_row.b)
    let mut result_a = Poly::zero_moduli(d, params.moduli());
    let mut result_b = b.clone();

    for (i, digit_poly) in decomposed.iter().enumerate() {
        if i < ks_matrix.len() {
            let ks_row = ks_matrix.get_row(i);

            // digit_poly · K[i].a
            let term_a = digit_poly.mul_ntt(&ks_row.a, &ctx);
            result_a = &result_a + &term_a;

            // digit_poly · K[i].b
            let term_b = digit_poly.mul_ntt(&ks_row.b, &ctx);
            result_b = &result_b + &term_b;
        }
    }

    // The remaining a components stay, plus the new key-switched a component
    let mut new_a: Vec<Poly> = a[..k - 1].to_vec();
    // Add the result_a from key-switching (this replaces the absorbed component)
    if !result_a.is_zero() {
        // If we already have a[0], add result_a to it
        if !new_a.is_empty() {
            new_a[0] = &new_a[0] + &result_a;
        } else {
            new_a.push(result_a);
        }
    }

    (new_a, result_b)
}

/// Apply key-switching to fully absorb a single a component
///
/// Returns (new_a, new_b) where the key-switching result is properly computed
/// using BOTH ks_row.a and ks_row.b
fn key_switch_component(
    a_component: &Poly,
    b: &Poly,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
    gadget: &GadgetVector,
) -> (Poly, Poly) {
    let d = a_component.dimension();

    let decomposed = rgsw_gadget_decompose(a_component, gadget);

    // Initialize: (a', b') = (0, b)
    let mut result_a = Poly::zero_moduli(d, a_component.moduli());
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

/// Gadget decomposition of a polynomial
///
/// Decomposes each coefficient into base-z digits:
/// a = sum_{i=0}^{l-1} a_i * z^i
///
/// Returns l polynomials where the i-th polynomial contains the i-th digit
/// of each coefficient.
#[allow(dead_code)]
pub fn gadget_decompose(poly: &Poly, params: &InspireParams) -> Vec<Poly> {
    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
    rgsw_gadget_decompose(poly, &gadget)
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
    fn test_gadget_decompose() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
        let poly = random_poly(&mut rng, params.ring_dim, params.q, params.moduli());

        let decomposed = gadget_decompose(&poly, &params);
        assert_eq!(decomposed.len(), params.gadget_len);

        // Verify decomposition produces valid output
        for digit_poly in &decomposed {
            assert_eq!(digit_poly.dimension(), params.ring_dim);
        }
    }

    #[test]
    fn test_collapse_one_reduces_dimension() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11111);
        let moduli = params.moduli();

        let k = 4;
        let a: Vec<Poly> = (0..k)
            .map(|_| random_poly(&mut rng, params.ring_dim, params.q, moduli))
            .collect();
        let b = random_poly(&mut rng, params.ring_dim, params.q, moduli);

        // Create a dummy key-switching matrix
        let ks_matrix = KeySwitchingMatrix::dummy(params.ring_dim, params.moduli(), params.gadget_len);

        let (new_a, _new_b) = collapse_one(&a, &b, &ks_matrix, &params);

        assert_eq!(new_a.len(), k - 1);
    }
}
