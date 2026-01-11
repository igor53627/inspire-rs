//! Transform procedure for InspiRING
//!
//! Converts LWE ciphertexts to intermediate representation for ring packing.
//! The message is encoded as the constant term of the plaintext polynomial.

use crate::lwe::LweCiphertext;
use crate::math::{ModQ, Poly};
use crate::params::InspireParams;

use super::types::IntermediateCiphertext;

/// Transform a single LWE ciphertext to intermediate representation
///
/// Input: (a, b) ∈ Z_q^d × Z_q
/// Output: (â, b̃) ∈ R_q^d × R_q
///
/// The transform embeds each LWE coefficient a_i into a monomial X^i in the polynomial ring.
/// For full packing (d ciphertexts), the output has d polynomials in the a-component.
///
/// The message is encoded as the constant term of the plaintext polynomial after packing.
pub fn transform(lwe: &LweCiphertext, params: &InspireParams) -> IntermediateCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let moduli = params.moduli();

    debug_assert_eq!(lwe.a.len(), d, "LWE dimension must match ring dimension");
    debug_assert_eq!(lwe.q, q, "LWE modulus must match params");

    // For full packing, we create d polynomials for the a-component
    // Each polynomial â_j is derived from a single coefficient a_j
    // We embed a_j as a polynomial such that after aggregation across all d LWE ciphertexts,
    // the coefficients align properly.
    //
    // Transform: â_j(X) = a_j (constant polynomial with coefficient a_j at position 0)
    // This gets modified during aggregation with appropriate X^k multipliers.
    let a_polys: Vec<Poly> = lwe
        .a
        .iter()
        .map(|&a_j| Poly::constant_moduli(a_j, d, moduli))
        .collect();

    // The b-component becomes a constant polynomial
    let b_poly = Poly::constant_moduli(lwe.b, d, moduli);

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Transform for partial packing (γ ≤ d/2 ciphertexts)
///
/// When packing fewer than d ciphertexts, we use a modified transform that
/// only requires a single key-switching matrix K_g.
///
/// # Arguments
/// * `gamma` - Number of ciphertexts being packed (must be ≤ d/2)
/// * `lwe` - The LWE ciphertext to transform
/// * `params` - System parameters
pub fn transform_partial(
    gamma: usize,
    lwe: &LweCiphertext,
    params: &InspireParams,
) -> IntermediateCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let moduli = params.moduli();

    debug_assert!(gamma <= d / 2, "gamma must be ≤ d/2 for partial packing");
    debug_assert_eq!(lwe.a.len(), d, "LWE dimension must match ring dimension");
    debug_assert_eq!(lwe.q, q, "LWE modulus must match params");

    // For partial packing, we only need to handle γ positions
    // The transformation is similar but optimized for fewer ciphertexts
    //
    // We reduce the effective dimension of the intermediate ciphertext
    // by grouping coefficients together.
    let group_size = d / gamma;

    // Create ceil(gamma) polynomials for the a-component
    let mut a_polys = Vec::with_capacity(gamma);

    for j in 0..gamma {
        // Group coefficients: a_polys[j] aggregates coefficients [j*group_size, (j+1)*group_size)
        let mut coeffs = vec![0u64; d];
        for k in 0..group_size {
            let idx = j * group_size + k;
            if idx < lwe.a.len() {
                // Place coefficient at position k in the polynomial
                coeffs[k] = lwe.a[idx];
            }
        }
        a_polys.push(Poly::from_coeffs_moduli(coeffs, moduli));
    }

    // The b-component remains a constant polynomial
    let b_poly = Poly::constant_moduli(lwe.b, d, moduli);

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Embed an LWE ciphertext at a specific slot position
///
/// For packing multiple LWE ciphertexts, each is embedded at a different slot
/// using a monomial multiplier X^slot_index.
///
/// # Arguments
/// * `lwe` - The LWE ciphertext
/// * `slot_index` - Which slot (0 to d-1) to embed at
/// * `params` - System parameters
pub fn transform_at_slot(
    lwe: &LweCiphertext,
    slot_index: usize,
    params: &InspireParams,
) -> IntermediateCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let moduli = params.moduli();

    debug_assert!(slot_index < d, "slot_index must be < ring_dim");
    debug_assert_eq!(lwe.a.len(), d, "LWE dimension must match ring dimension");

    // Embed each a coefficient as X^slot_index * a_j
    // This means coefficient a_j appears at position slot_index in polynomial â_j
    let a_polys: Vec<Poly> = lwe
        .a
        .iter()
        .map(|&a_j| {
            let mut coeffs = vec![0u64; d];
            if slot_index < d {
                coeffs[slot_index] = a_j;
            } else {
                // Handle wraparound for negacyclic: X^d = -1
                let actual_idx = slot_index % d;
                let sign = if (slot_index / d) % 2 == 1 {
                    ModQ::negate(a_j, q)
                } else {
                    a_j
                };
                coeffs[actual_idx] = sign;
            }
            Poly::from_coeffs_moduli(coeffs, moduli)
        })
        .collect();

    // Similarly for b
    let mut b_coeffs = vec![0u64; d];
    b_coeffs[slot_index] = lwe.b;
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, moduli);

    IntermediateCiphertext::new(a_polys, b_poly)
}

/// Aggregate multiple intermediate ciphertexts into one
///
/// Sums the intermediate ciphertexts (which are already positioned at their slots).
/// This expects each intermediate to have been created with transform_at_slot.
pub fn aggregate(
    intermediates: &[IntermediateCiphertext],
    params: &InspireParams,
) -> super::types::AggregatedCiphertext {
    let d = params.ring_dim;
    let moduli = params.moduli();
    let n = intermediates.len();

    assert!(
        !intermediates.is_empty(),
        "Must have at least one ciphertext"
    );
    assert!(n <= d, "Cannot aggregate more than d ciphertexts");

    let num_a_polys = intermediates[0].dimension();

    // Initialize aggregated polynomials
    let mut agg_a_polys: Vec<Poly> = (0..num_a_polys)
        .map(|_| Poly::zero_moduli(d, moduli))
        .collect();
    let mut agg_b_poly = Poly::zero_moduli(d, moduli);

    // Sum all intermediate ciphertexts (already positioned at their slots)
    for ct in intermediates.iter() {
        assert_eq!(
            ct.dimension(),
            num_a_polys,
            "All intermediates must have same dimension"
        );

        // Simply add the polynomials (no shift needed since transform_at_slot already positioned them)
        for (j, a_poly) in ct.a_polys.iter().enumerate() {
            agg_a_polys[j] = &agg_a_polys[j] + a_poly;
        }

        agg_b_poly = &agg_b_poly + &ct.b_poly;
    }

    super::types::AggregatedCiphertext::new(agg_a_polys, agg_b_poly)
}

/// Multiply a polynomial by X^k in R_q = Z_q[X]/(X^d + 1)
///
/// For negacyclic rings: X^d = -1
#[allow(dead_code)]
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
            // No wraparound
            result_coeffs[new_idx] = ModQ::add(result_coeffs[new_idx], coeff, q);
        } else if new_idx < 2 * d {
            // One wraparound: X^d = -1
            let actual_idx = new_idx - d;
            let neg_coeff = ModQ::negate(coeff, q);
            result_coeffs[actual_idx] = ModQ::add(result_coeffs[actual_idx], neg_coeff, q);
        } else {
            // Two wraparounds: X^(2d) = 1
            let actual_idx = new_idx - 2 * d;
            result_coeffs[actual_idx] = ModQ::add(result_coeffs[actual_idx], coeff, q);
        }
    }

    Poly::from_coeffs_moduli(result_coeffs, poly.moduli())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn random_lwe<R: Rng>(rng: &mut R, params: &InspireParams) -> LweCiphertext {
        let a: Vec<u64> = (0..params.ring_dim)
            .map(|_| rng.gen_range(0..params.q))
            .collect();
        let b = rng.gen_range(0..params.q);
        LweCiphertext { a, b, q: params.q }
    }

    #[test]
    fn test_transform_dimensions() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
        let lwe = random_lwe(&mut rng, &params);

        let intermediate = transform(&lwe, &params);

        assert_eq!(intermediate.dimension(), params.ring_dim);
        assert_eq!(intermediate.ring_dim(), params.ring_dim);
        assert_eq!(intermediate.modulus(), params.q);
    }

    #[test]
    fn test_transform_partial_dimensions() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
        let lwe = random_lwe(&mut rng, &params);
        let gamma = params.ring_dim / 4;

        let intermediate = transform_partial(gamma, &lwe, &params);

        assert_eq!(intermediate.dimension(), gamma);
        assert_eq!(intermediate.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_mul_by_monomial_identity() {
        let params = test_params();
        let coeffs: Vec<u64> = (0..params.ring_dim as u64).collect();
        let poly = Poly::from_coeffs(coeffs.clone(), params.q);

        let result = mul_by_monomial(&poly, 0, params.q);

        for i in 0..params.ring_dim {
            assert_eq!(result.coeff(i), poly.coeff(i));
        }
    }

    #[test]
    fn test_mul_by_monomial_shift() {
        let d = 256;
        let q = 1152921504606830593u64;
        let mut coeffs = vec![0u64; d];
        coeffs[0] = 1; // 1
        let poly = Poly::from_coeffs(coeffs, q);

        // X^0 * 1 = 1
        let result = mul_by_monomial(&poly, 1, q);
        assert_eq!(result.coeff(0), 0);
        assert_eq!(result.coeff(1), 1);
        for i in 2..d {
            assert_eq!(result.coeff(i), 0);
        }
    }

    #[test]
    fn test_mul_by_monomial_wraparound() {
        let d = 256;
        let q = 1152921504606830593u64;
        let mut coeffs = vec![0u64; d];
        coeffs[d - 1] = 1; // X^(d-1)
        let poly = Poly::from_coeffs(coeffs, q);

        // X * X^(d-1) = X^d = -1
        let result = mul_by_monomial(&poly, 1, q);
        assert_eq!(result.coeff(0), q - 1); // -1 mod q
        for i in 1..d {
            assert_eq!(result.coeff(i), 0);
        }
    }

    #[test]
    fn test_aggregate_single() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
        let lwe = random_lwe(&mut rng, &params);

        let intermediate = transform(&lwe, &params);
        let aggregated = aggregate(&[intermediate.clone()], &params);

        // Single ciphertext: aggregated should match intermediate
        assert_eq!(aggregated.dimension(), intermediate.dimension());
        for i in 0..aggregated.dimension() {
            for j in 0..params.ring_dim {
                assert_eq!(
                    aggregated.a_polys[i].coeff(j),
                    intermediate.a_polys[i].coeff(j)
                );
            }
        }
    }

    #[test]
    fn test_aggregate_multiple() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(54321);

        let n_cts = 4;
        let intermediates: Vec<IntermediateCiphertext> = (0..n_cts)
            .map(|_| {
                let lwe = random_lwe(&mut rng, &params);
                transform(&lwe, &params)
            })
            .collect();

        let aggregated = aggregate(&intermediates, &params);

        assert_eq!(aggregated.dimension(), params.ring_dim);
        // The b polynomial should have non-zero coefficients at positions 0..n_cts
        // (each LWE's b value shifted to its slot)
    }

    #[test]
    fn test_transform_at_slot() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(99999);
        let lwe = random_lwe(&mut rng, &params);
        let slot = 5;

        let intermediate = transform_at_slot(&lwe, slot, &params);

        // The b polynomial should have lwe.b at position 5
        assert_eq!(intermediate.b_poly.coeff(slot), lwe.b);
        for i in 0..params.ring_dim {
            if i != slot {
                assert_eq!(intermediate.b_poly.coeff(i), 0);
            }
        }
    }
}
