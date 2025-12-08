//! Main packing algorithms for InspiRING
//!
//! Provides the Pack and PartialPack procedures that combine Transform,
//! Aggregation, and Collapse stages to convert LWE ciphertexts to RLWE.
//!
//! Key insight: In the CRS model, the `a` vectors are fixed, so most
//! computation can be precomputed offline. Only `b` values change per query.

use crate::ks::KeySwitchingMatrix;
use crate::lwe::LweCiphertext;
use crate::math::Poly;
use crate::params::InspireParams;
use crate::rlwe::RlweCiphertext;

use super::collapse::{collapse, collapse_partial};
use super::transform::{aggregate, transform_at_slot};
use super::types::AggregatedCiphertext;

use serde::{Deserialize, Serialize};

/// Main packing algorithm: pack d LWE ciphertexts into one RLWE ciphertext
///
/// Input: [A, b] ∈ Z_q^(d×(d+1)) (d LWE ciphertexts)
/// Output: (a_fin, b_fin) ∈ R_q × R_q
///
/// The packed RLWE ciphertext encrypts a polynomial where the i-th coefficient
/// contains the message from the i-th LWE ciphertext.
///
/// # Arguments
/// * `lwe_ciphertexts` - Array of d LWE ciphertexts to pack
/// * `k_g` - Key-switching matrix for cyclic generator
/// * `k_h` - Key-switching matrix for conjugation
/// * `params` - System parameters
pub fn pack(
    lwe_ciphertexts: &[LweCiphertext],
    k_g: &KeySwitchingMatrix,
    k_h: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    assert_eq!(
        lwe_ciphertexts.len(),
        d,
        "Must provide exactly d ciphertexts for full packing"
    );

    // Stage 1: Transform each LWE ciphertext to intermediate form
    let intermediates: Vec<_> = lwe_ciphertexts
        .iter()
        .enumerate()
        .map(|(i, lwe)| transform_at_slot(lwe, i, params))
        .collect();

    // Stage 2: Aggregate all intermediate ciphertexts
    let aggregated = aggregate(&intermediates, params);

    // Stage 3: Collapse to RLWE using key-switching
    collapse(&aggregated, k_g, k_h, params)
}

/// Partial packing for γ ≤ d/2 LWE ciphertexts
///
/// When fewer ciphertexts need to be packed, this optimized version
/// uses only one key-switching matrix (K_g), reducing key material.
///
/// # Arguments
/// * `lwe_ciphertexts` - Array of γ ≤ d/2 LWE ciphertexts
/// * `k_g` - Key-switching matrix for cyclic generator
/// * `params` - System parameters
pub fn partial_pack(
    lwe_ciphertexts: &[LweCiphertext],
    k_g: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let gamma = lwe_ciphertexts.len();
    let d = params.ring_dim;

    assert!(
        gamma <= d / 2,
        "partial_pack requires γ ≤ d/2 ciphertexts"
    );

    if gamma == 0 {
        return RlweCiphertext::from_parts(Poly::zero(d, params.q), Poly::zero(d, params.q));
    }

    // Stage 1: Transform using partial transform
    let intermediates: Vec<_> = lwe_ciphertexts
        .iter()
        .enumerate()
        .map(|(i, lwe)| transform_at_slot(lwe, i, params))
        .collect();

    // Stage 2: Aggregate
    let aggregated = aggregate(&intermediates, params);

    // Stage 3: Collapse using only K_g
    collapse_partial(gamma, &aggregated.to_intermediate(), k_g, params)
}

/// Precomputable offline work (CRS-dependent)
///
/// In the CRS model, the `a` vectors are fixed and publicly known.
/// This struct holds precomputed values that depend only on:
/// - The CRS `a` vectors
/// - The key-switching matrices K_g, K_h
///
/// The online phase only needs to process the `b` values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackingPrecomputation {
    /// Precomputed aggregated polynomial for the a-component
    /// This is the result of Transform + Aggregate on the CRS a vectors
    precomputed_a_aggregate: AggregatedCiphertext,

    /// Number of ciphertexts this precomputation was built for
    num_ciphertexts: usize,

    /// Ring dimension
    ring_dim: usize,

    /// Modulus
    q: u64,
}

impl PackingPrecomputation {
    /// Get the number of ciphertexts this precomputation supports
    pub fn num_ciphertexts(&self) -> usize {
        self.num_ciphertexts
    }
}

/// Precompute packing values for fixed CRS randomness
///
/// Given the fixed `a` vectors from the CRS, precompute everything
/// that doesn't depend on the `b` values:
/// - Transform each a vector
/// - Aggregate the transformed a vectors
/// - Prepare intermediate key-switching computations
///
/// # Arguments
/// * `crs_a_vectors` - Fixed a vectors from CRS, one per LWE ciphertext
/// * `k_g` - Key-switching matrix for cyclic generator
/// * `k_h` - Key-switching matrix for conjugation
/// * `params` - System parameters
pub fn precompute_packing(
    crs_a_vectors: &[Vec<u64>],
    _k_g: &KeySwitchingMatrix,
    _k_h: &KeySwitchingMatrix,
    params: &InspireParams,
) -> PackingPrecomputation {
    let d = params.ring_dim;
    let q = params.q;
    let n = crs_a_vectors.len();

    assert!(!crs_a_vectors.is_empty(), "Must have at least one a vector");
    assert_eq!(
        crs_a_vectors[0].len(),
        d,
        "a vectors must have dimension d"
    );

    // Create dummy LWE ciphertexts with the CRS a vectors and b=0
    // We only care about the a-component transformation
    let dummy_lwes: Vec<LweCiphertext> = crs_a_vectors
        .iter()
        .map(|a| LweCiphertext {
            a: a.clone(),
            b: 0,
            q,
        })
        .collect();

    // Transform each at its slot
    let intermediates: Vec<_> = dummy_lwes
        .iter()
        .enumerate()
        .map(|(i, lwe)| transform_at_slot(lwe, i, params))
        .collect();

    // Aggregate the a components (b components will all be zero)
    let aggregated = aggregate(&intermediates, params);

    PackingPrecomputation {
        precomputed_a_aggregate: aggregated,
        num_ciphertexts: n,
        ring_dim: d,
        q,
    }
}

/// Online packing using precomputation
///
/// Given precomputed values for fixed CRS a vectors, pack LWE ciphertexts
/// using only the `b` values. This is the fast online phase.
///
/// # Arguments
/// * `lwe_b_values` - Only the b values from each LWE ciphertext
/// * `precomp` - Precomputed values from `precompute_packing`
/// * `k_g` - Key-switching matrix for cyclic generator
/// * `k_h` - Key-switching matrix for conjugation
/// * `params` - System parameters
pub fn pack_online(
    lwe_b_values: &[u64],
    precomp: &PackingPrecomputation,
    k_g: &KeySwitchingMatrix,
    k_h: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = precomp.ring_dim;
    let q = precomp.q;
    let n = lwe_b_values.len();

    assert_eq!(
        n, precomp.num_ciphertexts,
        "Number of b values must match precomputation"
    );

    // Create the b polynomial by embedding each b_i at position i
    // This is: sum_i b_i * X^i
    let mut b_coeffs = vec![0u64; d];
    for (i, &b_val) in lwe_b_values.iter().enumerate() {
        if i < d {
            b_coeffs[i] = b_val;
        }
    }
    let b_poly = Poly::from_coeffs(b_coeffs, q);

    // Combine with precomputed a aggregate
    let full_aggregate = AggregatedCiphertext::new(
        precomp.precomputed_a_aggregate.a_polys.clone(),
        &precomp.precomputed_a_aggregate.b_poly + &b_poly,
    );

    // Collapse to get final RLWE
    collapse(&full_aggregate, k_g, k_h, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lwe::LweSecretKey;
    use crate::math::GaussianSampler;
    use rand::Rng;
    use rand::SeedableRng;

    fn test_params() -> InspireParams {
        // Use smaller params for faster tests
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            p: 65536,
            sigma: 3.2,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    fn random_lwe<R: Rng>(rng: &mut R, params: &InspireParams) -> LweCiphertext {
        let a: Vec<u64> = (0..params.ring_dim)
            .map(|_| rng.gen_range(0..params.q))
            .collect();
        let b = rng.gen_range(0..params.q);
        LweCiphertext { a, b, q: params.q }
    }

    fn encrypt_lwe<R: Rng>(
        sk: &LweSecretKey,
        message: u64,
        rng: &mut R,
        params: &InspireParams,
    ) -> LweCiphertext {
        let a: Vec<u64> = (0..params.ring_dim)
            .map(|_| rng.gen_range(0..params.q))
            .collect();
        let error = (rng.gen::<u8>() % 7) as i64 - 3;
        LweCiphertext::encrypt(sk, message, params.delta(), a, error)
    }

    #[test]
    fn test_pack_dimensions() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);

        let lwe_cts: Vec<LweCiphertext> = (0..params.ring_dim)
            .map(|_| random_lwe(&mut rng, &params))
            .collect();

        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);
        let k_h = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);

        let result = pack(&lwe_cts, &k_g, &k_h, &params);

        assert_eq!(result.ring_dim(), params.ring_dim);
        assert_eq!(result.modulus(), params.q);
    }

    #[test]
    fn test_partial_pack_dimensions() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(54321);

        let gamma = params.ring_dim / 4;
        let lwe_cts: Vec<LweCiphertext> = (0..gamma)
            .map(|_| random_lwe(&mut rng, &params))
            .collect();

        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);

        let result = partial_pack(&lwe_cts, &k_g, &params);

        assert_eq!(result.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_precompute_pack_online() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(98765);

        let n = 16; // Small for testing
        let crs_a_vectors: Vec<Vec<u64>> = (0..n)
            .map(|_| {
                (0..params.ring_dim)
                    .map(|_| rng.gen_range(0..params.q))
                    .collect()
            })
            .collect();

        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);
        let k_h = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);

        // Precompute
        let precomp = precompute_packing(&crs_a_vectors, &k_g, &k_h, &params);
        assert_eq!(precomp.num_ciphertexts(), n);

        // Online phase
        let b_values: Vec<u64> = (0..n).map(|_| rng.gen_range(0..params.q)).collect();
        let result = pack_online(&b_values, &precomp, &k_g, &k_h, &params);

        assert_eq!(result.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_pack_with_real_encryption() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11111);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate LWE secret key
        let lwe_sk = LweSecretKey::generate(params.ring_dim, params.q, &mut sampler);

        // Messages to pack
        let messages: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64 * 7) % params.p)
            .collect();

        // Encrypt each message
        let lwe_cts: Vec<LweCiphertext> = messages
            .iter()
            .map(|&m| encrypt_lwe(&lwe_sk, m, &mut rng, &params))
            .collect();

        // Verify LWE decryption works
        for (ct, &expected) in lwe_cts.iter().zip(messages.iter()) {
            let decrypted = ct.decrypt(&lwe_sk, params.delta(), params.p);
            assert_eq!(decrypted, expected, "LWE decryption failed");
        }

        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);
        let k_h = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);

        // Pack
        let packed = pack(&lwe_cts, &k_g, &k_h, &params);

        // Note: Full correctness test requires proper RLWE decryption with
        // matching key setup. With dummy key-switching matrices, we can only
        // verify the structure is correct.
        assert_eq!(packed.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_empty_partial_pack() {
        let params = test_params();
        let k_g = KeySwitchingMatrix::dummy(params.ring_dim, params.q, params.gadget_len);

        let result = partial_pack(&[], &k_g, &params);

        assert_eq!(result.ring_dim(), params.ring_dim);
        for i in 0..params.ring_dim {
            assert_eq!(result.a.coeff(i), 0);
            assert_eq!(result.b.coeff(i), 0);
        }
    }

    #[test]
    fn test_aggregate_properties() {
        let params = test_params();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(33333);

        // Create 4 LWE ciphertexts with known structure
        let n = 4;
        let lwe_cts: Vec<LweCiphertext> = (0..n)
            .map(|_| random_lwe(&mut rng, &params))
            .collect();

        // Transform at slots
        let intermediates: Vec<_> = lwe_cts
            .iter()
            .enumerate()
            .map(|(i, lwe)| transform_at_slot(lwe, i, &params))
            .collect();

        // Aggregate
        let aggregated = aggregate(&intermediates, &params);

        // The b polynomial should have lwe_cts[i].b at position i
        for (i, ct) in lwe_cts.iter().enumerate() {
            assert_eq!(
                aggregated.b_poly.coeff(i),
                ct.b,
                "b coefficient mismatch at position {}",
                i
            );
        }
    }
}
