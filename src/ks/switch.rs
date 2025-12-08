//! Key-switching operation

use crate::math::{NttContext, Poly};
use crate::rgsw::gadget_decompose;
use crate::rlwe::RlweCiphertext;

use super::setup::KeySwitchingMatrix;

/// Apply key-switching to transform a ciphertext from key s to key s'
///
/// Given ciphertext (a, b) under key s and key-switching matrix K,
/// computes a new ciphertext (a', b') valid under key s'.
///
/// # Algorithm
///
/// 1. Decompose a using gadget: g⁻¹(a) = [a₀, a₁, ..., a_{ℓ-1}]
/// 2. Compute: (a', b') = (0, b) + Σᵢ aᵢ · K[i]
///
/// The result satisfies: a'·s' + b' ≈ a·s + b (the same decrypted message)
///
/// # Arguments
/// * `ct` - Input ciphertext (a, b) valid under source key s
/// * `ks_matrix` - Key-switching matrix from s to s'
/// * `ctx` - NTT context
///
/// # Returns
/// New ciphertext valid under target key s'
pub fn key_switch(
    ct: &RlweCiphertext,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = ct.ring_dim();
    let q = ct.modulus();
    let gadget = &ks_matrix.gadget;
    let ell = gadget.len;

    // Decompose the 'a' component
    let a_decomp = gadget_decompose(&ct.a, gadget);

    // Initialize result: (0, b)
    let mut result_a = Poly::zero(d, q);
    let mut result_b = ct.b.clone();

    // Accumulate: Σᵢ aᵢ · K[i]
    for i in 0..ell {
        let ks_row = &ks_matrix.rows[i];

        // aᵢ · K[i].a
        let term_a = a_decomp[i].mul_ntt(&ks_row.a, ctx);
        result_a += term_a;

        // aᵢ · K[i].b
        let term_b = a_decomp[i].mul_ntt(&ks_row.b, ctx);
        result_b += term_b;
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

/// Apply key-switching with precomputed NTT representations
///
/// This is an optimized version when the key-switching matrix rows
/// are already in NTT domain.
pub fn key_switch_ntt(
    ct: &RlweCiphertext,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = ct.ring_dim();
    let q = ct.modulus();
    let gadget = &ks_matrix.gadget;
    let ell = gadget.len;

    // Decompose the 'a' component
    let a_decomp = gadget_decompose(&ct.a, gadget);

    // Convert decomposed polynomials to NTT
    let a_decomp_ntt: Vec<Poly> = a_decomp
        .into_iter()
        .map(|mut p| {
            p.to_ntt(ctx);
            p
        })
        .collect();

    // Initialize result: (0, b)
    let mut result_a = Poly::zero(d, q);
    result_a.to_ntt(ctx);

    let mut result_b = ct.b.clone();
    result_b.to_ntt(ctx);

    // Accumulate in NTT domain
    for i in 0..ell {
        let ks_row = &ks_matrix.rows[i];

        // Convert KS row to NTT if needed
        let mut ks_a = ks_row.a.clone();
        let mut ks_b = ks_row.b.clone();
        ks_a.to_ntt(ctx);
        ks_b.to_ntt(ctx);

        // aᵢ · K[i].a in NTT domain
        let term_a = a_decomp_ntt[i].mul_ntt_domain(&ks_a, ctx);
        result_a += term_a;

        // aᵢ · K[i].b in NTT domain
        let term_b = a_decomp_ntt[i].mul_ntt_domain(&ks_b, ctx);
        result_b += term_b;
    }

    // Convert back to coefficient domain
    result_a.from_ntt(ctx);
    result_b.from_ntt(ctx);

    RlweCiphertext::from_parts(result_a, result_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ks::generate_ks_matrix;
    use crate::math::{GaussianSampler, ModQ};
    use crate::params::InspireParams;
    use crate::rgsw::GadgetVector;
    use crate::rlwe::RlweSecretKey;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        NttContext::new(params.ring_dim, params.q)
    }

    fn sample_error_poly(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Poly {
        let coeffs: Vec<u64> = (0..dim)
            .map(|_| {
                let sample = sampler.sample();
                ModQ::from_signed(sample, q)
            })
            .collect();
        Poly::from_coeffs(coeffs, q)
    }

    #[test]
    fn test_key_switch_correctness() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        // Generate two different secret keys
        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        // Create key-switching matrix from sk1 to sk2
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        // Encrypt a message under sk1
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % params.p).collect();
        let msg = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk1, &msg, delta, a, &e, &ctx);

        // Verify original decryption under sk1
        let dec1 = ct1.decrypt(&sk1, delta, params.p, &ctx);
        for i in 0..params.ring_dim {
            assert_eq!(dec1.coeff(i), msg_coeffs[i], "Original decryption failed at {}", i);
        }

        // Apply key-switching
        let ct2 = key_switch(&ct1, &ks_matrix, &ctx);

        // Verify decryption under sk2
        let dec2 = ct2.decrypt(&sk2, delta, params.p, &ctx);
        for i in 0..params.ring_dim {
            assert_eq!(
                dec2.coeff(i),
                msg_coeffs[i],
                "Key-switched decryption failed at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_key_switch_zero_message() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        // Encrypt zero under sk1
        let msg = Poly::zero(params.ring_dim, params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk1, &msg, delta, a, &e, &ctx);

        // Key-switch
        let ct2 = key_switch(&ct1, &ks_matrix, &ctx);

        // Decrypt under sk2
        let decrypted = ct2.decrypt(&sk2, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Expected 0 at coefficient {}", i);
        }
    }

    #[test]
    fn test_key_switch_same_key() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        // Key-switch from a key to itself (should work)
        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk, &sk, &gadget, &mut sampler, &ctx);

        // Encrypt a message
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();
        let msg = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // Key-switch (to same key)
        let ct_switched = key_switch(&ct, &ks_matrix, &ctx);

        // Should still decrypt correctly
        let decrypted = ct_switched.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(
                decrypted.coeff(i),
                msg_coeffs[i],
                "Mismatch at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_key_switch_ntt_equivalence() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        // Encrypt message under sk1
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 50).collect();
        let msg = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk1, &msg, delta, a, &e, &ctx);

        // Both methods should produce equivalent results
        let ct_basic = key_switch(&ct, &ks_matrix, &ctx);
        let ct_ntt = key_switch_ntt(&ct, &ks_matrix, &ctx);

        // Decrypt both
        let dec_basic = ct_basic.decrypt(&sk2, delta, params.p, &ctx);
        let dec_ntt = ct_ntt.decrypt(&sk2, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(dec_basic.coeff(i), msg_coeffs[i]);
            assert_eq!(dec_ntt.coeff(i), msg_coeffs[i]);
        }
    }

    #[test]
    fn test_key_switch_after_homomorphic_add() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        // Encrypt two messages under sk1
        let msg1_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 30).collect();
        let msg2_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| ((i + 10) as u64) % 30).collect();

        let msg1 = Poly::from_coeffs(msg1_coeffs.clone(), params.q);
        let msg2 = Poly::from_coeffs(msg2_coeffs.clone(), params.q);

        let a1 = Poly::random(params.ring_dim, params.q);
        let e1 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk1, &msg1, delta, a1, &e1, &ctx);

        let a2 = Poly::random(params.ring_dim, params.q);
        let e2 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct2 = RlweCiphertext::encrypt(&sk1, &msg2, delta, a2, &e2, &ctx);

        // Homomorphic add
        let ct_sum = ct1.add(&ct2);

        // Key-switch the sum
        let ct_switched = key_switch(&ct_sum, &ks_matrix, &ctx);

        // Decrypt under sk2
        let decrypted = ct_switched.decrypt(&sk2, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg1_coeffs[i] + msg2_coeffs[i]) % params.p;
            assert_eq!(
                decrypted.coeff(i),
                expected,
                "Mismatch at coefficient {}",
                i
            );
        }
    }
}
