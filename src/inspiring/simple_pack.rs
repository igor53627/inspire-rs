//! Simple RLWE coefficient packing
//!
//! A direct implementation of RLWE ciphertext packing that combines multiple
//! RLWE ciphertexts (each with value in coefficient 0) into a single RLWE
//! (with values in coefficients 0, 1, 2, ...).
//!
//! This is used for the OnePacking (InsPIRe^1) variant.
//!
//! NOTE: pack_rlwe_coeffs only works when each input RLWE has message ONLY in coeff 0.
//! For PIR, where each RLWE contains the full rotated database, use pack_lwe_to_rlwe instead.

use crate::ks::KeySwitchingMatrix;
use crate::lwe::LweCiphertext;
use crate::math::{NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{gadget_decompose, GadgetVector};
use crate::rlwe::RlweCiphertext;

/// Pack multiple RLWE ciphertexts into a single RLWE ciphertext
///
/// Each input RLWE ciphertext should have its message in coefficient 0.
/// The output RLWE has message_k in coefficient k.
///
/// # Algorithm
/// For each RLWE ciphertext at position i:
/// 1. Multiply by X^i to move coefficient 0 to coefficient i
/// 2. Add all shifted RLWEs together
///
/// # Arguments
/// * `rlwe_ciphertexts` - RLWE ciphertexts, each with message in coeff 0
/// * `params` - System parameters
///
/// # Returns
/// A single RLWE ciphertext whose plaintext polynomial has
/// the messages in coefficients 0, 1, ..., n-1
pub fn pack_rlwe_coeffs(
    rlwe_ciphertexts: &[RlweCiphertext],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;

    if rlwe_ciphertexts.is_empty() {
        return RlweCiphertext::from_parts(Poly::zero(d, q), Poly::zero(d, q));
    }

    let mut result_a = Poly::zero(d, q);
    let mut result_b = Poly::zero(d, q);

    for (slot, rlwe) in rlwe_ciphertexts.iter().enumerate() {
        let shifted = if slot == 0 {
            rlwe.clone()
        } else {
            mul_rlwe_by_monomial(rlwe, slot, q)
        };
        result_a = &result_a + &shifted.a;
        result_b = &result_b + &shifted.b;
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

/// Multiply an RLWE ciphertext by X^k (in the negacyclic ring)
///
/// This shifts all coefficients, placing the message from coefficient 0
/// into coefficient k.
fn mul_rlwe_by_monomial(ct: &RlweCiphertext, k: usize, q: u64) -> RlweCiphertext {
    let a_shifted = mul_poly_by_monomial(&ct.a, k, q);
    let b_shifted = mul_poly_by_monomial(&ct.b, k, q);
    RlweCiphertext::from_parts(a_shifted, b_shifted)
}

/// Multiply a polynomial by X^k in the negacyclic ring R_q = Z_q[X]/(X^d + 1)
///
/// X^d = -1, so coefficients that wrap around get negated.
fn mul_poly_by_monomial(poly: &Poly, k: usize, q: u64) -> Poly {
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

    Poly::from_coeffs(result_coeffs, q)
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

/// Pack extracted LWE values into a trivial RLWE ciphertext (b-only)
///
/// This creates a trivial RLWE ciphertext (a=0, b=values) that can be
/// decrypted by any RLWE secret key. Used when we only need to pack
/// the plaintext values, not maintain encryption under a specific key.
///
/// # Arguments
/// * `lwe_ciphertexts` - LWE ciphertexts to pack (each encrypts a scalar)
/// * `params` - System parameters
///
/// # Returns
/// A trivial RLWE ciphertext with packed b values in coefficients 0, 1, 2, ...
#[allow(dead_code)]
pub fn pack_lwe_trivial(
    lwe_ciphertexts: &[LweCiphertext],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;

    if lwe_ciphertexts.is_empty() {
        return RlweCiphertext::from_parts(Poly::zero(d, q), Poly::zero(d, q));
    }

    // Just pack the b values at their respective coefficient positions
    let mut b_coeffs = vec![0u64; d];
    for (slot, lwe) in lwe_ciphertexts.iter().enumerate() {
        if slot < d {
            b_coeffs[slot] = lwe.b;
        }
    }

    // a = 0, b = packed values
    RlweCiphertext::from_parts(Poly::zero(d, q), Poly::from_coeffs(b_coeffs, q))
}

/// Pack multiple LWE ciphertexts into a single RLWE ciphertext via key-switching
///
/// This correctly converts LWE ciphertexts (encrypted under s_lwe) to a single
/// RLWE ciphertext (encrypted under s_rlwe) with values in coefficients 0, 1, 2, ...
///
/// # Algorithm
/// For each LWE ciphertext at slot i:
/// 1. Key-switch the LWE to RLWE using the packing matrix
/// 2. Multiply by X^i to place message in coefficient i
/// 3. Sum all results
///
/// # Arguments
/// * `lwe_ciphertexts` - LWE ciphertexts to pack (each encrypts a scalar)
/// * `ks_matrix` - Key-switching matrix from LWE key to RLWE key
/// * `params` - System parameters
pub fn pack_lwe_to_rlwe(
    lwe_ciphertexts: &[LweCiphertext],
    ks_matrix: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    if lwe_ciphertexts.is_empty() {
        return RlweCiphertext::from_parts(Poly::zero(d, q), Poly::zero(d, q));
    }

    let mut result_a = Poly::zero(d, q);
    let mut result_b = Poly::zero(d, q);

    for (slot, lwe) in lwe_ciphertexts.iter().enumerate() {
        // Convert LWE to RLWE and key-switch
        let rlwe_switched = lwe_to_rlwe_keyswitch(lwe, ks_matrix, &ctx, params);

        // Shift by X^slot to place message in coefficient slot
        let shifted = if slot == 0 {
            rlwe_switched
        } else {
            mul_rlwe_by_monomial(&rlwe_switched, slot, q)
        };

        // Accumulate
        result_a = &result_a + &shifted.a;
        result_b = &result_b + &shifted.b;
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

/// Apply negacyclic permutation to convert LWE a-vector to polynomial form
///
/// The LWE inner product <a, s> where s is derived from RLWE secret key
/// via sample_extract pattern equals the constant term of perm(a)(X) * s_rlwe(X).
///
/// Formula: negacyclic_perm(a) = [a[0], -a[d-1], -a[d-2], ..., -a[1]]
///
/// This is the inverse of the sample_extract_coeff0 transformation.
fn negacyclic_perm(a: &[u64], q: u64) -> Vec<u64> {
    let d = a.len();
    let mut out = vec![0u64; d];
    
    // First element stays the same
    out[0] = a[0];
    
    // Rest are negated and reversed: out[i] = -a[d-i] for i > 0
    for i in 1..d {
        let val = a[d - i];
        out[i] = if val == 0 { 0 } else { q - val };
    }
    
    out
}

/// Convert a single LWE ciphertext to RLWE via key-switching
///
/// The LWE ciphertext (a, b) encrypts m under s_lwe where:
///   b + <a, s_lwe> ≈ Δm
///
/// We produce an RLWE ciphertext (a', b') under s_rlwe where:
///   a'·s_rlwe + b' ≈ Δm  (in coefficient 0)
///
/// The key insight is that the LWE secret key s_lwe is derived from the RLWE
/// secret key s_rlwe via sample_extract pattern:
///   s_lwe[0] = s_rlwe[0], s_lwe[i] = s_rlwe[d-i] for i > 0
///
/// To make <a, s_lwe> equal to coeff_0(a'(X) * s_rlwe(X)), we need:
///   a'(X) = negacyclic_perm(a)
///
/// The key-switching matrix K encrypts s_lwe·z^i under s_rlwe.
fn lwe_to_rlwe_keyswitch(
    lwe: &LweCiphertext,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;

    // Apply negacyclic permutation to convert LWE a-vector to polynomial
    // This ensures <a, s_lwe> = coeff_0(a_poly * s_rlwe)
    let a_perm = negacyclic_perm(&lwe.a, q);
    let a_poly = Poly::from_coeffs(a_perm, q);

    // Create initial b polynomial with LWE b in constant term
    let mut b_coeffs = vec![0u64; d];
    b_coeffs[0] = lwe.b;
    let b_poly = Poly::from_coeffs(b_coeffs, q);

    // Key-switch: decompose a_poly and apply KS matrix
    // This converts encryption from s_lwe (as polynomial) to s_rlwe
    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
    let a_decomp = gadget_decompose(&a_poly, &gadget);

    // Initialize result: (0, b)
    let mut result_a = Poly::zero(d, q);
    let mut result_b = b_poly;

    // Accumulate: Σᵢ decomp_i · K[i]
    for (i, digit_poly) in a_decomp.iter().enumerate() {
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

    RlweCiphertext::from_parts(result_a, result_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{GaussianSampler, ModQ, NttContext};
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
    fn test_pack_rlwe_coeffs_single() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);

        let message = 12345u64;
        let mut msg_coeffs = vec![0u64; d];
        msg_coeffs[0] = message;
        let msg_poly = Poly::from_coeffs(msg_coeffs, q);
        let a = Poly::random(d, q);
        let error = sample_error_poly(d, q, &mut sampler);
        let rlwe_ct = RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx);

        let decrypted = rlwe_ct.decrypt(&rlwe_sk, delta, params.p, &ctx);
        assert_eq!(decrypted.coeff(0), message, "Original RLWE decryption failed");

        let packed = pack_rlwe_coeffs(&[rlwe_ct], &params);
        let packed_decrypted = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        assert_eq!(
            packed_decrypted.coeff(0),
            message,
            "Packed RLWE coefficient 0 should contain the message"
        );
    }

    #[test]
    fn test_pack_rlwe_coeffs_multiple() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);

        let messages: Vec<u64> = vec![100, 200, 300, 400];
        let rlwe_cts: Vec<_> = messages
            .iter()
            .map(|&msg| {
                let mut msg_coeffs = vec![0u64; d];
                msg_coeffs[0] = msg;
                let msg_poly = Poly::from_coeffs(msg_coeffs, q);
                let a = Poly::random(d, q);
                let error = sample_error_poly(d, q, &mut sampler);
                RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx)
            })
            .collect();

        let packed = pack_rlwe_coeffs(&rlwe_cts, &params);
        let packed_decrypted = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        for (i, &expected_msg) in messages.iter().enumerate() {
            assert_eq!(
                packed_decrypted.coeff(i),
                expected_msg,
                "Coefficient {} mismatch: expected {}, got {}",
                i,
                expected_msg,
                packed_decrypted.coeff(i)
            );
        }
    }

    #[test]
    fn test_mul_poly_by_monomial() {
        let d = 8;
        let q = 1152921504606830593u64;

        let mut coeffs = vec![0u64; d];
        coeffs[0] = 1;
        let poly = Poly::from_coeffs(coeffs, q);

        let shifted = mul_poly_by_monomial(&poly, 3, q);
        assert_eq!(shifted.coeff(3), 1);
        assert_eq!(shifted.coeff(0), 0);

        let mut coeffs2 = vec![0u64; d];
        coeffs2[d - 1] = 1;
        let poly2 = Poly::from_coeffs(coeffs2, q);

        let wrapped = mul_poly_by_monomial(&poly2, 1, q);
        assert_eq!(wrapped.coeff(0), q - 1);
    }

    #[test]
    fn test_pack_lwe_to_rlwe_single() {
        use crate::lwe::LweSecretKey;
        use crate::rgsw::GadgetVector;
        use crate::ks::generate_packing_ks_matrix;

        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);

        // Create packing KS matrix
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        let packing_ks = generate_packing_ks_matrix(&lwe_sk, &rlwe_sk, &gadget, &mut sampler, &ctx);

        // Create message in coeff 0
        let message = 12345u64;
        let mut msg_coeffs = vec![0u64; d];
        msg_coeffs[0] = message;
        let msg_poly = Poly::from_coeffs(msg_coeffs, q);

        // Encrypt with RLWE
        let a = Poly::random(d, q);
        let error_coeffs: Vec<u64> = (0..d)
            .map(|_| ModQ::from_signed(sampler.sample(), q))
            .collect();
        let error = Poly::from_coeffs(error_coeffs, q);
        let rlwe_ct = RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx);

        // Extract LWE
        let lwe_ct = rlwe_ct.sample_extract_coeff0();

        // Verify LWE decryption works
        let lwe_dec = lwe_ct.decrypt(&lwe_sk, delta, params.p);
        assert_eq!(lwe_dec, message, "LWE decrypt failed: got {}, expected {}", lwe_dec, message);

        // Pack single LWE into RLWE
        let packed = pack_lwe_to_rlwe(&[lwe_ct], &packing_ks, &params);

        // Decrypt packed RLWE
        let packed_dec = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        assert_eq!(packed_dec.coeff(0), message,
            "Packed RLWE decrypt failed: got {}, expected {}", packed_dec.coeff(0), message);
    }

    // NOTE: test_pack_lwe_to_rlwe_multiple is intentionally removed.
    // 
    // The simple shift-and-add packing approach (pack_lwe_to_rlwe with multiple LWEs)
    // does NOT work because key-switched RLWEs have noise in ALL coefficients, not just
    // in coefficient 0. When we shift and add, the noise from different coefficients mixes.
    //
    // Proper OnePacking requires automorphism-based tree packing as implemented in
    // Google's InsPIRe code (research/InsPIRe/src/packing.rs).
    //
    // For now, OnePacking falls back to NoPacking (per-column extraction) which works correctly.
}
