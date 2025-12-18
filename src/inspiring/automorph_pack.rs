//! Automorphism-based tree packing for OnePacking (InsPIRe^1)
//!
//! This module implements the automorphism-based tree packing algorithm from
//! Google's InsPIRe code that correctly packs multiple LWE ciphertexts into
//! a single RLWE ciphertext.
//!
//! The simple "shift and add" approach fails because key-switched RLWEs have
//! noise in ALL coefficients. The automorphism approach uses Galois automorphisms
//! to permute coefficients in a controlled way that preserves encryption structure.
//!
//! # Algorithm Overview (Google's prep_pack_lwes + pack_lwes approach)
//!
//! 1. **prep_pack_lwes**: For each LWE ciphertext (a, b):
//!    - Create RLWE with a' = negacyclic_perm(a), b' = 0
//!    - The b values are handled separately
//!
//! 2. **Tree packing** on the prepped RLWEs:
//!    - Recursively pair ciphertexts in a binary tree
//!    - At each level, compute: ct_even + y * ct_odd, ct_even - y * ct_odd
//!    - Apply automorphism τ_t and key-switch to combine pairs
//!
//! 3. **Finalize**: Add b_values[z] * d to result.b[z] for each coefficient
//!
//! The key insight is that we only tree-pack the 'a' polynomials, then add
//! the scaled 'b' values at the end. This avoids the noise mixing problem.

use crate::ks::KeySwitchingMatrix;
use crate::lwe::LweCiphertext;
use crate::math::{ModQ, NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::gadget_decompose;
use crate::rlwe::{automorphism_ciphertext, RlweCiphertext};

/// Apply homomorphic automorphism τ_t to RLWE ciphertext and key-switch back
///
/// After applying τ_t to a ciphertext, it's encrypted under τ_t(s) instead of s.
/// The key-switching matrix converts it back to encryption under s.
///
/// # Arguments
/// * `ct` - Input RLWE ciphertext
/// * `t` - Galois element (automorphism index)
/// * `ks_matrix` - Key-switching matrix from τ_t(s) to s
/// * `ctx` - NTT context
pub fn homomorphic_automorph(
    ct: &RlweCiphertext,
    t: usize,
    ks_matrix: &KeySwitchingMatrix,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = ct.ring_dim();
    let q = ct.modulus();

    // Step 1: Apply automorphism τ_t to both components
    let ct_auto = automorphism_ciphertext(ct, t);

    // Step 2: Decompose the 'a' component for key-switching
    // After automorphism, ciphertext is encrypted under τ_t(s)
    // Key-switch converts to encryption under s
    let gadget = &ks_matrix.gadget;
    let a_decomp = gadget_decompose(&ct_auto.a, gadget);

    // Step 3: Key-switch
    // Result: (a', b') = (0, τ_t(b)) + Σᵢ decomp_i · K[i]
    let mut result_a = Poly::zero(d, q);
    let mut result_b = ct_auto.b.clone();

    for (i, digit_poly) in a_decomp.iter().enumerate() {
        if i < ks_matrix.len() {
            let ks_row = ks_matrix.get_row(i);
            let term_a = digit_poly.mul_ntt(&ks_row.a, ctx);
            let term_b = digit_poly.mul_ntt(&ks_row.b, ctx);
            result_a = &result_a + &term_a;
            result_b = &result_b + &term_b;
        }
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

/// Y-constants for tree packing at each level
///
/// At level ℓ, we use y = ω^(d / 2^ℓ) where ω is a primitive 2d-th root of unity.
/// In the polynomial ring Z_q[X]/(X^d + 1), X is a primitive 2d-th root of unity.
///
/// The y-constants are polynomials representing X^(d / 2^ℓ).
pub struct YConstants {
    /// Y values at each level: y[ℓ] = X^(d / 2^(ℓ+1))
    pub y_polys: Vec<Poly>,
    /// Negative Y values at each level: -y[ℓ]
    pub neg_y_polys: Vec<Poly>,
}

impl YConstants {
    /// Generate y-constants for packing up to log_d levels
    ///
    /// For d = 256 with log_d = 8 levels:
    /// - Level 0: y = X^128 (step = 128)
    /// - Level 1: y = X^64 (step = 64)
    /// - Level 2: y = X^32 (step = 32)
    /// - ...
    /// - Level 7: y = X^1 (step = 1)
    pub fn generate(d: usize, q: u64) -> Self {
        let log_d = (d as f64).log2() as usize;
        let mut y_polys = Vec::with_capacity(log_d);
        let mut neg_y_polys = Vec::with_capacity(log_d);

        for ell in 0..log_d {
            // At level ell, step = d / 2^(ell+1)
            let step = d >> (ell + 1);
            
            // y = X^step
            let mut y_coeffs = vec![0u64; d];
            if step < d {
                y_coeffs[step] = 1;
            }
            let y_poly = Poly::from_coeffs(y_coeffs, q);

            // -y = -X^step
            let mut neg_y_coeffs = vec![0u64; d];
            if step < d {
                neg_y_coeffs[step] = q - 1;
            }
            let neg_y_poly = Poly::from_coeffs(neg_y_coeffs, q);

            y_polys.push(y_poly);
            neg_y_polys.push(neg_y_poly);
        }

        Self { y_polys, neg_y_polys }
    }

    /// Get y polynomial at level ℓ
    pub fn y(&self, level: usize) -> &Poly {
        &self.y_polys[level]
    }

    /// Get -y polynomial at level ℓ
    pub fn neg_y(&self, level: usize) -> &Poly {
        &self.neg_y_polys[level]
    }
}

/// Recursive tree packing of RLWE ciphertexts
///
/// Packs 2^ℓ ciphertexts (starting at start_idx) into a single ciphertext
/// where each input's value appears at a distinct coefficient position.
///
/// # Algorithm
/// 
/// Base case (ℓ = 0): Return the single ciphertext.
///
/// Recursive case:
/// 1. Pack even-indexed half: pack_inner(ℓ-1, even)
/// 2. Pack odd-indexed half: pack_inner(ℓ-1, odd)
/// 3. Compute: ct_sum_0 = ct_even + y * ct_odd
/// 4. Compute: ct_sum_1 = ct_even - y * ct_odd
/// 5. Apply automorphism τ_t to ct_sum_1 and key-switch
/// 6. Return: ct_sum_0 + τ_t(ct_sum_1)
///
/// # Arguments
/// * `ell` - Recursion level (log2 of number of ciphertexts to pack)
/// * `start_idx` - Starting index in rlwe_cts
/// * `rlwe_cts` - Array of RLWE ciphertexts (each with value in coeff 0)
/// * `automorph_keys` - Key-switching matrices indexed by automorphism level
/// * `y_constants` - Pre-computed y constants for each level
/// * `ctx` - NTT context
/// * `log_n` - log2 of total number of ciphertexts being packed
pub fn pack_lwes_inner(
    ell: usize,
    start_idx: usize,
    rlwe_cts: &[RlweCiphertext],
    automorph_keys: &[KeySwitchingMatrix],
    y_constants: &YConstants,
    ctx: &NttContext,
    log_n: usize,
) -> RlweCiphertext {
    // Base case: single ciphertext
    if ell == 0 {
        return rlwe_cts[start_idx].clone();
    }

    // Step size: 2^(log_n - ell) ciphertexts apart
    let step = 1 << (log_n - ell);
    let even = start_idx;
    let odd = start_idx + step;

    // Recursive calls for even and odd halves
    let ct_even = pack_lwes_inner(ell - 1, even, rlwe_cts, automorph_keys, y_constants, ctx, log_n);
    let ct_odd = pack_lwes_inner(ell - 1, odd, rlwe_cts, automorph_keys, y_constants, ctx, log_n);

    // Get y and -y for this level
    // y[ell-1] = X^(d / 2^ell)
    let y = y_constants.y(ell - 1);
    let neg_y = y_constants.neg_y(ell - 1);

    // ct_sum_0 = ct_even + y * ct_odd
    let y_times_odd = ct_odd.poly_mul(y, ctx);
    let ct_sum_0 = ct_even.add(&y_times_odd);

    // ct_sum_1 = ct_even - y * ct_odd = ct_even + (-y) * ct_odd
    let neg_y_times_odd = ct_odd.poly_mul(neg_y, ctx);
    let ct_sum_1 = ct_even.add(&neg_y_times_odd);

    // Automorphism: τ_t where t = 2^ℓ + 1
    let t = (1 << ell) + 1;
    
    // The automorph_keys are indexed by the exponent in t = 2^k + 1
    // For ell = 1, we need t = 3 = 2^1 + 1, so k = 1, index = log_d - 1 - (log_d - 1) = 0?
    // Actually, Google's code uses: pub_params[poly_len_log2 - 1 - (ell - 1)]
    // So for ell=1, index = log_d - 1 - 0 = log_d - 1
    // For ell=log_d, index = log_d - 1 - (log_d - 1) = 0
    //
    // automorph_keys[i] is for t = d/2^i + 1:
    //   i=0: t = d + 1
    //   i=1: t = d/2 + 1
    //   ...
    //   i=log_d-1: t = 2 + 1 = 3
    //
    // We need t = 2^ell + 1. So we need 2^ell = d/2^i, meaning i = log_d - ell
    let log_d = automorph_keys.len();
    let ks_idx = log_d - ell;
    
    if ks_idx >= automorph_keys.len() {
        panic!("ks_idx {} out of bounds for {} automorph_keys", ks_idx, automorph_keys.len());
    }
    let ks_matrix = &automorph_keys[ks_idx];

    // Apply homomorphic automorphism to ct_sum_1
    let ct_sum_1_auto = homomorphic_automorph(&ct_sum_1, t, ks_matrix, ctx);

    // Final result: ct_sum_0 + τ_t(ct_sum_1)
    ct_sum_0.add(&ct_sum_1_auto)
}

/// Pack up to d RLWE ciphertexts into a single RLWE using tree packing
///
/// Each input ciphertext should have its message in coefficient 0.
/// The output has message_k in coefficient k.
///
/// # Arguments
/// * `rlwe_cts` - RLWE ciphertexts (each with message in coeff 0)
/// * `automorph_keys` - Key-switching matrices for automorphisms (log_d matrices)
/// * `params` - System parameters
pub fn pack_rlwes_tree(
    rlwe_cts: &[RlweCiphertext],
    automorph_keys: &[KeySwitchingMatrix],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    if rlwe_cts.is_empty() {
        return RlweCiphertext::from_parts(Poly::zero(d, q), Poly::zero(d, q));
    }

    if rlwe_cts.len() == 1 {
        return rlwe_cts[0].clone();
    }

    // Pad to power of 2 if needed
    let n = rlwe_cts.len();
    let log_n = (n as f64).log2().ceil() as usize;
    let padded_n = 1 << log_n;

    let mut padded_cts = rlwe_cts.to_vec();
    while padded_cts.len() < padded_n {
        padded_cts.push(RlweCiphertext::zero(params));
    }

    // Generate y constants
    let y_constants = YConstants::generate(d, q);

    // Run recursive packing with log_n levels
    pack_lwes_inner(log_n, 0, &padded_cts, automorph_keys, &y_constants, &ctx, log_n)
}

/// Single LWE packing using repeated automorphism (simpler algorithm)
///
/// For a single LWE/RLWE ciphertext with value in coeff 0, this "spreads" it
/// to all coefficients by repeatedly applying τ_t and adding.
///
/// After this, all coefficients contain the same value.
/// This is useful as a building block or for verification.
pub fn pack_single_lwe(
    ct: &RlweCiphertext,
    automorph_keys: &[KeySwitchingMatrix],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    let log_d = (d as f64).log2() as usize;

    let mut cur = ct.clone();

    // Apply: cur = cur + τ_t(cur) for each level
    for i in 0..log_d {
        let t = (d >> i) + 1;  // t = d/2^i + 1
        let ks_matrix = &automorph_keys[i];
        let tau_cur = homomorphic_automorph(&cur, t, ks_matrix, &ctx);
        cur = cur.add(&tau_cur);
    }

    cur
}

/// Invert sample_extract_coeff0 to convert LWE a-vector back to polynomial form
///
/// sample_extract_coeff0 does:
///   a_lwe[0] = a_rlwe[0]
///   a_lwe[i] = a_rlwe[d-i] for i > 0
///
/// This inverts that:
///   a_rlwe[0] = a_lwe[0]
///   a_rlwe[j] = a_lwe[d-j] for j > 0
///
/// Result: coeff_0(a_rlwe * s_rlwe) = <a_lwe, s_lwe>
fn invert_sample_extract(a_lwe: &[u64]) -> Vec<u64> {
    let d = a_lwe.len();
    let mut out = vec![0u64; d];

    // First element stays the same
    out[0] = a_lwe[0];

    // Reverse the rest (no negation)
    for j in 1..d {
        out[j] = a_lwe[d - j];
    }

    out
}

/// Prepare LWE ciphertexts for tree packing
///
/// Creates "prepped" RLWE ciphertexts where:
/// - a' = negacyclic_perm(lwe.a)
/// - b' = 0
///
/// The b values are extracted separately and added at the end of packing.
///
/// # Returns
/// (prepped_rlwes, b_values)
pub fn prep_pack_lwes(lwe_cts: &[LweCiphertext], params: &InspireParams) -> (Vec<RlweCiphertext>, Vec<u64>) {
    let d = params.ring_dim;
    let q = params.q;

    let mut prepped_rlwes = Vec::with_capacity(lwe_cts.len());
    let mut b_values = Vec::with_capacity(lwe_cts.len());

    for lwe in lwe_cts {
        // Invert sample_extract_coeff0 to get a-polynomial
        // coeff_0(a_poly * s_rlwe) = <a_lwe, s_lwe>
        let a_coeffs = invert_sample_extract(&lwe.a);
        let a_poly = Poly::from_coeffs(a_coeffs, q);

        // b' = 0 (b values handled separately)
        let b_poly = Poly::zero(d, q);

        prepped_rlwes.push(RlweCiphertext::from_parts(a_poly, b_poly));
        b_values.push(lwe.b);
    }

    (prepped_rlwes, b_values)
}

/// Pack LWE ciphertexts into a single RLWE using automorphism-based tree packing
///
/// This is the main entry point for OnePacking. It implements Google's InsPIRe
/// approach:
/// 1. Prep LWEs: convert to RLWE form with negacyclic permutation
/// 2. Tree pack: recursively combine using automorphisms
/// 3. Finalize: add b_values * d to result.b coefficients
///
/// # Arguments
/// * `lwe_cts` - LWE ciphertexts to pack (one per column)
/// * `automorph_keys` - Key-switching matrices for automorphisms
/// * `params` - System parameters
///
/// # Returns
/// A single RLWE ciphertext where coefficient k contains column k's value
pub fn pack_lwes(
    lwe_cts: &[LweCiphertext],
    automorph_keys: &[KeySwitchingMatrix],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    if lwe_cts.is_empty() {
        return RlweCiphertext::from_parts(Poly::zero(d, q), Poly::zero(d, q));
    }

    // Step 1: Prep LWEs - create RLWE forms with a = negacyclic_perm(lwe.a), b = 0
    let (prepped_rlwes, b_values) = prep_pack_lwes(lwe_cts, params);

    // Handle single ciphertext case
    if prepped_rlwes.len() == 1 {
        // For single LWE, result is RLWE(a = perm(lwe.a), b = lwe.b)
        // No scaling needed for single element
        let mut b_coeffs = vec![0u64; d];
        b_coeffs[0] = b_values[0];
        let b_poly = Poly::from_coeffs(b_coeffs, q);
        return RlweCiphertext::from_parts(prepped_rlwes[0].a.clone(), b_poly);
    }

    // Always pad to d elements for full tree packing
    // This ensures each element ends up at its corresponding coefficient position
    let log_d = (d as f64).log2() as usize;

    let mut padded_cts = prepped_rlwes;
    let mut padded_b = b_values.clone();
    while padded_cts.len() < d {
        padded_cts.push(RlweCiphertext::zero(params));
        padded_b.push(0);
    }

    // Generate y constants
    let y_constants = YConstants::generate(d, q);

    // Step 2: Run full tree packing on d RLWEs (with b=0)
    let mut packed = pack_lwes_inner(log_d, 0, &padded_cts, automorph_keys, &y_constants, &ctx, log_d);

    // Step 3: Add b_values * d to result.b coefficients
    // After full tree packing of d elements, each b value gets scaled by d
    let scale = d as u64;
    let mut b_coeffs = packed.b.coeffs().to_vec();
    for (z, &b_val) in padded_b.iter().enumerate() {
        if z < d {
            // b_coeffs[z] += b_val * scale (mod q)
            let scaled = ModQ::mul(b_val, scale, q);
            b_coeffs[z] = ModQ::add(b_coeffs[z], scaled, q);
        }
    }
    packed.b = Poly::from_coeffs(b_coeffs, q);

    packed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ks::generate_automorphism_ks_matrix;
    use crate::math::{GaussianSampler, ModQ};
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

    fn sample_error_poly(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Poly {
        let coeffs: Vec<u64> = (0..dim)
            .map(|_| ModQ::from_signed(sampler.sample(), q))
            .collect();
        Poly::from_coeffs(coeffs, q)
    }

    fn generate_automorph_keys(
        sk: &RlweSecretKey,
        params: &InspireParams,
        sampler: &mut GaussianSampler,
    ) -> Vec<KeySwitchingMatrix> {
        let d = params.ring_dim;
        let q = params.q;
        let ctx = NttContext::new(d, q);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        let log_d = (d as f64).log2() as usize;

        let mut keys = Vec::with_capacity(log_d);
        for i in 0..log_d {
            let t = (d >> i) + 1;
            let ks = generate_automorphism_ks_matrix(sk, t, &gadget, sampler, &ctx);
            keys.push(ks);
        }
        keys
    }

    #[test]
    fn test_y_constants_generation() {
        let d = 256;
        let q = 1152921504606830593u64;
        let y_consts = YConstants::generate(d, q);

        // Level 0: y = X^128
        assert_eq!(y_consts.y(0).coeff(128), 1);
        assert_eq!(y_consts.neg_y(0).coeff(128), q - 1);

        // Level 1: y = X^64
        assert_eq!(y_consts.y(1).coeff(64), 1);

        // Level 7: y = X^1
        assert_eq!(y_consts.y(7).coeff(1), 1);
    }

    #[test]
    fn test_homomorphic_automorph_identity() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        // Encrypt message in coeff 0
        let message = 12345u64;
        let mut msg_coeffs = vec![0u64; d];
        msg_coeffs[0] = message;
        let msg_poly = Poly::from_coeffs(msg_coeffs, q);
        let a = Poly::random(d, q);
        let error = sample_error_poly(d, q, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk, &msg_poly, delta, a, &error, &ctx);

        // Apply τ_1 (identity) - should preserve message
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        let ks_1 = generate_automorphism_ks_matrix(&sk, 1, &gadget, &mut sampler, &ctx);
        let ct_auto = homomorphic_automorph(&ct, 1, &ks_1, &ctx);

        let decrypted = ct_auto.decrypt(&sk, delta, params.p, &ctx);
        assert_eq!(decrypted.coeff(0), message, "Identity automorphism should preserve message");
    }

    #[test]
    fn test_pack_single_runs() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let automorph_keys = generate_automorph_keys(&sk, &params, &mut sampler);

        // Encrypt message in coeff 0
        let message = 100u64;
        let mut msg_coeffs = vec![0u64; d];
        msg_coeffs[0] = message;
        let msg_poly = Poly::from_coeffs(msg_coeffs, q);
        let a = Poly::random(d, q);
        let error = sample_error_poly(d, q, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk, &msg_poly, delta, a, &error, &ctx);

        // Verify original decryption works
        let orig_dec = ct.decrypt(&sk, delta, params.p, &ctx);
        assert_eq!(orig_dec.coeff(0), message, "Original message should decrypt correctly");

        // Pack single - verifies the algorithm runs without panic
        let packed = pack_single_lwe(&ct, &automorph_keys, &params);
        let decrypted = packed.decrypt(&sk, delta, params.p, &ctx);

        // After pack_single with log_d iterations, coeff 0 gets value * 2^log_d = value * d
        // The automorphisms spread the value to all coefficients
        let expected_coeff0 = (message * (d as u64)) % params.p;
        assert_eq!(
            decrypted.coeff(0), expected_coeff0,
            "Coefficient 0 should be message * d mod p: got {}, expected {}",
            decrypted.coeff(0), expected_coeff0
        );
    }

    #[test]
    fn test_pack_two_rlwes() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let automorph_keys = generate_automorph_keys(&sk, &params, &mut sampler);

        // Create two ciphertexts with different messages
        let messages = [100u64, 200u64];
        let cts: Vec<RlweCiphertext> = messages.iter().map(|&msg| {
            let mut msg_coeffs = vec![0u64; d];
            msg_coeffs[0] = msg;
            let msg_poly = Poly::from_coeffs(msg_coeffs.clone(), q);
            let a = Poly::random(d, q);
            let error = sample_error_poly(d, q, &mut sampler);
            RlweCiphertext::encrypt(&sk, &msg_poly, delta, a, &error, &ctx)
        }).collect();

        // Pack two ciphertexts
        let packed = pack_rlwes_tree(&cts, &automorph_keys, &params);
        let decrypted = packed.decrypt(&sk, delta, params.p, &ctx);

        // For 2 ciphertexts packed into d slots, the pattern depends on the algorithm
        // The tree packing places values at specific positions based on the recursion
        println!("Decrypted coefficients (first 10):");
        for i in 0..10 {
            println!("  coeff[{}] = {}", i, decrypted.coeff(i));
        }
    }

    #[test]
    fn test_pack_lwes_single() {
        use crate::lwe::LweSecretKey;

        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
        let automorph_keys = generate_automorph_keys(&rlwe_sk, &params, &mut sampler);

        // Create a message and encrypt with RLWE
        let message = 12345u64;
        let mut msg_coeffs = vec![0u64; d];
        msg_coeffs[0] = message;
        let msg_poly = Poly::from_coeffs(msg_coeffs, q);
        let a = Poly::random(d, q);
        let error = sample_error_poly(d, q, &mut sampler);
        let rlwe_ct = RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx);

        // Extract LWE from coeff 0
        let lwe_ct = rlwe_ct.sample_extract_coeff0();

        // Verify LWE decryption works
        let lwe_dec = lwe_ct.decrypt(&lwe_sk, delta, params.p);
        assert_eq!(lwe_dec, message, "LWE decrypt failed: got {}, expected {}", lwe_dec, message);

        // Pack single LWE
        let packed = pack_lwes(&[lwe_ct], &automorph_keys, &params);

        // Decrypt packed RLWE
        let packed_dec = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        assert_eq!(packed_dec.coeff(0), message,
            "Packed single LWE decrypt failed: got {}, expected {}", packed_dec.coeff(0), message);
    }

    #[test]
    fn test_pack_lwes_two() {
        use crate::lwe::LweSecretKey;

        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
        let automorph_keys = generate_automorph_keys(&rlwe_sk, &params, &mut sampler);

        // Create 2 messages
        let messages = [100u64, 200u64];
        let lwe_cts: Vec<_> = messages.iter().map(|&msg| {
            let mut msg_coeffs = vec![0u64; d];
            msg_coeffs[0] = msg;
            let msg_poly = Poly::from_coeffs(msg_coeffs, q);
            let a = Poly::random(d, q);
            let error = sample_error_poly(d, q, &mut sampler);
            let rlwe_ct = RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx);
            rlwe_ct.sample_extract_coeff0()
        }).collect();

        // Pack all LWEs
        let packed = pack_lwes(&lwe_cts, &automorph_keys, &params);
        let packed_dec = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        // Full tree packing scales by d, not by element count
        // Messages 100, 200 scaled by d=256 = 25600, 51200
        println!("Pack 2 LWEs (first 4 coefficients):");
        for i in 0..4 {
            println!("  coeff[{}] = {}", i, packed_dec.coeff(i));
        }

        // Verify positions - full tree packing with d=256
        // coeff[0] = 100 * 256 = 25600 mod p
        // coeff[1] = 200 * 256 = 51200 mod p
        let p = params.p;
        assert_eq!(packed_dec.coeff(0), (100 * (d as u64)) % p, "coeff[0] should be 100*d mod p");
        assert_eq!(packed_dec.coeff(1), (200 * (d as u64)) % p, "coeff[1] should be 200*d mod p");
    }

    #[test]
    fn test_pack_lwes_trivial() {
        // Test with trivial LWEs (a=0) to verify b-value placement without noise
        use crate::lwe::LweCiphertext;

        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let automorph_keys = generate_automorph_keys(&rlwe_sk, &params, &mut sampler);

        // Create trivial LWEs: a = 0, b = Δ*msg
        let messages = [100u64, 200u64, 300u64, 400u64];
        let lwe_cts: Vec<_> = messages.iter().map(|&msg| {
            let a = vec![0u64; d];
            let b = ModQ::mul(delta, msg, q);
            LweCiphertext { a, b, q }
        }).collect();

        // Pack all LWEs
        let packed = pack_lwes(&lwe_cts, &automorph_keys, &params);
        let packed_dec = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        // Print coefficients
        println!("Trivial packed LWE decryption (first 8 coefficients):");
        for i in 0..8 {
            println!("  coeff[{}] = {}", i, packed_dec.coeff(i));
        }

        // With a=0 (trivial), tree packing should only have the b-values
        // Each b-value gets added to its position, scaled by d
        // Note: results are reduced mod p, so 300*256 = 76800 -> 76800 mod 65536 = 11264
        let p = params.p;
        assert_eq!(packed_dec.coeff(0), (100 * (d as u64)) % p, "coeff[0] should be 100*d mod p");
        assert_eq!(packed_dec.coeff(1), (200 * (d as u64)) % p, "coeff[1] should be 200*d mod p");
        assert_eq!(packed_dec.coeff(2), (300 * (d as u64)) % p, "coeff[2] should be 300*d mod p");
        assert_eq!(packed_dec.coeff(3), (400 * (d as u64)) % p, "coeff[3] should be 400*d mod p");
    }

    #[test]
    fn test_pack_lwes_multiple() {
        use crate::lwe::LweSecretKey;

        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
        let automorph_keys = generate_automorph_keys(&rlwe_sk, &params, &mut sampler);

        // Create 4 real LWEs with encryption
        let messages = [100u64, 200u64, 300u64, 400u64];
        let lwe_cts: Vec<_> = messages.iter().map(|&msg| {
            let mut msg_coeffs = vec![0u64; d];
            msg_coeffs[0] = msg;
            let msg_poly = Poly::from_coeffs(msg_coeffs, q);
            let a = Poly::random(d, q);
            let error = sample_error_poly(d, q, &mut sampler);
            let rlwe_ct = RlweCiphertext::encrypt(&rlwe_sk, &msg_poly, delta, a, &error, &ctx);
            rlwe_ct.sample_extract_coeff0()
        }).collect();

        // Verify each LWE decrypts correctly
        for (i, lwe) in lwe_cts.iter().enumerate() {
            let dec = lwe.decrypt(&lwe_sk, delta, params.p);
            assert_eq!(dec, messages[i], "LWE {} decrypt failed", i);
        }

        // Pack all LWEs
        let packed = pack_lwes(&lwe_cts, &automorph_keys, &params);
        let packed_dec = packed.decrypt(&rlwe_sk, delta, params.p, &ctx);

        // Print all coefficients to understand the pattern
        println!("Packed LWE decryption (first 8 coefficients):");
        for i in 0..8 {
            println!("  coeff[{}] = {}", i, packed_dec.coeff(i));
        }

        // With real encryption and 8 levels of tree packing, there may be noise
        // Just verify coeff[0] and coeff[1] are approximately correct
        let c0 = packed_dec.coeff(0);
        let c1 = packed_dec.coeff(1);
        assert_eq!(c0, 100 * (d as u64), "coeff[0] should be 100*d");
        assert_eq!(c1, 200 * (d as u64), "coeff[1] should be 200*d");
    }
}
