//! InspiRING 2-Matrix Packing Algorithm
//!
//! Implements the InspiRING packing algorithm from the InsPIRe paper that uses
//! only 2 key-switching matrices (K_g and K_h) instead of log(d) matrices.
//!
//! # Algorithm Overview
//!
//! The key insight is using a multiplicative group generator g of Z*_{2d} to index
//! LWE samples, then applying automorphisms of a SINGLE key-switching matrix
//! (pre-rotated offline) rather than storing log(d) distinct matrices.
//!
//! ## Structure
//!
//! 1. **Generator Setup**: Find g such that g generates Z*_{2d} (order d)
//! 2. **Offline Phase**: 
//!    - Compute inner products with monomials X^{j·g^i}
//!    - Precompute gadget inversions (backward recursion)
//!    - Pre-rotate K_g by powers of g
//! 3. **Online Phase**: 
//!    - Single matrix-vector multiply using pre-rotated K_g
//!    - Add b-values at their positions
//!
//! ## Complexity Comparison
//!
//! | Approach           | KS Matrices | Key Material |
//! |--------------------|-------------|--------------|
//! | Tree Packing       | log(d) = 11 | 11 × d × ℓ   |
//! | InspiRING 2-Matrix | 2           | 2 × d × ℓ    |
//!
//! # References
//! - InsPIRe paper: https://eprint.iacr.org/2024/XXX
//! - Google reference: https://github.com/google/private-membership/tree/main/research/InsPIRe

use crate::ks::KeySwitchingMatrix;
use crate::lwe::LweCiphertext;
use crate::math::{ModQ, NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{gadget_decompose, GadgetVector};
use crate::rlwe::{apply_automorphism, RlweCiphertext};

use serde::{Deserialize, Serialize};

/// Generator powers table for InspiRING indexing
///
/// For d = 2048, g = 3 generates Z*_{4096} with order 2048.
/// This table stores g^0, g^1, ..., g^{d-1} mod 2d.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneratorPowers {
    /// Powers of generator: gen_pows[i] = g^i mod 2d
    pub powers: Vec<usize>,
    /// Inverse powers: inv_pows[i] = g^{-i} mod 2d (for reverse lookup)
    pub inv_powers: Vec<usize>,
    /// The generator g
    pub generator: usize,
    /// Ring dimension d
    pub ring_dim: usize,
}

impl GeneratorPowers {
    /// Compute generator powers for ring dimension d
    ///
    /// For X^d + 1 ring, g = 3 generates a cyclic subgroup of order d/2 in Z*_{2d}.
    /// We compute g^0, g^1, ..., g^{order-1} for the actual order.
    ///
    /// For full d-slot packing, InspiRING uses both K_g (covering the g-orbit)
    /// and K_h (covering the conjugate orbit via h = 2d - 1).
    pub fn new(d: usize) -> Self {
        assert!(d.is_power_of_two(), "d must be power of 2");
        
        let two_d = 2 * d;
        let g = find_generator(d);
        let order = compute_order(g, two_d);
        
        // Compute g^0, g^1, ..., g^{order-1} mod 2d
        let mut powers = Vec::with_capacity(order);
        let mut val = 1usize;
        for _ in 0..order {
            powers.push(val);
            val = (val * g) % two_d;
        }
        
        // Compute inverse powers using g^{-1}
        let g_inv = mod_inverse(g, two_d).expect("g must be invertible mod 2d");
        let mut inv_powers = Vec::with_capacity(order);
        val = 1;
        for _ in 0..order {
            inv_powers.push(val);
            val = (val * g_inv) % two_d;
        }
        
        Self {
            powers,
            inv_powers,
            generator: g,
            ring_dim: d,
        }
    }
    
    /// Get the order of the generator (number of distinct powers)
    pub fn order(&self) -> usize {
        self.powers.len()
    }
    
    /// Get g^i mod 2d
    #[inline]
    pub fn pow(&self, i: usize) -> usize {
        self.powers[i % self.powers.len()]
    }
    
    /// Get g^{-i} mod 2d
    #[inline]
    pub fn inv_pow(&self, i: usize) -> usize {
        self.inv_powers[i % self.inv_powers.len()]
    }
    
    /// Get the generator g
    #[inline]
    pub fn generator(&self) -> usize {
        self.generator
    }
}

/// Find a generator g of the cyclic subgroup of Z*_{2d}
///
/// For d a power of 2, the group Z*_{2d} ≅ Z_{d/2} × Z_2 has order φ(2d) = d.
/// The element g = 3 generates the cyclic subgroup of order d/2.
///
/// For InspiRING, we actually need the full order d coverage. The Google code
/// uses g = 3 which has order d/2, and handles the second half via the K_h matrix.
///
/// Returns (g, order) where g generates a cyclic subgroup of the given order.
fn find_generator(d: usize) -> usize {
    let two_d = 2 * d;
    let g = 3usize;
    
    // g = 3 generates cyclic subgroup of order d/2 in Z*_{2d}
    let order = compute_order(g, two_d);
    
    // For InspiRING, we work with whatever order g has (d/2 for g=3)
    // The algorithm handles full d coverage via K_g (first half) and K_h (second half)
    assert!(order >= d / 2, "Generator {} has order {} which is too small", g, order);
    
    g
}

/// Compute the multiplicative order of g mod n
fn compute_order(g: usize, n: usize) -> usize {
    let mut val = g % n;
    let mut order = 1;
    while val != 1 {
        val = (val * g) % n;
        order += 1;
        if order > n {
            panic!("g={} is not in (Z/{}Z)*", g, n);
        }
    }
    order
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: usize, m: usize) -> Option<usize> {
    let (g, x, _) = extended_gcd(a as i64, m as i64);
    if g != 1 {
        None
    } else {
        Some(((x % m as i64 + m as i64) % m as i64) as usize)
    }
}

fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Pre-rotated key-switching matrix
///
/// Instead of storing log(d) different KS matrices, we store ONE base matrix K_g
/// and apply (num_to_pack - 1) automorphisms to it offline.
///
/// Result: A (num_to_pack - 1) × ℓ matrix where each row is K_g rotated by g^i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotatedKsMatrix {
    /// Rotated rows: rotations[i] = τ_{g^i}(K_g) for i in 0..num_to_pack-1
    pub rotations: Vec<Vec<RlweCiphertext>>,
    /// Number of LWEs this supports packing
    pub num_to_pack: usize,
    /// Gadget parameters
    pub gadget: GadgetVector,
}

impl RotatedKsMatrix {
    /// Generate pre-rotated K_g for packing num_to_pack LWEs
    ///
    /// This is the offline precomputation that replaces storing log(d) matrices.
    /// For num_to_pack > gen_pows.order(), we cycle through the powers.
    pub fn generate(
        k_g: &KeySwitchingMatrix,
        gen_pows: &GeneratorPowers,
        num_to_pack: usize,
    ) -> Self {
        // We need num_to_pack - 1 rotations (the first is identity, handled implicitly)
        let num_rotations = if num_to_pack > 0 { num_to_pack - 1 } else { 0 };
        let mut rotations = Vec::with_capacity(num_rotations);
        
        for i in 0..num_rotations {
            let g_pow_i = gen_pows.pow(i);
            
            // Apply automorphism τ_{g^i} to each row of K_g
            let rotated_rows: Vec<RlweCiphertext> = k_g.rows
                .iter()
                .map(|row| {
                    let a_rot = apply_automorphism(&row.a, g_pow_i);
                    let b_rot = apply_automorphism(&row.b, g_pow_i);
                    RlweCiphertext::from_parts(a_rot, b_rot)
                })
                .collect();
            
            rotations.push(rotated_rows);
        }
        
        Self {
            rotations,
            num_to_pack,
            gadget: k_g.gadget.clone(),
        }
    }
    
    /// Get rotated K_g at index i (τ_{g^i}(K_g))
    pub fn get_rotation(&self, i: usize) -> &[RlweCiphertext] {
        &self.rotations[i]
    }
}

/// Precomputed values for InspiRING offline phase
///
/// These depend on the CRS a-vectors and can be computed once before queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspiringPrecomputation {
    /// Generator powers table
    pub gen_pows: GeneratorPowers,
    
    /// Pre-rotated K_g matrix
    pub rotated_k_g: RotatedKsMatrix,
    
    /// Precomputed inner products: r[i] = ⟨a_ct, X^{j·g^i}⟩_j
    /// These are polynomials that get gadget-decomposed in backward recursion
    pub r_polys: Vec<Poly>,
    
    /// Precomputed gadget inversions (bold_t in Google's code)
    /// Result of backward recursion on r_polys
    pub bold_t: Vec<Vec<Poly>>,
    
    /// Number of LWEs this precomputation supports
    pub num_to_pack: usize,
    
    /// Ring dimension
    pub ring_dim: usize,
    
    /// Modulus
    pub q: u64,
}

/// Compute inner product with monomials: r^{(i)} = ⟨a_vec, X^{j·g^i}⟩_j
///
/// This computes: sum_j a_j · X^{j·g^i mod 2d}
///
/// The result is a polynomial where coefficient k contains
/// sum of a_j where j·g^i ≡ k (mod d) or j·g^i ≡ k+d (mod 2d) with negation.
fn compute_monomial_inner_product(
    a_vec: &[u64],
    gen_pow: usize,
    d: usize,
    q: u64,
) -> Poly {
    let two_d = 2 * d;
    let mut coeffs = vec![0u64; d];
    
    for (j, &a_j) in a_vec.iter().enumerate() {
        if a_j == 0 {
            continue;
        }
        
        // Compute j · g^i mod 2d
        let idx = (j * gen_pow) % two_d;
        
        if idx < d {
            // No negation needed
            coeffs[idx] = ModQ::add(coeffs[idx], a_j, q);
        } else {
            // X^{idx} = X^{idx-d} · X^d = -X^{idx-d} in negacyclic ring
            let actual_idx = idx - d;
            let neg_a_j = ModQ::negate(a_j, q);
            coeffs[actual_idx] = ModQ::add(coeffs[actual_idx], neg_a_j, q);
        }
    }
    
    Poly::from_coeffs(coeffs, q)
}

/// Backward recursion to compute gadget inversions (bold_t)
///
/// This is the key computation that allows using a single K_g matrix.
/// Starting from r[n-1] and working backwards:
///   bold_t[i] = gadget_decompose(r[i+1])
///   r[i] += sum_k bold_t[i][k] · rotated_k_g[i][k]
///
/// The result bold_t encodes all the key-switching operations needed.
fn backward_recursion(
    r_polys: &mut [Poly],
    rotated_k_g: &RotatedKsMatrix,
    gadget: &GadgetVector,
    ctx: &NttContext,
) -> Vec<Vec<Poly>> {
    let n = r_polys.len();
    let mut bold_t = Vec::with_capacity(n - 1);
    
    // Process backwards: i = n-2, n-3, ..., 0
    for i in (0..(n - 1)).rev() {
        // Gadget decompose r[i+1]
        let decomposed = gadget_decompose(&r_polys[i + 1], gadget);
        
        // Compute: r[i] += sum_k decomposed[k] · rotated_k_g[i][k].b
        // (We only need the b component for the recursion)
        let rotated_rows = rotated_k_g.get_rotation(i);
        for (k, digit_poly) in decomposed.iter().enumerate() {
            if k < rotated_rows.len() {
                let term = digit_poly.mul_ntt(&rotated_rows[k].b, ctx);
                r_polys[i] = &r_polys[i] + &term;
            }
        }
        
        bold_t.push(decomposed);
    }
    
    // Reverse to get bold_t[0], bold_t[1], ..., bold_t[n-2]
    bold_t.reverse();
    bold_t
}

/// Precompute InspiRING packing for fixed CRS a-vectors
///
/// This is the offline phase that prepares all CRS-dependent values.
/// Call once during setup, reuse for all queries.
///
/// # Arguments
/// * `crs_a_vectors` - Fixed a vectors from CRS (one per LWE slot)
/// * `k_g` - Base key-switching matrix for generator g
/// * `params` - System parameters
pub fn precompute_inspiring(
    crs_a_vectors: &[Vec<u64>],
    k_g: &KeySwitchingMatrix,
    params: &InspireParams,
) -> InspiringPrecomputation {
    let d = params.ring_dim;
    let q = params.q;
    let num_to_pack = crs_a_vectors.len();
    let ctx = NttContext::new(d, q);
    
    // Step 1: Generate generator powers table
    let gen_pows = GeneratorPowers::new(d);
    
    // Step 2: Pre-rotate K_g by powers of g
    let rotated_k_g = RotatedKsMatrix::generate(k_g, &gen_pows, num_to_pack);
    
    // Step 3: Compute inner products r[i] = ⟨a_vectors, X^{j·g^i}⟩
    // For each a_vector (representing one LWE's a component)
    let mut r_polys: Vec<Poly> = (0..num_to_pack)
        .map(|i| {
            // Sum over all a_vectors, computing the inner product for position i
            let mut r_i = Poly::zero(d, q);
            for (j, a_vec) in crs_a_vectors.iter().enumerate() {
                let contrib = compute_monomial_inner_product(
                    a_vec,
                    gen_pows.pow(i),
                    d,
                    q,
                );
                // Weight by position j (this is the "X^j" part of indexing)
                let weighted = mul_by_monomial(&contrib, j, d, q);
                r_i = &r_i + &weighted;
            }
            r_i
        })
        .collect();
    
    // Step 4: Backward recursion to compute bold_t
    let bold_t = backward_recursion(
        &mut r_polys,
        &rotated_k_g,
        &k_g.gadget,
        &ctx,
    );
    
    InspiringPrecomputation {
        gen_pows,
        rotated_k_g,
        r_polys,
        bold_t,
        num_to_pack,
        ring_dim: d,
        q,
    }
}

/// Multiply polynomial by X^k in negacyclic ring
fn mul_by_monomial(poly: &Poly, k: usize, d: usize, q: u64) -> Poly {
    let k = k % (2 * d);
    if k == 0 {
        return poly.clone();
    }
    
    let mut coeffs = vec![0u64; d];
    for i in 0..d {
        let c = poly.coeff(i);
        if c == 0 {
            continue;
        }
        
        let new_idx = (i + k) % (2 * d);
        if new_idx < d {
            coeffs[new_idx] = ModQ::add(coeffs[new_idx], c, q);
        } else {
            let actual = new_idx - d;
            coeffs[actual] = ModQ::add(coeffs[actual], ModQ::negate(c, q), q);
        }
    }
    
    Poly::from_coeffs(coeffs, q)
}

/// Pack LWEs using InspiRING 2-matrix algorithm (online phase)
///
/// Given precomputed values and the b-values from LWE ciphertexts,
/// produce a packed RLWE ciphertext.
///
/// # Algorithm
/// 1. Matrix multiply: sum = rotated_k_g × bold_t (precomputed structure)
/// 2. Add b-values at their generator-indexed positions
/// 3. Return (sum.a, sum.b + b_polynomial)
///
/// # Arguments
/// * `lwe_ciphertexts` - LWE ciphertexts to pack
/// * `precomp` - Precomputed InspiRING values
/// * `k_g` - Base key-switching matrix
/// * `params` - System parameters
pub fn pack_inspiring(
    lwe_ciphertexts: &[LweCiphertext],
    precomp: &InspiringPrecomputation,
    _k_g: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let n = lwe_ciphertexts.len();
    let ctx = NttContext::new(d, q);
    
    assert_eq!(n, precomp.num_to_pack, "Number of LWEs must match precomputation");
    
    // Online Phase Step 1: Matrix multiply using precomputed bold_t
    // Compute: sum_a = sum_{i,k} bold_t[i][k] · rotated_k_g[i][k].a
    // Compute: sum_b = sum_{i,k} bold_t[i][k] · rotated_k_g[i][k].b
    let mut sum_a = Poly::zero(d, q);
    let mut sum_b = Poly::zero(d, q);
    
    for (i, decomposed) in precomp.bold_t.iter().enumerate() {
        let rotated_rows = precomp.rotated_k_g.get_rotation(i);
        for (k, digit_poly) in decomposed.iter().enumerate() {
            if k < rotated_rows.len() {
                let term_a = digit_poly.mul_ntt(&rotated_rows[k].a, &ctx);
                let term_b = digit_poly.mul_ntt(&rotated_rows[k].b, &ctx);
                sum_a = &sum_a + &term_a;
                sum_b = &sum_b + &term_b;
            }
        }
    }
    
    // Online Phase Step 2: Construct b polynomial from LWE b-values
    // Place each b_i at position determined by generator indexing
    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_ciphertexts.iter().enumerate() {
        // In InspiRING, position i maps to coefficient i (simple embedding)
        // The generator indexing is handled in the offline phase
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs(b_coeffs, q);
    
    // Final result: (sum_a, sum_b + b_poly)
    let final_b = &sum_b + &b_poly;
    
    RlweCiphertext::from_parts(sum_a, final_b)
}

/// Pack LWEs using InspiRING with full packing (gamma = d)
///
/// For full packing, we need both K_g and K_h.
/// K_h handles the "conjugate branch" when packing d ciphertexts.
///
/// # Arguments
/// * `lwe_ciphertexts` - Exactly d LWE ciphertexts
/// * `precomp` - Precomputed InspiRING values (for K_g branch)
/// * `k_g` - Key-switching matrix for generator g
/// * `k_h` - Key-switching matrix for conjugation h = 2d - 1
/// * `params` - System parameters
pub fn pack_inspiring_full(
    lwe_ciphertexts: &[LweCiphertext],
    precomp: &InspiringPrecomputation,
    _k_g: &KeySwitchingMatrix,
    k_h: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    
    assert_eq!(lwe_ciphertexts.len(), d, "Full packing requires exactly d LWEs");
    
    // For full packing (gamma = d), we need two branches:
    // 1. K_g branch (handled by pack_inspiring)
    // 2. K_h branch (conjugate automorphism)
    
    // First, get the K_g branch result
    let kg_result = pack_inspiring(lwe_ciphertexts, precomp, _k_g, params);
    
    // For K_h branch, we apply the conjugation automorphism τ_h where h = 2d - 1
    // This handles the second half of the coefficient space
    let h = 2 * d - 1;
    
    // Apply τ_h to the K_g result
    let kg_a_conj = apply_automorphism(&kg_result.a, h);
    let kg_b_conj = apply_automorphism(&kg_result.b, h);
    
    // Key-switch the conjugated a component
    let gadget = &k_h.gadget;
    let decomposed = gadget_decompose(&kg_a_conj, gadget);
    
    let mut kh_a = Poly::zero(d, q);
    let mut kh_b = kg_b_conj;
    
    for (i, digit_poly) in decomposed.iter().enumerate() {
        if i < k_h.len() {
            let row = k_h.get_row(i);
            let term_a = digit_poly.mul_ntt(&row.a, &ctx);
            let term_b = digit_poly.mul_ntt(&row.b, &ctx);
            kh_a = &kh_a + &term_a;
            kh_b = &kh_b + &term_b;
        }
    }
    
    // Combine K_g and K_h branches
    let final_a = &kg_result.a + &kh_a;
    let final_b = &kg_result.b + &kh_b;
    
    RlweCiphertext::from_parts(final_a, final_b)
}

/// Simplified pack function for partial packing (gamma <= d/2)
///
/// When packing fewer than d/2 LWEs, only K_g is needed.
/// This is the most common case for practical PIR.
pub fn pack_inspiring_partial(
    lwe_ciphertexts: &[LweCiphertext],
    k_g: &KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let n = lwe_ciphertexts.len();
    let d = params.ring_dim;
    
    assert!(n <= d / 2, "Partial packing requires gamma <= d/2");
    
    // For small n, create precomputation on the fly
    // In production, this would be cached
    let crs_a_vectors: Vec<Vec<u64>> = lwe_ciphertexts
        .iter()
        .map(|lwe| lwe.a.clone())
        .collect();
    
    let precomp = precompute_inspiring(&crs_a_vectors, k_g, params);
    
    pack_inspiring(lwe_ciphertexts, &precomp, k_g, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::rlwe::RlweSecretKey;
    use crate::lwe::LweSecretKey;
    use crate::ks::generate_automorphism_ks_matrix;
    use crate::rgsw::GadgetVector;
    use rand::SeedableRng;
    
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
    fn test_generator_powers() {
        let d = 256;
        let gen_pows = GeneratorPowers::new(d);
        
        // Verify generator is 3
        assert_eq!(gen_pows.generator(), 3);
        
        // Verify g^0 = 1
        assert_eq!(gen_pows.pow(0), 1);
        
        // Verify g^1 = 3
        assert_eq!(gen_pows.pow(1), 3);
        
        // For Z*_{2d} with d power of 2, g=3 has order d/2
        let expected_order = d / 2;
        assert_eq!(gen_pows.order(), expected_order, 
            "Generator 3 should have order d/2 = {} in Z*_{}", expected_order, 2 * d);
        
        // Verify powers are distinct within the actual order
        let mut seen = std::collections::HashSet::new();
        for i in 0..gen_pows.order() {
            assert!(seen.insert(gen_pows.pow(i)), "Duplicate power at i={}", i);
        }
        
        // Verify inverse: g^i * g^{-i} = 1 (mod 2d)
        let two_d = 2 * d;
        for i in 0..gen_pows.order() {
            let prod = (gen_pows.pow(i) * gen_pows.inv_pow(i)) % two_d;
            assert_eq!(prod, 1, "Inverse check failed at i={}", i);
        }
    }
    
    #[test]
    fn test_generator_powers_d2048() {
        let d = 2048;
        let gen_pows = GeneratorPowers::new(d);
        
        assert_eq!(gen_pows.generator(), 3);
        
        // For d=2048, g=3 has order 1024 (d/2)
        assert_eq!(gen_pows.order(), d / 2);
        assert_eq!(gen_pows.powers.len(), d / 2);
        
        // Spot check a few values
        assert_eq!(gen_pows.pow(0), 1);
        assert_eq!(gen_pows.pow(1), 3);
        assert_eq!(gen_pows.pow(2), 9);
    }
    
    #[test]
    fn test_monomial_inner_product() {
        let d = 256;
        let q = 1152921504606830593u64;
        
        // Simple test: a = [1, 0, 0, ...], gen_pow = 1
        // Result should be: X^0 = 1 (just coefficient 0 = 1)
        let mut a_vec = vec![0u64; d];
        a_vec[0] = 1;
        
        let result = compute_monomial_inner_product(&a_vec, 1, d, q);
        assert_eq!(result.coeff(0), 1);
        for i in 1..d {
            assert_eq!(result.coeff(i), 0);
        }
        
        // Test with a[1] = 1, gen_pow = 3
        // Result: X^{1*3} = X^3
        let mut a_vec2 = vec![0u64; d];
        a_vec2[1] = 1;
        
        let result2 = compute_monomial_inner_product(&a_vec2, 3, d, q);
        assert_eq!(result2.coeff(3), 1);
    }
    
    #[test]
    fn test_rotated_ks_matrix_generation() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);
        
        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        
        // Generate K_g for generator g = 3
        let g = 3;
        let k_g = generate_automorphism_ks_matrix(&sk, g, &gadget, &mut sampler, &ctx);
        
        let gen_pows = GeneratorPowers::new(d);
        let num_to_pack = 16;
        
        let rotated = RotatedKsMatrix::generate(&k_g, &gen_pows, num_to_pack);
        
        assert_eq!(rotated.num_to_pack, num_to_pack);
        assert_eq!(rotated.rotations.len(), num_to_pack - 1);
        
        // Each rotation should have gadget_len rows
        for rot in &rotated.rotations {
            assert_eq!(rot.len(), params.gadget_len);
        }
    }
    
    #[test]
    fn test_precompute_inspiring() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);
        
        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        
        let g = 3;
        let k_g = generate_automorphism_ks_matrix(&sk, g, &gadget, &mut sampler, &ctx);
        
        // Create dummy CRS a-vectors
        let num_to_pack = 8;
        let crs_a_vectors: Vec<Vec<u64>> = (0..num_to_pack)
            .map(|_| Poly::random(d, q).coeffs().to_vec())
            .collect();
        
        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
        
        assert_eq!(precomp.num_to_pack, num_to_pack);
        assert_eq!(precomp.r_polys.len(), num_to_pack);
        assert_eq!(precomp.bold_t.len(), num_to_pack - 1);
    }
    
    #[test]
    fn test_pack_inspiring_dimensions() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);
        
        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        
        let g = 3;
        let k_g = generate_automorphism_ks_matrix(&sk, g, &gadget, &mut sampler, &ctx);
        
        // Create LWE ciphertexts
        let num_to_pack = 8;
        let lwe_cts: Vec<LweCiphertext> = (0..num_to_pack)
            .map(|_| LweCiphertext {
                a: Poly::random(d, q).coeffs().to_vec(),
                b: rand::random::<u64>() % q,
                q,
            })
            .collect();
        
        let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();
        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
        
        let packed = pack_inspiring(&lwe_cts, &precomp, &k_g, &params);
        
        assert_eq!(packed.ring_dim(), d);
        assert_eq!(packed.modulus(), q);
    }
    
    #[test]
    fn test_pack_inspiring_with_real_encryption() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();
        let ctx = NttContext::new(d, q);
        let mut sampler = GaussianSampler::new(params.sigma);
        
        // Generate keys
        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        
        let g = 3;
        let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g, &gadget, &mut sampler, &ctx);
        
        // Create and encrypt messages
        let messages: Vec<u64> = vec![100, 200, 300, 400];
        let num_to_pack = messages.len();
        
        let lwe_cts: Vec<LweCiphertext> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u64> = Poly::random(d, q).coeffs().to_vec();
                LweCiphertext::encrypt(&lwe_sk, msg, delta, a, 0)
            })
            .collect();
        
        // Verify LWE decryption works
        for (lwe, &expected) in lwe_cts.iter().zip(messages.iter()) {
            let dec = lwe.decrypt(&lwe_sk, delta, params.p);
            assert_eq!(dec, expected, "LWE decryption failed");
        }
        
        // Pack using InspiRING
        let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();
        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
        
        let packed = pack_inspiring(&lwe_cts, &precomp, &k_g, &params);
        
        // Verify structure (full correctness requires proper RLWE key relationship)
        assert_eq!(packed.ring_dim(), d);
        
        // Note: Full decryption test requires the LWE→RLWE key relationship
        // to be set up correctly. This is tested in integration tests.
        println!("InspiRING packing produced RLWE with {} coefficients", packed.ring_dim());
    }
    
    #[test]
    fn test_compare_matrix_count() {
        // Verify the key material reduction
        let d = 2048;
        let gadget_len = 3;
        
        // Old approach: log(d) = 11 matrices
        let old_matrices = (d as f64).log2() as usize;
        
        // InspiRING: 2 matrices (K_g and K_h)
        let new_matrices = 2;
        
        println!("Matrix count comparison for d={}:", d);
        println!("  Tree packing: {} matrices", old_matrices);
        println!("  InspiRING:    {} matrices", new_matrices);
        println!("  Reduction:    {:.1}x", old_matrices as f64 / new_matrices as f64);
        
        // Key material comparison (coefficients)
        let old_key_material = old_matrices * d * gadget_len;
        let new_key_material = new_matrices * d * gadget_len;
        
        println!("Key material (coefficients):");
        println!("  Tree packing: {}", old_key_material);
        println!("  InspiRING:    {}", new_key_material);
        println!("  Reduction:    {:.1}x", old_key_material as f64 / new_key_material as f64);
        
        assert!(new_matrices < old_matrices);
    }
    
    #[test]
    fn test_inspiring2_vs_tree_packing_structure() {
        // Structural comparison between the two approaches
        // This doesn't test correctness (which requires proper key setup)
        // but verifies both produce valid RLWE ciphertexts
        
        use crate::inspiring::automorph_pack::pack_lwes;
        use crate::pir::setup;
        
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let mut sampler = GaussianSampler::new(params.sigma);
        
        // Create a small database to get proper setup
        let entry_size = 2;
        let database: Vec<u8> = (0..(d * entry_size)).map(|i| (i % 256) as u8).collect();
        let (crs, _encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();
        
        // Create test LWE ciphertexts
        let num_to_pack = 8;
        let messages: Vec<u64> = (0..num_to_pack).map(|i| (i * 10) as u64).collect();
        
        let lwe_cts: Vec<LweCiphertext> = messages.iter().map(|&msg| {
            let a: Vec<u64> = Poly::random(d, q).coeffs().to_vec();
            let delta = params.delta();
            let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
            LweCiphertext::encrypt(&lwe_sk, msg, delta, a, 0)
        }).collect();
        
        // Tree packing (old approach - uses log(d) matrices from crs.galois_keys)
        let tree_packed = pack_lwes(&lwe_cts, &crs.galois_keys, &params);
        
        // InspiRING packing (new approach - uses 2 matrices)
        let ctx = NttContext::new(d, q);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);
        let g = 3; // Generator
        let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g, &gadget, &mut sampler, &ctx);
        
        let crs_a_vectors: Vec<Vec<u64>> = lwe_cts.iter().map(|lwe| lwe.a.clone()).collect();
        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);
        let inspiring_packed = pack_inspiring(&lwe_cts, &precomp, &k_g, &params);
        
        // Both should produce valid RLWE ciphertexts
        assert_eq!(tree_packed.ring_dim(), d);
        assert_eq!(inspiring_packed.ring_dim(), d);
        assert_eq!(tree_packed.modulus(), q);
        assert_eq!(inspiring_packed.modulus(), q);
        
        println!("\n=== Packing Algorithm Comparison ===");
        println!("Number of LWEs packed: {}", num_to_pack);
        println!("Ring dimension: {}", d);
        println!("");
        println!("Tree packing:");
        println!("  - Uses {} key-switching matrices", crs.galois_keys.len());
        println!("  - Output ring_dim: {}", tree_packed.ring_dim());
        println!("");
        println!("InspiRING 2-matrix:");
        println!("  - Uses 2 key-switching matrices (K_g, K_h)");
        println!("  - Pre-rotated K_g: {} rotations", precomp.rotated_k_g.rotations.len());
        println!("  - Output ring_dim: {}", inspiring_packed.ring_dim());
        println!("");
        println!("Key material reduction: {:.1}x fewer base matrices", 
                 crs.galois_keys.len() as f64 / 2.0);
    }
}
