//! InspiRING 2-Matrix Packing Algorithm (Canonical Implementation)
//!
//! This is a faithful port of Google's reference implementation from:
//! https://github.com/google/private-membership/tree/main/research/InsPIRe
//!
//! # Algorithm Overview
//!
//! The InspiRING algorithm packs γ LWE ciphertexts into a single RLWE ciphertext
//! using only 2 key-switching matrices (K_g and K_h) instead of log(d) matrices.
//!
//! ## Key Insight
//!
//! Uses a multiplicative group generator g of Z*_{2d} to index LWE samples,
//! then applies automorphisms and a backward recursion to precompute most work offline.
//!
//! ## Client/Server Key Separation
//!
//! The InspiRING algorithm separates keys between client and server:
//!
//! - **Shared**: `w_seed` - random seed stored in CRS (public)
//! - **Server offline**: `w_mask` = expand(w_seed), `w_all` = rotations of w_mask
//!   Used in `packing_offline()` to compute `a_hat` and `bold_t`
//! - **Client query**: `y_body` = τ_g(s)·G - s·w_mask + error (requires secret key)
//!   `y_all` = rotations of y_body, sent with query
//! - **Server online**: Uses client's `y_all` with precomputed `bold_t`
//!
//! ## Offline/Online Separation
//!
//! - **Offline**: Compute R[i] inner products, apply automorphisms, backward recursion → a_hat, bold_t
//! - **Online**: Compute y_all × bold_t + b_poly → packed ciphertext
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

use crate::lwe::LweCiphertext;
use crate::math::{GaussianSampler, NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{gadget_decompose, GadgetVector};
use crate::rlwe::{apply_automorphism, RlweCiphertext, RlweSecretKey};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Packing parameters for InspiRING algorithm
///
/// Equivalent to Google's `PackParams` struct.
///
/// **Performance optimizations** (matching Google):
/// - Monomials stored in NTT form for O(n) multiply
/// - Automorphism tables for O(n) NTT-domain automorphisms
/// - Shared NttContext to avoid recreation
/// - mod_inv as polynomial for NTT-domain scalar multiply
#[derive(Clone, Debug)]
pub struct PackParams {
    /// Number of items to pack (γ)
    pub num_to_pack: usize,
    /// Ring dimension (n or d)
    pub ring_dim: usize,
    /// Modulus q
    pub q: u64,
    /// CRT moduli (length 1 for single-modulus mode)
    pub moduli: Vec<u64>,
    /// Generator for the multiplicative group
    pub generator: usize,
    /// Powers of generator: gen_pows[i] = g^i mod 2n
    pub gen_pows: Vec<usize>,
    /// Modular inverse of γ: 1/γ mod q (scalar form)
    pub mod_inv_gamma: u64,
    /// Modular inverse as polynomial in NTT form (for fast scalar multiply)
    pub mod_inv_poly_ntt: Poly,
    /// Precomputed monomials X^j in coefficient form (for inner products)
    pub monomials: Vec<Poly>,
    /// Precomputed negative monomials -X^j
    pub neg_monomials: Vec<Poly>,
    /// Precomputed monomials in NTT form (for fast multiplication)
    pub monomials_ntt: Vec<Poly>,
    /// Precomputed negative monomials in NTT form
    pub neg_monomials_ntt: Vec<Poly>,
    /// Gadget parameters
    pub gadget: GadgetVector,
    /// Automorphism tables for NTT-domain automorphisms
    /// tables[t_idx] maps NTT index i → source index for automorphism τ_t
    /// where t_idx = (t - 1) / 2 for odd t in [1, 2n)
    pub automorph_tables: Vec<Vec<usize>>,
}

impl PackParams {
    /// Create packing parameters for γ items
    ///
    /// Generator formula from Google reference:
    /// - If γ < n: gen = 2n/γ + 1
    /// - If γ = n: gen = 5
    ///
    /// **Performance optimizations** (matching Google):
    /// - Precomputes monomials in both coefficient and NTT form
    /// - Generates automorphism tables for O(n) NTT-domain automorphisms
    /// - Creates mod_inv polynomial for fast NTT-domain scalar multiply
    pub fn new(params: &InspireParams, num_to_pack: usize) -> Self {
        let n = params.ring_dim;
        let q = params.q;
        let moduli = params.moduli().to_vec();
        let two_n = 2 * n;
        let ctx = params.ntt_context();

        // Generator selection (canonical formula)
        let generator = if num_to_pack < n {
            (two_n / num_to_pack) + 1
        } else {
            5
        };

        // Compute generator powers: g^0, g^1, ..., g^{n-1} mod 2n
        let mut gen_pows = Vec::with_capacity(n);
        let mut val = 1usize;
        for _ in 0..n {
            gen_pows.push(val);
            val = (val * generator) % two_n;
        }

        // Modular inverse of γ (scalar and polynomial forms)
        let mod_inv_gamma =
            mod_inverse_u64(num_to_pack as u64, q).expect("num_to_pack must be invertible mod q");

        // mod_inv as constant polynomial in NTT form for fast scalar multiply
        let mut mod_inv_poly_ntt = Poly::constant_moduli(mod_inv_gamma, n, &moduli);
        mod_inv_poly_ntt.to_ntt(&ctx);

        // Precompute monomials in both coefficient and NTT form
        let mut monomials = Vec::with_capacity(n);
        let mut neg_monomials = Vec::with_capacity(n);
        let mut monomials_ntt = Vec::with_capacity(n);
        let mut neg_monomials_ntt = Vec::with_capacity(n);

        for j in 0..n {
            let mut coeffs = vec![0u64; n];
            coeffs[j] = 1;
            let mono = Poly::from_coeffs_moduli(coeffs.clone(), &moduli);
            let mut mono_ntt = mono.clone();
            mono_ntt.to_ntt(&ctx);
            monomials.push(mono);
            monomials_ntt.push(mono_ntt);

            coeffs[j] = q - 1; // -1 mod q
            let neg_mono = Poly::from_coeffs_moduli(coeffs, &moduli);
            let mut neg_mono_ntt = neg_mono.clone();
            neg_mono_ntt.to_ntt(&ctx);
            neg_monomials.push(neg_mono);
            neg_monomials_ntt.push(neg_mono_ntt);
        }

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

        // Generate automorphism tables for NTT-domain automorphisms
        // Following Google's generate_automorph_tables_brute_force approach
        let automorph_tables = generate_automorph_tables(n, &moduli, &ctx);

        Self {
            num_to_pack,
            ring_dim: n,
            q,
            moduli,
            generator,
            gen_pows,
            mod_inv_gamma,
            mod_inv_poly_ntt,
            monomials,
            neg_monomials,
            monomials_ntt,
            neg_monomials_ntt,
            gadget,
            automorph_tables,
        }
    }

    /// Get the table index for automorphism τ_t
    ///
    /// For odd t in [1, 2n), the table index is (t - 1) / 2
    #[inline]
    pub fn table_index(&self, t: usize) -> usize {
        debug_assert!(t % 2 == 1, "Automorphism index must be odd");
        (t - 1) / 2
    }

    /// Get the automorphism table for τ_t
    #[inline]
    pub fn get_automorph_table(&self, t: usize) -> &[usize] {
        &self.automorph_tables[self.table_index(t)]
    }
}

/// Generate automorphism tables for NTT-domain automorphisms
///
/// Equivalent to Google's `generate_automorph_tables_brute_force`.
///
/// For each odd automorphism index t in [1, 2n), computes a permutation table
/// such that: NTT(τ_t(poly))[i] = NTT(poly)[table[i]]
///
/// This allows O(n) automorphism in NTT domain via index permutation.
fn generate_automorph_tables(n: usize, moduli: &[u64], ctx: &NttContext) -> Vec<Vec<usize>> {
    let two_n = 2 * n;
    let mut tables = Vec::with_capacity(n);

    // For each odd t in [1, 2n)
    for t in (1..two_n).step_by(2) {
        let mut table = vec![0usize; n];

        // Use brute-force approach like Google: find NTT index mapping
        // by comparing NTT of random poly vs NTT of automorphed poly
        loop {
            // Generate random polynomial
            let poly = Poly::random_moduli(n, moduli);
            let mut poly_ntt = poly.clone();
            poly_ntt.to_ntt(ctx);

            // Apply automorphism in coefficient domain
            let poly_auto = apply_automorphism(&poly, t);
            let mut poly_auto_ntt = poly_auto.clone();
            poly_auto_ntt.to_ntt(ctx);

            let mut must_redo = false;

            // Find the permutation: for each position i in original NTT,
            // find where it maps to in automorphed NTT
            for i in 0..n {
                let orig_val = poly_ntt.coeffs()[i];
                let mut found = None;
                let mut count = 0;

                for j in 0..n {
                    if poly_auto_ntt.coeffs()[j] == orig_val {
                        count += 1;
                        found = Some(j);
                    }
                }

                if count != 1 {
                    must_redo = true;
                    break;
                }

                // table[j] = i means: to get automorphed[j], read from original[i]
                table[found.unwrap()] = i;
            }

            if !must_redo {
                break;
            }
        }

        tables.push(table);
    }

    tables
}

/// Apply automorphism τ_t in NTT domain using precomputed tables
///
/// Equivalent to Google's `apply_automorph_ntt_raw`.
///
/// **Performance**: O(n) index permutation instead of O(n log n) NTT conversion.
///
/// # Arguments
/// * `poly_ntt` - Polynomial in NTT domain
/// * `table` - Precomputed permutation table for τ_t
/// * `q` - Modulus
///
/// # Returns
/// The automorphed polynomial in NTT domain
#[inline]
pub fn apply_automorphism_ntt(poly_ntt: &Poly, table: &[usize]) -> Poly {
    debug_assert!(poly_ntt.is_ntt(), "Polynomial must be in NTT domain");
    let n = poly_ntt.dimension();
    let moduli = poly_ntt.moduli();

    let mut result_coeffs = vec![0u64; n];
    let src = poly_ntt.coeffs();

    // Apply permutation: result[i] = poly[table[i]]
    for i in 0..n {
        result_coeffs[i] = src[table[i]];
    }

    let mut result = Poly::from_coeffs_moduli(result_coeffs, moduli);
    // Mark as NTT domain (from_coeffs sets is_ntt = false)
    result.force_ntt_domain();
    result
}

/// Apply automorphism τ_t in NTT domain, writing result into output buffer
///
/// Equivalent to Google's `apply_automorph_ntt_raw` with output parameter.
///
/// **Performance**: O(n) with no allocation when output is pre-allocated.
#[inline]
pub fn apply_automorphism_ntt_into(poly_ntt: &Poly, table: &[usize], out: &mut Poly) {
    debug_assert!(poly_ntt.is_ntt(), "Input must be in NTT domain");
    debug_assert!(out.is_ntt(), "Output must be in NTT domain");

    let n = poly_ntt.dimension();
    let src = poly_ntt.coeffs();
    let dst = out.coeffs_mut();

    // Apply permutation: out[i] = poly[table[i]]
    for i in 0..n {
        dst[i] = src[table[i]];
    }
}

/// Apply automorphism τ_t and its conjugate τ_{2n-t} simultaneously
///
/// Equivalent to Google's `apply_automorph_ntt_double`.
///
/// **Performance**: Single pass over input for both outputs.
#[inline]
pub fn apply_automorphism_ntt_double(
    poly_ntt: &Poly,
    table_pos: &[usize],
    table_neg: &[usize],
) -> (Poly, Poly) {
    debug_assert!(poly_ntt.is_ntt(), "Polynomial must be in NTT domain");
    let n = poly_ntt.dimension();
    let moduli = poly_ntt.moduli();

    let mut result_pos = vec![0u64; n];
    let mut result_neg = vec![0u64; n];
    let src = poly_ntt.coeffs();

    for i in 0..n {
        result_pos[i] = src[table_pos[i]];
        result_neg[i] = src[table_neg[i]];
    }

    let mut poly_pos = Poly::from_coeffs_moduli(result_pos, moduli);
    let mut poly_neg = Poly::from_coeffs_moduli(result_neg, moduli);
    poly_pos.force_ntt_domain();
    poly_neg.force_ntt_domain();

    (poly_pos, poly_neg)
}

/// Precomputed values from offline phase
///
/// Equivalent to Google's `PrecompInsPIR` struct.
///
/// Google stores `bold_t_condensed` which packs two CRT components into one u64.
/// We store bold_t in both coefficient and NTT form for maximum flexibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecompInsPIR {
    /// a_hat = R[0] after backward recursion (the 'a' component of packed ciphertext)
    pub a_hat: Poly,
    /// bold_t: gadget-decomposed R[i+1] values, shape (γ-1) × gadget_len (coefficient form)
    pub bold_t: Vec<Vec<Poly>>,
    /// bold_t in NTT form for O(n) multiply in online phase
    #[serde(skip)] // Skip serialization - regenerate from bold_t
    pub bold_t_ntt: Vec<Vec<Poly>>,
    /// For full packing: conjugate branch T̄
    pub bold_t_bar: Vec<Vec<Poly>>,
    /// For full packing: final gadget T̂
    pub bold_t_hat: Vec<Poly>,
    /// Number of items packed
    pub num_to_pack: usize,
    /// Ring dimension
    pub ring_dim: usize,
    /// Modulus
    pub q: u64,
}

impl PrecompInsPIR {
    /// Get the total number of polynomial multiplications in online phase
    ///
    /// Google formula: (γ-1) × gadget_len multiplications
    pub fn online_mult_count(&self) -> usize {
        if self.bold_t.is_empty() {
            0
        } else {
            self.bold_t.len() * self.bold_t[0].len()
        }
    }

    /// Ensure bold_t_ntt is populated (regenerate from bold_t if needed)
    pub fn ensure_ntt_cached(&mut self, ctx: &NttContext) {
        if self.bold_t_ntt.is_empty() && !self.bold_t.is_empty() {
            self.bold_t_ntt = self
                .bold_t
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|p| {
                            let mut pn = p.clone();
                            pn.to_ntt(ctx);
                            pn
                        })
                        .collect()
                })
                .collect();
        }
    }
}

/// Offline packing keys (server-side precomputation)
///
/// Stores the w_mask and its rotations w_all, derived from w_seed.
/// Used in packing_offline() to compute a_hat and bold_t.
///
/// Equivalent to Google's `OfflinePackingKeys` struct.
///
/// **Performance**: Stores w_all in NTT form for O(n) multiply-accumulate
/// in the backward recursion phase.
#[derive(Clone, Debug)]
pub struct OfflinePackingKeys {
    /// Seed for generating w_mask (32 bytes, shared in CRS)
    pub w_seed: [u8; 32],
    /// Seed for generating v_mask (32 bytes, for full packing)
    pub v_seed: [u8; 32],
    /// w_mask: random matrix expanded from w_seed (gadget_len polynomials)
    pub w_mask: Vec<Poly>,
    /// v_mask: random matrix for conjugation (full packing only)
    pub v_mask: Vec<Poly>,
    /// w_all[i] = τ_{g^i}(w_mask) - rotations of w_mask (coefficient form)
    pub w_all: Vec<Vec<Poly>>,
    /// w_all in NTT form for fast multiplication
    pub w_all_ntt: Vec<Vec<Poly>>,
    /// w_bar_all[i] = τ_{2n-g^i}(w_mask) - negative rotations (full packing)
    pub w_bar_all: Vec<Vec<Poly>>,
    /// w_bar_all in NTT form
    pub w_bar_all_ntt: Vec<Vec<Poly>>,
    /// Whether this is for full packing (γ = n)
    pub full_key: bool,
}

impl OfflinePackingKeys {
    /// Generate offline packing keys from a random seed
    ///
    /// For partial packing (γ < n).
    ///
    /// **Performance optimizations** (matching Google):
    /// - Uses NTT-domain automorphisms via lookup tables: O(n) vs O(n log n)
    /// - Generates w_all directly in NTT form
    pub fn generate(pack_params: &PackParams, w_seed: [u8; 32]) -> Self {
        let n = pack_params.ring_dim;
        let q = pack_params.q;
        let num_to_pack = pack_params.num_to_pack;
        let gadget_len = pack_params.gadget.len;
        let ctx = NttContext::with_moduli(n, &pack_params.moduli);

        // Generate w_mask from seed and convert to NTT form
        let w_mask = generate_mask_from_seed(w_seed, n, q, &pack_params.moduli, gadget_len);
        let w_mask_ntt: Vec<Poly> = w_mask
            .iter()
            .map(|p| {
                let mut pn = p.clone();
                pn.to_ntt(&ctx);
                pn
            })
            .collect();

        // Generate rotations using NTT-domain automorphisms: O(n) per rotation
        // w_all[i] = τ_{g^i}(w_mask)
        let mut w_all = Vec::with_capacity(num_to_pack - 1);
        let mut w_all_ntt = Vec::with_capacity(num_to_pack - 1);

        for i in 0..(num_to_pack - 1) {
            let g_pow_i = pack_params.gen_pows[i];
            let table = pack_params.get_automorph_table(g_pow_i);

            // Apply automorphism in NTT domain: O(n) per polynomial
            let rotated_ntt: Vec<Poly> = w_mask_ntt
                .iter()
                .map(|poly_ntt| apply_automorphism_ntt(poly_ntt, table))
                .collect();

            // Also keep coefficient form for gadget decomposition
            let rotated: Vec<Poly> = rotated_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();

            w_all.push(rotated);
            w_all_ntt.push(rotated_ntt);
        }

        Self {
            w_seed,
            v_seed: [0u8; 32],
            w_mask,
            v_mask: vec![],
            w_all,
            w_all_ntt,
            w_bar_all: vec![],
            w_bar_all_ntt: vec![],
            full_key: false,
        }
    }

    /// Generate offline packing keys for full packing (γ = n)
    ///
    /// **Performance optimizations** (matching Google):
    /// - Uses NTT-domain automorphisms via lookup tables: O(n) vs O(n log n)
    /// - Uses apply_automorphism_ntt_double for simultaneous pos/neg rotations
    pub fn generate_full(pack_params: &PackParams, w_seed: [u8; 32], v_seed: [u8; 32]) -> Self {
        let n = pack_params.ring_dim;
        let q = pack_params.q;
        let num_to_pack_half = n / 2;
        let two_n = 2 * n;
        let gadget_len = pack_params.gadget.len;
        let ctx = NttContext::with_moduli(n, &pack_params.moduli);

        // Generate masks from seeds and convert to NTT
        let w_mask = generate_mask_from_seed(w_seed, n, q, &pack_params.moduli, gadget_len);
        let v_mask = generate_mask_from_seed(v_seed, n, q, &pack_params.moduli, gadget_len);

        let w_mask_ntt: Vec<Poly> = w_mask
            .iter()
            .map(|p| {
                let mut pn = p.clone();
                pn.to_ntt(&ctx);
                pn
            })
            .collect();

        // Generate both w_all and w_bar_all using NTT-domain double automorphism
        let mut w_all = Vec::with_capacity(num_to_pack_half - 1);
        let mut w_all_ntt = Vec::with_capacity(num_to_pack_half - 1);
        let mut w_bar_all = Vec::with_capacity(num_to_pack_half - 1);
        let mut w_bar_all_ntt = Vec::with_capacity(num_to_pack_half - 1);

        for i in 0..(num_to_pack_half - 1) {
            let g_pow_i = pack_params.gen_pows[i];
            let neg_g_pow_i = (two_n - g_pow_i) % two_n;

            let table_pos = pack_params.get_automorph_table(g_pow_i);
            let table_neg = pack_params.get_automorph_table(neg_g_pow_i);

            // Apply both automorphisms simultaneously in NTT domain
            let mut rotated_ntt = Vec::with_capacity(gadget_len);
            let mut rotated_bar_ntt = Vec::with_capacity(gadget_len);

            for poly_ntt in &w_mask_ntt {
                let (pos, neg) = apply_automorphism_ntt_double(poly_ntt, table_pos, table_neg);
                rotated_ntt.push(pos);
                rotated_bar_ntt.push(neg);
            }

            // Convert to coefficient form
            let rotated: Vec<Poly> = rotated_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();
            let rotated_bar: Vec<Poly> = rotated_bar_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();

            w_all.push(rotated);
            w_all_ntt.push(rotated_ntt);
            w_bar_all.push(rotated_bar);
            w_bar_all_ntt.push(rotated_bar_ntt);
        }

        Self {
            w_seed,
            v_seed,
            w_mask,
            v_mask,
            w_all,
            w_all_ntt,
            w_bar_all,
            w_bar_all_ntt,
            full_key: true,
        }
    }
}

/// Client packing keys (sent with query)
///
/// Contains y_body computed from secret key and w_mask.
/// y_body = τ_g(s)·G - s·w_mask + error
///
/// Equivalent to Google's `PackingKeys` struct.
///
/// **Performance**: Stores y_all in NTT form for O(n) multiply in online phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientPackingKeys {
    /// y_body: key-switching body for generator g
    /// y_body[k] = τ_g(s)·g^k - s·w_mask[k] + error
    pub y_body: Vec<Poly>,
    /// z_body: key-switching body for conjugation h (full packing only)
    pub z_body: Vec<Poly>,
    /// Pre-rotated y_all = [τ_{g^0}(y_body), τ_{g^1}(y_body), ...] (coefficient form)
    /// This is what gets used in packing_online()
    pub y_all: Vec<Vec<Poly>>,
    /// y_all in NTT form for fast multiplication
    pub y_all_ntt: Vec<Vec<Poly>>,
    /// y_bar_all for full packing (coefficient form)
    pub y_bar_all: Vec<Vec<Poly>>,
    /// y_bar_all in NTT form
    pub y_bar_all_ntt: Vec<Vec<Poly>>,
    /// Whether this is for full packing
    pub full_key: bool,
    /// Number of items to pack
    pub num_to_pack: usize,
}

impl ClientPackingKeys {
    /// Generate client packing keys from secret key and w_seed
    ///
    /// This is called by the client during query generation.
    ///
    /// Following Google's reference: uses gen_pows[1] (= g^1 = generator) for y_body.
    ///
    /// **Performance optimizations** (matching Google):
    /// - Uses NTT-domain automorphisms via lookup tables: O(n) vs O(n log n)
    /// - Generates y_all directly in NTT form
    pub fn generate(
        sk: &RlweSecretKey,
        pack_params: &PackParams,
        w_seed: [u8; 32],
        sampler: &mut GaussianSampler,
    ) -> Self {
        let n = pack_params.ring_dim;
        let q = pack_params.q;
        let num_to_pack = pack_params.num_to_pack;
        let gadget_len = pack_params.gadget.len;
        let ctx = NttContext::with_moduli(n, &pack_params.moduli);

        // Regenerate w_mask from seed (same as server did)
        let w_mask = generate_mask_from_seed(w_seed, n, q, &pack_params.moduli, gadget_len);

        // Generate y_body = τ_g(s)·G - s·w_mask + error
        // Google uses gen_pows[1] which equals generator (g^1)
        let gen = pack_params.gen_pows[1];
        let y_body = generate_ksk_body(sk, gen, &pack_params.gadget, &w_mask, sampler, &ctx);

        // Convert y_body to NTT form for fast rotations
        let y_body_ntt: Vec<Poly> = y_body
            .iter()
            .map(|p| {
                let mut pn = p.clone();
                pn.to_ntt(&ctx);
                pn
            })
            .collect();

        // Generate rotations using NTT-domain automorphisms: O(n) per rotation
        let mut y_all = Vec::with_capacity(num_to_pack - 1);
        let mut y_all_ntt = Vec::with_capacity(num_to_pack - 1);
        for i in 0..(num_to_pack - 1) {
            let g_pow_i = pack_params.gen_pows[i];
            let table = pack_params.get_automorph_table(g_pow_i);

            // Apply automorphism in NTT domain: O(n) per polynomial
            let rotated_ntt: Vec<Poly> = y_body_ntt
                .iter()
                .map(|poly_ntt| apply_automorphism_ntt(poly_ntt, table))
                .collect();

            // Keep coefficient form for compatibility
            let rotated: Vec<Poly> = rotated_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();

            y_all.push(rotated);
            y_all_ntt.push(rotated_ntt);
        }

        Self {
            y_body,
            z_body: vec![],
            y_all,
            y_all_ntt,
            y_bar_all: vec![],
            y_bar_all_ntt: vec![],
            full_key: false,
            num_to_pack,
        }
    }

    /// Generate client packing keys for full packing (γ = n)
    ///
    /// Following Google's reference: uses gen_pows[1] for y_body, (2n-1) for z_body.
    ///
    /// **Performance**: Precomputes y_all and y_bar_all in both forms.
    pub fn generate_full(
        sk: &RlweSecretKey,
        pack_params: &PackParams,
        w_seed: [u8; 32],
        v_seed: [u8; 32],
        sampler: &mut GaussianSampler,
    ) -> Self {
        let n = pack_params.ring_dim;
        let q = pack_params.q;
        let num_to_pack_half = n / 2;
        let two_n = 2 * n;
        let gadget_len = pack_params.gadget.len;
        let ctx = NttContext::with_moduli(n, &pack_params.moduli);

        // Regenerate masks from seeds
        let w_mask = generate_mask_from_seed(w_seed, n, q, &pack_params.moduli, gadget_len);
        let v_mask = generate_mask_from_seed(v_seed, n, q, &pack_params.moduli, gadget_len);

        // Generate y_body and z_body
        // Google uses gen_pows[1] for y_body, (2*poly_len - 1) for z_body
        let gen = pack_params.gen_pows[1];
        let y_body = generate_ksk_body(sk, gen, &pack_params.gadget, &w_mask, sampler, &ctx);
        let z_body = generate_ksk_body(
            sk,
            two_n - 1, // conjugation automorphism τ_{-1}
            &pack_params.gadget,
            &v_mask,
            sampler,
            &ctx,
        );

        // Convert y_body to NTT for fast rotations
        let y_body_ntt: Vec<Poly> = y_body
            .iter()
            .map(|p| {
                let mut pn = p.clone();
                pn.to_ntt(&ctx);
                pn
            })
            .collect();

        // Generate y_all and y_bar_all using NTT-domain double automorphism
        let mut y_all = Vec::with_capacity(num_to_pack_half - 1);
        let mut y_all_ntt = Vec::with_capacity(num_to_pack_half - 1);
        let mut y_bar_all = Vec::with_capacity(num_to_pack_half - 1);
        let mut y_bar_all_ntt = Vec::with_capacity(num_to_pack_half - 1);

        for i in 0..(num_to_pack_half - 1) {
            let g_pow_i = pack_params.gen_pows[i];
            let neg_g_pow_i = (two_n - g_pow_i) % two_n;

            let table_pos = pack_params.get_automorph_table(g_pow_i);
            let table_neg = pack_params.get_automorph_table(neg_g_pow_i);

            // Apply both automorphisms simultaneously in NTT domain
            let mut rotated_ntt = Vec::with_capacity(gadget_len);
            let mut rotated_bar_ntt = Vec::with_capacity(gadget_len);

            for poly_ntt in &y_body_ntt {
                let (pos, neg) = apply_automorphism_ntt_double(poly_ntt, table_pos, table_neg);
                rotated_ntt.push(pos);
                rotated_bar_ntt.push(neg);
            }

            // Convert to coefficient form
            let rotated: Vec<Poly> = rotated_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();
            let rotated_bar: Vec<Poly> = rotated_bar_ntt
                .iter()
                .map(|p| {
                    let mut pc = p.clone();
                    pc.from_ntt(&ctx);
                    pc
                })
                .collect();

            y_all.push(rotated);
            y_all_ntt.push(rotated_ntt);
            y_bar_all.push(rotated_bar);
            y_bar_all_ntt.push(rotated_bar_ntt);
        }

        Self {
            y_body,
            z_body,
            y_all,
            y_all_ntt,
            y_bar_all,
            y_bar_all_ntt,
            full_key: true,
            num_to_pack: n,
        }
    }
}

/// Generate mask from seed (deterministic expansion)
fn generate_mask_from_seed(
    seed: [u8; 32],
    n: usize,
    q: u64,
    moduli: &[u64],
    gadget_len: usize,
) -> Vec<Poly> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut result = Vec::with_capacity(gadget_len);

    for _ in 0..gadget_len {
        let mut coeffs = vec![0u64; n];
        for coeff in coeffs.iter_mut() {
            *coeff = (rng.next_u64()) % q;
        }
        result.push(Poly::from_coeffs_moduli(coeffs, moduli));
    }

    result
}

/// Generate key-switching key body (optimized implementation)
///
/// Computes y_body = τ_g(s)·G - s·w_mask + error
///
/// Equivalent to Google's `generate_ksk_body` function.
///
/// **Performance optimizations**:
/// - Accepts shared NttContext to avoid recreation
/// - Uses NTT-domain multiplication for s·w_mask
fn generate_ksk_body(
    sk: &RlweSecretKey,
    gen: usize,
    gadget: &GadgetVector,
    w_mask: &[Poly],
    sampler: &mut GaussianSampler,
    ctx: &NttContext,
) -> Vec<Poly> {
    let s = &sk.poly;
    let n = s.dimension();
    let q = s.modulus();
    let moduli = s.moduli();

    // τ_g(s) - automorphism of secret key
    let tau_s = apply_automorphism(s, gen);

    // Pre-convert s to NTT for efficient multiplication
    let mut s_ntt = s.clone();
    s_ntt.to_ntt(ctx);

    let mut result = Vec::with_capacity(gadget.len);

    for k in 0..gadget.len {
        let gadget_power = gadget.power(k);

        // τ_g(s) · g^k (where g^k is gadget base^k)
        let tau_s_times_g = tau_s.scalar_mul(gadget_power);

        // -s · w_mask[k] (using shared NttContext)
        let s_times_mask = if k < w_mask.len() {
            let mut w_k_ntt = w_mask[k].clone();
            w_k_ntt.to_ntt(ctx);
            let mut prod = s_ntt.mul_ntt_domain(&w_k_ntt, ctx);
            prod.from_ntt(ctx);
            prod
        } else {
            Poly::zero_moduli(n, moduli)
        };
        let neg_s_times_mask = s_times_mask.negate();

        // error term (sample Gaussian noise for each coefficient)
        let mut error_coeffs = vec![0u64; n];
        for coeff in error_coeffs.iter_mut() {
            let sample = sampler.sample() as i64;
            *coeff = if sample >= 0 {
                sample as u64 % q
            } else {
                (q as i64 + (sample % q as i64)) as u64
            };
        }
        let error = Poly::from_coeffs_moduli(error_coeffs, moduli);

        // y_body[k] = τ_g(s)·g^k - s·w_mask[k] + error
        let result_k = &(&tau_s_times_g + &neg_s_times_mask) + &error;
        result.push(result_k);
    }

    result
}

/// Type alias for backward compatibility
pub type PackingKeyBody = OfflinePackingKeys;

/// Offline preprocessing phase (optimized implementation)
///
/// Computes a_hat and bold_t from CRS a-vectors.
/// This is the optimized implementation matching Google's `packing_with_preprocessing_offline`.
///
/// **Performance optimizations** (matching Google):
/// - NTT-domain automorphisms via lookup tables: O(n) vs O(n log n)
/// - Fused multiply-accumulate in NTT domain: no intermediate allocations
/// - mod_inv as NTT polynomial for fast scalar multiply
/// - All operations stay in NTT domain until final output
///
/// # Algorithm
/// 1. For each i in 0..γ: compute R[i] = (1/γ) · τ_{g^i}(Σ_j X^{j·g^{n-i}} · a_j)
/// 2. Backward recursion: for i from γ-2 down to 0:
///    - T[i] = G^{-1}(R[i+1])
///    - R[i] += Σ_k w_all[i][k] · T[i][k]
/// 3. Return a_hat = R[0], bold_t = [T[0], ..., T[γ-2]]
pub fn packing_offline(
    pack_params: &PackParams,
    packing_key: &PackingKeyBody,
    a_ct_tilde: &[Poly],
    ctx: &NttContext,
) -> PrecompInsPIR {
    let n = pack_params.ring_dim;
    let q = pack_params.q;
    let moduli = &pack_params.moduli;
    let num_to_pack = pack_params.num_to_pack;
    let gen_pows = &pack_params.gen_pows;

    // Pre-convert a_ct_tilde to NTT form once (O(γ × n log n) total)
    let a_ct_ntt: Vec<Poly> = a_ct_tilde
        .iter()
        .map(|a| {
            let mut a_ntt = a.clone();
            a_ntt.to_ntt(ctx);
            a_ntt
        })
        .collect();

    // Step 1: Compute R[i] for each i in 0..γ
    // All operations in NTT domain, using NTT-domain automorphisms
    let mut r_all: Vec<Poly> = Vec::with_capacity(num_to_pack);

    for i in 0..num_to_pack {
        // Inner product: Σ_j X^{j·g^{n-i}} · a_j (all in NTT domain)
        let mut r_pow_i_ntt = Poly::zero_moduli(n, moduli);
        r_pow_i_ntt.to_ntt(ctx);

        for (j, a_j_ntt) in a_ct_ntt.iter().enumerate() {
            // Index using g^{n-i} (canonical: inverse direction)
            let exp_index = (n - i) % n;
            let index = (j * gen_pows[exp_index]) % (2 * n);

            // Select NTT-form monomial (precomputed)
            let monomial_ntt = if index < n {
                &pack_params.monomials_ntt[index % n]
            } else {
                &pack_params.neg_monomials_ntt[index % n]
            };

            // Fused multiply-accumulate in NTT domain
            r_pow_i_ntt.mul_acc_ntt_domain(monomial_ntt, a_j_ntt, ctx);
        }

        // Scale by 1/γ in NTT domain (pointwise multiply by constant polynomial)
        let r_pow_i_scaled = r_pow_i_ntt.mul_ntt_domain(&pack_params.mod_inv_poly_ntt, ctx);

        // Apply automorphism τ_{g^i} in NTT domain using precomputed tables
        let g_pow_i = gen_pows[i];
        let table = pack_params.get_automorph_table(g_pow_i);
        let r_pow_i_rotated = apply_automorphism_ntt(&r_pow_i_scaled, table);

        r_all.push(r_pow_i_rotated);
    }

    // Step 2: Backward recursion (stay in NTT domain as much as possible)
    let mut bold_t: Vec<Vec<Poly>> = Vec::with_capacity(num_to_pack - 1);

    for i in (0..(num_to_pack - 1)).rev() {
        // Convert R[i+1] to coefficient domain for gadget decomposition
        let mut r_i_plus_1_coeff = r_all[i + 1].clone();
        r_i_plus_1_coeff.from_ntt(ctx);

        // T[i] = G^{-1}(R[i+1]) - gadget decomposition in coefficient domain
        let gadget_inv = gadget_decompose(&r_i_plus_1_coeff, &pack_params.gadget);

        // R[i] += Σ_k w_all_ntt[i][k] · T[i][k]
        // Both r_all[i] and w_all_ntt[i][k] are in NTT domain
        for (k, t_k) in gadget_inv.iter().enumerate() {
            if k < packing_key.w_all_ntt[i].len() {
                // Convert T[i][k] to NTT
                let mut t_k_ntt = t_k.clone();
                t_k_ntt.to_ntt(ctx);
                // Fused multiply-accumulate
                r_all[i].mul_acc_ntt_domain(&t_k_ntt, &packing_key.w_all_ntt[i][k], ctx);
            }
        }

        bold_t.push(gadget_inv);
    }

    // Reverse bold_t to get [T[0], T[1], ..., T[γ-2]]
    bold_t.reverse();

    // Pre-convert bold_t to NTT form for optimized online phase
    let bold_t_ntt: Vec<Vec<Poly>> = bold_t
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| {
                    let mut pn = p.clone();
                    pn.to_ntt(ctx);
                    pn
                })
                .collect()
        })
        .collect();

    // Convert a_hat from NTT to coefficient domain
    let mut a_hat = r_all[0].clone();
    a_hat.from_ntt(ctx);

    PrecompInsPIR {
        a_hat,
        bold_t,
        bold_t_ntt,
        bold_t_bar: vec![],
        bold_t_hat: vec![],
        num_to_pack,
        ring_dim: n,
        q,
    }
}

/// Full packing offline phase (γ = n)
///
/// Uses parallel dual recursions for R and R̄ branches.
pub fn full_packing_offline(
    pack_params: &PackParams,
    packing_key: &PackingKeyBody,
    a_ct_tilde: &[Poly],
    ctx: &NttContext,
) -> PrecompInsPIR {
    let n = pack_params.ring_dim;
    let q = pack_params.q;
    let moduli = &pack_params.moduli;
    let num_to_pack_half = n / 2;
    let two_n = 2 * n;
    let gen_pows = &pack_params.gen_pows;
    let mod_inv = pack_params.mod_inv_gamma;

    assert_eq!(pack_params.num_to_pack, n, "Full packing requires γ = n");

    // Step 1: Compute R[i] and R̄[i] for each i in 0..n/2
    let mut r_all: Vec<Poly> = Vec::with_capacity(num_to_pack_half);
    let mut r_bar_all: Vec<Poly> = Vec::with_capacity(num_to_pack_half);

    for i in 0..num_to_pack_half {
        let mut r_pow_i = Poly::zero_moduli(n, moduli);
        let mut r_bar_pow_i = Poly::zero_moduli(n, moduli);

        for (j, a_j) in a_ct_tilde.iter().enumerate() {
            let exp_index = (n - i) % n;

            // R[i]: index = j · g^{n-i}
            let index = (j * gen_pows[exp_index]) % two_n;
            let monomial = if index < n {
                &pack_params.monomials[index % n]
            } else {
                &pack_params.neg_monomials[index % n]
            };
            let term = monomial.mul_ntt(a_j, ctx);
            r_pow_i = &r_pow_i + &term;

            // R̄[i]: index = 2n - j · g^{n-i} (negated exponent)
            let neg_index = (two_n - (j * gen_pows[exp_index]) % two_n) % two_n;
            let neg_monomial = if neg_index < n {
                &pack_params.monomials[neg_index % n]
            } else {
                &pack_params.neg_monomials[neg_index % n]
            };
            let neg_term = neg_monomial.mul_ntt(a_j, ctx);
            r_bar_pow_i = &r_bar_pow_i + &neg_term;
        }

        // Scale by 1/γ
        r_pow_i = r_pow_i.scalar_mul(mod_inv);
        r_bar_pow_i = r_bar_pow_i.scalar_mul(mod_inv);

        // Apply automorphisms
        let r_rotated = apply_automorphism(&r_pow_i, gen_pows[i]);
        let neg_g_pow_i = (two_n - gen_pows[i]) % two_n;
        let r_bar_rotated = apply_automorphism(&r_bar_pow_i, neg_g_pow_i);

        r_all.push(r_rotated);
        r_bar_all.push(r_bar_rotated);
    }

    // Step 2: Parallel backward recursions
    let mut bold_t: Vec<Vec<Poly>> = Vec::with_capacity(num_to_pack_half - 1);
    let mut bold_t_bar: Vec<Vec<Poly>> = Vec::with_capacity(num_to_pack_half - 1);

    for i in (0..(num_to_pack_half - 1)).rev() {
        // T_g[i] = G^{-1}(R[i+1])
        let gadget_inv = gadget_decompose(&r_all[i + 1], &pack_params.gadget);
        for (k, t_k) in gadget_inv.iter().enumerate() {
            if k < packing_key.w_all[i].len() {
                let term = t_k.mul_ntt(&packing_key.w_all[i][k], ctx);
                r_all[i] = &r_all[i] + &term;
            }
        }
        bold_t.push(gadget_inv);

        // T̄_g[i] = G^{-1}(R̄[i+1])
        let gadget_inv_bar = gadget_decompose(&r_bar_all[i + 1], &pack_params.gadget);
        for (k, t_k) in gadget_inv_bar.iter().enumerate() {
            if k < packing_key.w_bar_all[i].len() {
                let term = t_k.mul_ntt(&packing_key.w_bar_all[i][k], ctx);
                r_bar_all[i] = &r_bar_all[i] + &term;
            }
        }
        bold_t_bar.push(gadget_inv_bar);
    }

    // Step 3: Final gadget for conjugate branch
    // T̂ = G^{-1}(R̄[0])
    let bold_t_hat = gadget_decompose(&r_bar_all[0], &pack_params.gadget);

    // R[0] += v_mask · T̂
    for (k, t_k) in bold_t_hat.iter().enumerate() {
        if k < packing_key.v_mask.len() {
            let term = t_k.mul_ntt(&packing_key.v_mask[k], ctx);
            r_all[0] = &r_all[0] + &term;
        }
    }

    bold_t.reverse();
    bold_t_bar.reverse();

    // Pre-convert bold_t to NTT form
    let bold_t_ntt: Vec<Vec<Poly>> = bold_t
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| {
                    let mut pn = p.clone();
                    pn.to_ntt(ctx);
                    pn
                })
                .collect()
        })
        .collect();

    PrecompInsPIR {
        a_hat: r_all[0].clone(),
        bold_t,
        bold_t_ntt,
        bold_t_bar,
        bold_t_hat,
        num_to_pack: n,
        ring_dim: n,
        q,
    }
}

/// Online packing phase
///
/// Computes y_all × bold_t + b_poly to produce packed ciphertext.
///
/// # Arguments
/// * `precomp` - Precomputed a_hat and bold_t from offline phase
/// * `y_all` - Rotated client key body (from generate_rotations on y_body)
/// * `b_poly` - Polynomial of b values from LWE ciphertexts
///
/// **Performance**: Uses coefficient form inputs. For NTT-optimized version,
/// use `packing_online_ntt` with pre-converted inputs.
pub fn packing_online(
    precomp: &PrecompInsPIR,
    y_all: &[Vec<Poly>],
    b_poly: &Poly,
    ctx: &NttContext,
) -> RlweCiphertext {
    let n = precomp.ring_dim;
    let num_to_pack = precomp.num_to_pack;
    let moduli = precomp.a_hat.moduli();

    // Convert bold_t to NTT form for efficient multiply-accumulate
    let mut sum_b_ntt = Poly::zero_moduli(n, moduli);
    sum_b_ntt.to_ntt(ctx);

    for i in 0..(num_to_pack - 1) {
        if i < y_all.len() && i < precomp.bold_t.len() {
            for (k, t_k) in precomp.bold_t[i].iter().enumerate() {
                if k < y_all[i].len() {
                    // Convert both to NTT
                    let mut y_ntt = y_all[i][k].clone();
                    y_ntt.to_ntt(ctx);
                    let mut t_ntt = t_k.clone();
                    t_ntt.to_ntt(ctx);

                    // Pointwise multiply and accumulate
                    let term = y_ntt.mul_ntt_domain(&t_ntt, ctx);
                    sum_b_ntt = sum_b_ntt.add_ntt_domain(&term);
                }
            }
        }
    }

    // Convert back and add b_poly
    sum_b_ntt.from_ntt(ctx);
    let final_b = b_poly + &sum_b_ntt;

    RlweCiphertext::from_parts(precomp.a_hat.clone(), final_b)
}

/// Optimized online packing using pre-cached NTT forms
///
/// **Performance**: O(γ × ℓ × n) vs O(γ × ℓ × n log n) for non-NTT version.
/// Requires y_all_ntt pre-computed (from ClientPackingKeys).
pub fn packing_online_ntt(
    precomp: &PrecompInsPIR,
    y_all_ntt: &[Vec<Poly>],
    b_poly: &Poly,
    ctx: &NttContext,
) -> RlweCiphertext {
    let n = precomp.ring_dim;
    let num_to_pack = precomp.num_to_pack;
    let moduli = precomp.a_hat.moduli();

    // Accumulate in NTT domain
    let mut sum_b_ntt = Poly::zero_moduli(n, moduli);
    sum_b_ntt.to_ntt(ctx);

    for i in 0..(num_to_pack - 1) {
        if i < y_all_ntt.len() && i < precomp.bold_t.len() {
            for (k, t_k) in precomp.bold_t[i].iter().enumerate() {
                if k < y_all_ntt[i].len() {
                    // Convert t_k to NTT (bold_t is in coefficient form)
                    let mut t_ntt = t_k.clone();
                    t_ntt.to_ntt(ctx);

                    // y_all_ntt is already in NTT form
                    let term = y_all_ntt[i][k].mul_ntt_domain(&t_ntt, ctx);
                    sum_b_ntt = sum_b_ntt.add_ntt_domain(&term);
                }
            }
        }
    }

    // Convert back and add b_poly
    sum_b_ntt.from_ntt(ctx);
    let final_b = b_poly + &sum_b_ntt;

    RlweCiphertext::from_parts(precomp.a_hat.clone(), final_b)
}

/// Fully optimized online packing using pre-cached NTT forms for both inputs
///
/// **Performance**: O(γ × ℓ × n) - pure pointwise operations, no NTT conversions.
/// This is the fastest variant, matching Google's optimized implementation.
///
/// Requires:
/// - `precomp.bold_t_ntt` pre-computed (from packing_offline)
/// - `y_all_ntt` pre-computed (from ClientPackingKeys)
pub fn packing_online_fully_ntt(
    precomp: &PrecompInsPIR,
    y_all_ntt: &[Vec<Poly>],
    b_poly: &Poly,
    ctx: &NttContext,
) -> RlweCiphertext {
    let n = precomp.ring_dim;
    let num_to_pack = precomp.num_to_pack;
    let moduli = precomp.a_hat.moduli();

    // Accumulate in NTT domain - pure pointwise operations
    let mut sum_b_ntt = Poly::zero_moduli(n, moduli);
    sum_b_ntt.to_ntt(ctx);

    for i in 0..(num_to_pack - 1) {
        if i < y_all_ntt.len() && i < precomp.bold_t_ntt.len() {
            for k in 0..precomp.bold_t_ntt[i].len() {
                if k < y_all_ntt[i].len() {
                    // Both are already in NTT form - O(n) pointwise multiply
                    let term = y_all_ntt[i][k].mul_ntt_domain(&precomp.bold_t_ntt[i][k], ctx);
                    sum_b_ntt = sum_b_ntt.add_ntt_domain(&term);
                }
            }
        }
    }

    // Single NTT inverse at the end
    sum_b_ntt.from_ntt(ctx);
    let final_b = b_poly + &sum_b_ntt;

    RlweCiphertext::from_parts(precomp.a_hat.clone(), final_b)
}

/// Generate rotations of key body for online phase
///
/// y_all[i] = τ_{g^i}(y_body) for i in 0..γ-1
pub fn generate_rotations(pack_params: &PackParams, y_body: &[Poly]) -> Vec<Vec<Poly>> {
    let num_to_pack = pack_params.num_to_pack;
    let gen_pows = &pack_params.gen_pows;

    let mut y_all = Vec::with_capacity(num_to_pack - 1);
    for i in 0..(num_to_pack - 1) {
        let g_pow_i = gen_pows[i];
        let rotated: Vec<Poly> = y_body
            .iter()
            .map(|poly| apply_automorphism(poly, g_pow_i))
            .collect();
        y_all.push(rotated);
    }
    y_all
}

/// Convenience function: pack LWEs with full offline+online
///
/// This combines precomputation and packing in one call.
/// For production, use packing_offline + packing_online separately.
pub fn pack_inspiring(
    lwe_ciphertexts: &[LweCiphertext],
    pack_params: &PackParams,
    packing_key: &PackingKeyBody,
    y_body: &[Poly],
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let ctx = params.ntt_context();
    let moduli = params.moduli();

    // Convert LWE a-vectors to Poly
    let a_ct_tilde: Vec<Poly> = lwe_ciphertexts
        .iter()
        .map(|lwe| Poly::from_coeffs_moduli(lwe.a.clone(), params.moduli()))
        .collect();

    // Offline phase
    let precomp = packing_offline(pack_params, packing_key, &a_ct_tilde, &ctx);

    // Generate y_all rotations
    let y_all = generate_rotations(pack_params, y_body);

    // Build b_poly from LWE b values
    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_ciphertexts.iter().enumerate() {
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, moduli);

    // Online phase
    packing_online(&precomp, &y_all, &b_poly, &ctx)
}

// ============================================================================
// Legacy API compatibility (wraps new implementation)
// ============================================================================

/// Generator powers table (legacy compatibility)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneratorPowers {
    pub powers: Vec<usize>,
    pub inv_powers: Vec<usize>,
    pub generator: usize,
    pub ring_dim: usize,
}

impl GeneratorPowers {
    pub fn new(d: usize) -> Self {
        let two_d = 2 * d;
        // Use canonical generator for full packing
        let g = 5usize;

        let mut powers = Vec::with_capacity(d);
        let mut val = 1usize;
        for _ in 0..d {
            powers.push(val);
            val = (val * g) % two_d;
        }

        let g_inv = mod_inverse_usize(g, two_d).expect("g must be invertible mod 2d");
        let mut inv_powers = Vec::with_capacity(d);
        val = 1;
        for _ in 0..d {
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

    pub fn order(&self) -> usize {
        self.powers.len()
    }

    #[inline]
    pub fn pow(&self, i: usize) -> usize {
        self.powers[i % self.powers.len()]
    }

    #[inline]
    pub fn inv_pow(&self, i: usize) -> usize {
        self.inv_powers[i % self.inv_powers.len()]
    }

    #[inline]
    pub fn generator(&self) -> usize {
        self.generator
    }
}

/// Legacy precomputation struct
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspiringPrecomputation {
    pub gen_pows: GeneratorPowers,
    pub rotated_k_g: RotatedKsMatrix,
    pub r_polys: Vec<Poly>,
    pub bold_t: Vec<Vec<Poly>>,
    pub num_to_pack: usize,
    pub ring_dim: usize,
    pub q: u64,
}

/// Legacy rotated KS matrix (kept for API compatibility)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotatedKsMatrix {
    pub rotations: Vec<Vec<RlweCiphertext>>,
    pub num_to_pack: usize,
    pub gadget: GadgetVector,
}

impl RotatedKsMatrix {
    pub fn generate(
        k_g: &crate::ks::KeySwitchingMatrix,
        gen_pows: &GeneratorPowers,
        num_to_pack: usize,
    ) -> Self {
        let num_rotations = if num_to_pack > 0 { num_to_pack - 1 } else { 0 };
        let mut rotations = Vec::with_capacity(num_rotations);

        for i in 0..num_rotations {
            let g_pow_i = gen_pows.pow(i);
            let rotated_rows: Vec<RlweCiphertext> = k_g
                .rows
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

    pub fn get_rotation(&self, i: usize) -> &[RlweCiphertext] {
        &self.rotations[i]
    }
}

/// Legacy precompute function
pub fn precompute_inspiring(
    crs_a_vectors: &[Vec<u64>],
    k_g: &crate::ks::KeySwitchingMatrix,
    params: &InspireParams,
) -> InspiringPrecomputation {
    let d = params.ring_dim;
    let q = params.q;
    let num_to_pack = crs_a_vectors.len();
    let ctx = params.ntt_context();

    let gen_pows = GeneratorPowers::new(d);
    let rotated_k_g = RotatedKsMatrix::generate(k_g, &gen_pows, num_to_pack);

    // Use new canonical implementation
    let pack_params = PackParams::new(params, num_to_pack);

    // Convert a vectors to Poly
    let a_polys: Vec<Poly> = crs_a_vectors
        .iter()
        .map(|a| Poly::from_coeffs_moduli(a.clone(), params.moduli()))
        .collect();

    // Create simple packing key (using K_g rows as w_all approximation)
    // This is a legacy compatibility shim - in proper usage, use OfflinePackingKeys::generate()
    let w_all: Vec<Vec<Poly>> = rotated_k_g
        .rotations
        .iter()
        .map(|rows| rows.iter().map(|r| r.b.clone()).collect())
        .collect();

    // Convert w_all to NTT form for the optimized packing_offline
    let w_all_ntt: Vec<Vec<Poly>> = w_all
        .iter()
        .map(|row| {
            row.iter()
                .map(|p| {
                    let mut pn = p.clone();
                    pn.to_ntt(&ctx);
                    pn
                })
                .collect()
        })
        .collect();

    let packing_key = OfflinePackingKeys {
        w_seed: [0u8; 32],
        v_seed: [0u8; 32],
        w_mask: vec![],
        v_mask: vec![],
        w_all,
        w_all_ntt,
        w_bar_all: vec![],
        w_bar_all_ntt: vec![],
        full_key: false,
    };

    let precomp = packing_offline(&pack_params, &packing_key, &a_polys, &ctx);

    InspiringPrecomputation {
        gen_pows,
        rotated_k_g,
        r_polys: vec![precomp.a_hat],
        bold_t: precomp.bold_t,
        num_to_pack,
        ring_dim: d,
        q,
    }
}

/// Legacy pack function (simplified)
pub fn pack_inspiring_legacy(
    lwe_ciphertexts: &[LweCiphertext],
    precomp: &InspiringPrecomputation,
    _k_g: &crate::ks::KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let d = params.ring_dim;
    let q = params.q;
    let n = lwe_ciphertexts.len();
    let ctx = params.ntt_context();
    let moduli = params.moduli();

    assert_eq!(
        n, precomp.num_to_pack,
        "Number of LWEs must match precomputation"
    );

    // Use rotated_k_g as y_all approximation
    let y_all: Vec<Vec<Poly>> = precomp
        .rotated_k_g
        .rotations
        .iter()
        .map(|rows| rows.iter().map(|r| r.b.clone()).collect())
        .collect();

    // Build b_poly
    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_ciphertexts.iter().enumerate() {
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, moduli);

    // Build precomp for online phase
    let precomp_new = PrecompInsPIR {
        a_hat: precomp
            .r_polys
            .get(0)
            .cloned()
            .unwrap_or_else(|| Poly::zero_moduli(d, moduli)),
        bold_t: precomp.bold_t.clone(),
        bold_t_ntt: vec![], // Legacy shim - will be converted on-the-fly
        bold_t_bar: vec![],
        bold_t_hat: vec![],
        num_to_pack: n,
        ring_dim: d,
        q,
    };

    packing_online(&precomp_new, &y_all, &b_poly, &ctx)
}

/// Partial pack (simplified API)
pub fn pack_inspiring_partial(
    lwe_ciphertexts: &[LweCiphertext],
    k_g: &crate::ks::KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    let crs_a_vectors: Vec<Vec<u64>> = lwe_ciphertexts.iter().map(|lwe| lwe.a.clone()).collect();
    let precomp = precompute_inspiring(&crs_a_vectors, k_g, params);
    pack_inspiring_legacy(lwe_ciphertexts, &precomp, k_g, params)
}

/// Full pack (placeholder - needs proper K_h)
pub fn pack_inspiring_full(
    lwe_ciphertexts: &[LweCiphertext],
    precomp: &InspiringPrecomputation,
    _k_g: &crate::ks::KeySwitchingMatrix,
    _k_h: &crate::ks::KeySwitchingMatrix,
    params: &InspireParams,
) -> RlweCiphertext {
    // For now, delegate to legacy
    pack_inspiring_legacy(lwe_ciphertexts, precomp, _k_g, params)
}

// ============================================================================
// Utility functions
// ============================================================================

fn mod_inverse_u64(a: u64, m: u64) -> Option<u64> {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);
    if g != 1 {
        None
    } else {
        Some(((x % m as i128 + m as i128) % m as i128) as u64)
    }
}

fn mod_inverse_usize(a: usize, m: usize) -> Option<usize> {
    let (g, x, _) = extended_gcd_i64(a as i64, m as i64);
    if g != 1 {
        None
    } else {
        Some(((x % m as i64 + m as i64) % m as i64) as usize)
    }
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd_i128(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

fn extended_gcd_i64(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd_i64(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ks::generate_automorphism_ks_matrix;
    use crate::math::GaussianSampler;
    use crate::rlwe::RlweSecretKey;

    fn test_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            crt_moduli: vec![1152921504606830593],
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    #[test]
    fn test_pack_params_generator() {
        let params = test_params();
        let n = params.ring_dim;

        // Test generator formula
        let pack_8 = PackParams::new(&params, 8);
        assert_eq!(pack_8.generator, (2 * n / 8) + 1); // 65

        let pack_16 = PackParams::new(&params, 16);
        assert_eq!(pack_16.generator, (2 * n / 16) + 1); // 33

        let pack_n = PackParams::new(&params, n);
        assert_eq!(pack_n.generator, 5); // Full packing uses 5
    }

    #[test]
    fn test_mod_inverse() {
        let q = 1152921504606830593u64;

        // Test 1/8 mod q
        let inv_8 = mod_inverse_u64(8, q).unwrap();
        assert_eq!((8u128 * inv_8 as u128) % q as u128, 1);

        // Test 1/16 mod q
        let inv_16 = mod_inverse_u64(16, q).unwrap();
        assert_eq!((16u128 * inv_16 as u128) % q as u128, 1);
    }

    #[test]
    fn test_generator_powers() {
        let params = test_params();
        let pack_params = PackParams::new(&params, 16);
        let n = params.ring_dim;
        let two_n = 2 * n;

        // Verify g^0 = 1
        assert_eq!(pack_params.gen_pows[0], 1);

        // Verify g^1 = generator
        assert_eq!(pack_params.gen_pows[1], pack_params.generator);

        // Verify powers are computed correctly
        let g = pack_params.generator;
        for i in 0..10 {
            let expected = pow_mod(g, i, two_n);
            assert_eq!(pack_params.gen_pows[i], expected);
        }
    }

    fn pow_mod(base: usize, exp: usize, m: usize) -> usize {
        let mut result = 1usize;
        let mut b = base % m;
        let mut e = exp;
        while e > 0 {
            if e % 2 == 1 {
                result = (result * b) % m;
            }
            e /= 2;
            b = (b * b) % m;
        }
        result
    }

    #[test]
    fn test_legacy_api_compatibility() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;
        let ctx = params.ntt_context();
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

        let g = 3;
        let k_g = generate_automorphism_ks_matrix(&sk, g, &gadget, &mut sampler, &ctx);

        // Create dummy CRS a-vectors
        let num_to_pack = 8;
        let crs_a_vectors: Vec<Vec<u64>> = (0..num_to_pack)
            .map(|_| Poly::random_moduli(d, params.moduli()).coeffs().to_vec())
            .collect();

        let precomp = precompute_inspiring(&crs_a_vectors, &k_g, &params);

        assert_eq!(precomp.num_to_pack, num_to_pack);
        assert_eq!(precomp.bold_t.len(), num_to_pack - 1);
    }

    #[test]
    fn test_packing_offline_dimensions() {
        let params = test_params();
        let d = params.ring_dim;
        let ctx = params.ntt_context();
        let mut sampler = GaussianSampler::new(params.sigma);

        let _sk = RlweSecretKey::generate(&params, &mut sampler);
        let num_to_pack = 8;

        let pack_params = PackParams::new(&params, num_to_pack);

        // Use the new API with w_seed
        let w_seed = [42u8; 32];
        let packing_key = OfflinePackingKeys::generate(&pack_params, w_seed);

        // Create test a-polynomials
        let a_polys: Vec<Poly> = (0..num_to_pack)
            .map(|_| Poly::random_moduli(d, params.moduli()))
            .collect();

        let precomp = packing_offline(&pack_params, &packing_key, &a_polys, &ctx);

        assert_eq!(precomp.num_to_pack, num_to_pack);
        assert_eq!(precomp.ring_dim, d);
        assert_eq!(precomp.bold_t.len(), num_to_pack - 1);
        assert_eq!(precomp.a_hat.dimension(), d);
    }
}
