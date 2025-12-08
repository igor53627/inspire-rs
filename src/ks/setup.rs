//! Key-switching matrix generation

use crate::math::{GaussianSampler, ModQ, NttContext, Poly};
use crate::rgsw::GadgetVector;
use crate::rlwe::{RlweCiphertext, RlweSecretKey};
use serde::{Deserialize, Serialize};

/// Sample a polynomial with coefficients from discrete Gaussian
fn sample_error_poly(dim: usize, q: u64, sampler: &mut GaussianSampler) -> Poly {
    let coeffs: Vec<u64> = (0..dim)
        .map(|_| {
            let sample = sampler.sample();
            ModQ::from_signed(sample, q)
        })
        .collect();
    Poly::from_coeffs(coeffs, q)
}

/// Key-switching matrix from secret key s to secret key s'
///
/// The matrix consists of ℓ RLWE ciphertexts encrypting s·z^i under s':
/// ```text
/// K[i] = RLWE_{s'}(s·z^i) = (a_i, -a_i·s' + e_i + s·z^i)
/// ```
///
/// This allows transforming ciphertexts from key s to key s' with controlled noise.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySwitchingMatrix {
    /// ℓ RLWE ciphertexts
    pub rows: Vec<RlweCiphertext>,
    /// Gadget parameters
    pub gadget: GadgetVector,
}

impl KeySwitchingMatrix {
    /// Create from component rows
    pub fn from_rows(rows: Vec<RlweCiphertext>, gadget: GadgetVector) -> Self {
        debug_assert_eq!(rows.len(), gadget.len, "KS matrix must have ℓ rows");
        Self { rows, gadget }
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.rows[0].ring_dim()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.rows[0].modulus()
    }

    /// Get the gadget length ℓ
    pub fn gadget_len(&self) -> usize {
        self.gadget.len
    }

    /// Get the number of rows (same as gadget length)
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Check if the matrix is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a reference to the i-th row
    pub fn get_row(&self, i: usize) -> &RlweCiphertext {
        &self.rows[i]
    }

    /// Create a dummy key-switching matrix for testing
    ///
    /// This creates a matrix with zero ciphertexts, useful for structural tests.
    pub fn dummy(ring_dim: usize, q: u64, gadget_len: usize) -> Self {
        let gadget = GadgetVector::new(1 << 20, gadget_len, q);
        let rows: Vec<RlweCiphertext> = (0..gadget_len)
            .map(|_| {
                let a = Poly::zero(ring_dim, q);
                let b = Poly::zero(ring_dim, q);
                RlweCiphertext::from_parts(a, b)
            })
            .collect();
        Self { rows, gadget }
    }
}

/// Generate a key-switching matrix from secret key s to secret key s'
///
/// This creates ℓ RLWE encryptions of s·z^i under s':
/// ```text
/// K[i] = (a_i, -a_i·s' + e_i + s·z^i)
/// ```
///
/// # Arguments
/// * `from_key` - Source secret key s
/// * `to_key` - Target secret key s'
/// * `gadget` - Gadget vector parameters
/// * `sampler` - Gaussian sampler for error
/// * `ctx` - NTT context
///
/// # Returns
/// Key-switching matrix that transforms ciphertexts from `from_key` to `to_key`
pub fn generate_ks_matrix(
    from_key: &RlweSecretKey,
    to_key: &RlweSecretKey,
    gadget: &GadgetVector,
    sampler: &mut GaussianSampler,
    ctx: &NttContext,
) -> KeySwitchingMatrix {
    let d = from_key.ring_dim();
    let q = from_key.modulus();
    let ell = gadget.len;
    let powers = gadget.powers();

    debug_assert_eq!(
        from_key.ring_dim(),
        to_key.ring_dim(),
        "Keys must have same ring dimension"
    );
    debug_assert_eq!(
        from_key.modulus(),
        to_key.modulus(),
        "Keys must have same modulus"
    );

    let mut rows = Vec::with_capacity(ell);

    for i in 0..ell {
        // Sample random a_i
        let a = Poly::random(d, q);

        // Sample error e_i
        let error = sample_error_poly(d, q, sampler);

        // Compute b_i = -a_i·s' + e_i + s·z^i
        let a_times_s_prime = a.mul_ntt(&to_key.poly, ctx);
        let neg_a_s_prime = -a_times_s_prime;

        // s·z^i
        let s_scaled = from_key.poly.scalar_mul(powers[i]);

        // b = -a·s' + e + s·z^i
        let b = &(&neg_a_s_prime + &error) + &s_scaled;

        rows.push(RlweCiphertext::from_parts(a, b));
    }

    KeySwitchingMatrix {
        rows,
        gadget: gadget.clone(),
    }
}

/// Generate a key-switching matrix for automorphism
///
/// For Galois automorphism τ_g, creates a matrix from τ_g(s) to s.
/// This is used to switch back after applying an automorphism to a ciphertext.
///
/// # Arguments
/// * `sk` - Secret key s
/// * `automorphism` - Galois element g (must be odd and coprime to 2d)
/// * `gadget` - Gadget vector parameters
/// * `sampler` - Gaussian sampler for error
/// * `ctx` - NTT context
pub fn generate_automorphism_ks_matrix(
    sk: &RlweSecretKey,
    automorphism: usize,
    gadget: &GadgetVector,
    sampler: &mut GaussianSampler,
    ctx: &NttContext,
) -> KeySwitchingMatrix {
    let d = sk.ring_dim();
    let q = sk.modulus();

    // Compute τ_g(s): apply automorphism to secret key
    // τ_g(X^i) = X^(g·i mod 2d), with sign flip if (g·i) mod 2d >= d
    let mut auto_s_coeffs = vec![0u64; d];
    for i in 0..d {
        let new_idx = (automorphism * i) % (2 * d);
        let coeff = sk.poly.coeff(i);

        if new_idx < d {
            auto_s_coeffs[new_idx] = coeff;
        } else {
            // X^(d+k) = -X^k in the ring X^d + 1
            let reduced_idx = new_idx - d;
            auto_s_coeffs[reduced_idx] = if coeff == 0 { 0 } else { q - coeff };
        }
    }
    let auto_s = RlweSecretKey::from_poly(Poly::from_coeffs(auto_s_coeffs, q));

    // Generate KS matrix from τ_g(s) to s
    generate_ks_matrix(&auto_s, sk, gadget, sampler, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::InspireParams;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        NttContext::new(params.ring_dim, params.q)
    }

    #[test]
    fn test_ks_matrix_generation() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        assert_eq!(ks_matrix.rows.len(), params.gadget_len);
        assert_eq!(ks_matrix.ring_dim(), params.ring_dim);
        assert_eq!(ks_matrix.modulus(), params.q);
    }

    #[test]
    fn test_ks_matrix_decryption() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk1 = RlweSecretKey::generate(&params, &mut sampler);
        let sk2 = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);
        let ks_matrix = generate_ks_matrix(&sk1, &sk2, &gadget, &mut sampler, &ctx);

        // Each row K[i] should decrypt to s1·z^i under sk2
        let powers = gadget.powers();
        for (i, row) in ks_matrix.rows.iter().enumerate() {
            // Decrypt row under sk2: a·s2 + b = e + s1·z^i
            let a_s2 = row.a.mul_ntt(&sk2.poly, &ctx);
            let decrypted = &a_s2 + &row.b;

            // Expected: s1 * powers[i]
            let expected = sk1.poly.scalar_mul(powers[i]);

            // Check that decrypted ≈ expected (up to small error)
            for j in 0..params.ring_dim {
                let dec_val = decrypted.coeff(j);
                let exp_val = expected.coeff(j);

                // Compute difference in centered representation
                let diff = if dec_val >= exp_val {
                    dec_val - exp_val
                } else {
                    exp_val - dec_val
                };
                let centered_diff = std::cmp::min(diff, params.q - diff);

                assert!(
                    centered_diff < delta / 10,
                    "Row {} coefficient {} has large error: {}",
                    i, j, centered_diff
                );
            }
        }
    }

    #[test]
    fn test_automorphism_ks_matrix() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Generate automorphism KS matrix for τ_3
        let auto_g = 3;
        let ks_matrix = generate_automorphism_ks_matrix(&sk, auto_g, &gadget, &mut sampler, &ctx);

        assert_eq!(ks_matrix.rows.len(), params.gadget_len);
    }
}
