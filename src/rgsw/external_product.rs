//! External product operation: RLWE × RGSW → RLWE
//!
//! This is the key operation for homomorphic multiplication in the InsPIRe scheme.

use crate::math::{NttContext, Poly};
use crate::rlwe::RlweCiphertext;

use super::types::{GadgetVector, RgswCiphertext};

/// Decompose a polynomial coefficient-wise into base-z digits
///
/// For each coefficient c, computes digits [c₀, c₁, ..., c_{ℓ-1}] such that:
/// c ≡ c₀ + c₁·z + c₂·z² + ... + c_{ℓ-1}·z^{ℓ-1} (mod q)
///
/// The digits are in [0, z) range for simplicity.
pub fn gadget_decompose(poly: &Poly, gadget: &GadgetVector) -> Vec<Poly> {
    let d = poly.dimension();
    let q = poly.modulus();
    let base = gadget.base;
    let ell = gadget.len;

    let mut result = Vec::with_capacity(ell);
    for _ in 0..ell {
        result.push(Poly::zero(d, q));
    }

    for j in 0..d {
        let mut val = poly.coeff(j);

        for i in 0..ell {
            let digit = val % base;
            result[i].set_coeff(j, digit);
            val /= base;
        }
    }

    result
}

/// Reconstruct a polynomial from its gadget decomposition
///
/// Given decomposition [p₀, p₁, ..., p_{ℓ-1}], computes:
/// p = p₀ + p₁·z + p₂·z² + ... + p_{ℓ-1}·z^{ℓ-1}
pub fn gadget_reconstruct(decomposed: &[Poly], gadget: &GadgetVector) -> Poly {
    assert!(!decomposed.is_empty(), "Decomposition cannot be empty");
    assert_eq!(decomposed.len(), gadget.len, "Decomposition length must match gadget length");

    let d = decomposed[0].dimension();
    let q = decomposed[0].modulus();
    let powers = gadget.powers();

    let mut result = Poly::zero(d, q);

    for (i, poly) in decomposed.iter().enumerate() {
        let scaled = poly.scalar_mul(powers[i]);
        result += scaled;
    }

    result
}

/// Compute the external product: RLWE(m₀) ⊡ RGSW(m₁) → RLWE(m₀·m₁)
///
/// This is the key operation for homomorphic multiplication by an encrypted bit.
///
/// # Algorithm
///
/// Given RLWE ciphertext (a, b) and RGSW ciphertext C:
/// 1. Decompose a and b using gadget inverse: g⁻¹(a), g⁻¹(b)
/// 2. Compute: (a', b') = Σᵢ [g⁻¹(a)ᵢ · C[i] + g⁻¹(b)ᵢ · C[ℓ+i]]
///
/// The result decrypts to m₀·m₁ with controlled noise growth.
pub fn external_product(
    rlwe: &RlweCiphertext,
    rgsw: &RgswCiphertext,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = rlwe.ring_dim();
    let q = rlwe.modulus();
    let gadget = &rgsw.gadget;
    let ell = gadget.len;

    // Decompose both components of the RLWE ciphertext
    let a_decomp = gadget_decompose(&rlwe.a, gadget);
    let b_decomp = gadget_decompose(&rlwe.b, gadget);

    // Initialize result as zero
    let mut result_a = Poly::zero(d, q);
    let mut result_b = Poly::zero(d, q);

    // Sum over decomposition digits
    for i in 0..ell {
        // First ℓ rows of RGSW correspond to 'a' component
        // g⁻¹(a)ᵢ · RGSW[i]
        let row_a = &rgsw.rows[i];
        let term_a_a = a_decomp[i].mul_ntt(&row_a.a, ctx);
        let term_a_b = a_decomp[i].mul_ntt(&row_a.b, ctx);
        result_a += term_a_a;
        result_b += term_a_b;

        // Next ℓ rows of RGSW correspond to 'b' component
        // g⁻¹(b)ᵢ · RGSW[ℓ+i]
        let row_b = &rgsw.rows[ell + i];
        let term_b_a = b_decomp[i].mul_ntt(&row_b.a, ctx);
        let term_b_b = b_decomp[i].mul_ntt(&row_b.b, ctx);
        result_a += term_b_a;
        result_b += term_b_b;
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{GaussianSampler, ModQ};
    use crate::params::InspireParams;
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
    fn test_gadget_decompose_reconstruct_roundtrip() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Random polynomial
        let poly = Poly::random(params.ring_dim, params.q);

        // Decompose and reconstruct
        let decomposed = gadget_decompose(&poly, &gadget);
        let reconstructed = gadget_reconstruct(&decomposed, &gadget);

        // Should be equal
        assert_eq!(poly, reconstructed);
    }

    #[test]
    fn test_gadget_decompose_small_digits() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let poly = Poly::random(params.ring_dim, params.q);
        let decomposed = gadget_decompose(&poly, &gadget);

        // Each digit should be in [0, base) range
        for digit_poly in &decomposed {
            for j in 0..params.ring_dim {
                let coeff = digit_poly.coeff(j);
                assert!(
                    coeff < params.gadget_base,
                    "Digit {} exceeds base {}",
                    coeff,
                    params.gadget_base
                );
            }
        }
    }

    #[test]
    fn test_gadget_decompose_zero() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let zero = Poly::zero(params.ring_dim, params.q);
        let decomposed = gadget_decompose(&zero, &gadget);

        for digit_poly in &decomposed {
            assert!(digit_poly.is_zero());
        }
    }

    #[test]
    fn test_external_product_by_zero() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt a message
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % params.p).collect();
        let msg = Poly::from_coeffs(msg_coeffs, params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(0)
        let rgsw_zero = super::super::RgswCiphertext::encrypt_scalar(&sk, 0, &gadget, &mut sampler, &ctx);

        // External product with RGSW(0) should give encryption of 0
        let result = external_product(&rlwe, &rgsw_zero, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        // All coefficients should be 0 (or very close due to noise)
        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Expected 0 at coefficient {}", i);
        }
    }

    #[test]
    fn test_external_product_by_one() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt a message
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();
        let msg = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(1)
        let rgsw_one = super::super::RgswCiphertext::encrypt_scalar(&sk, 1, &gadget, &mut sampler, &ctx);

        // External product with RGSW(1) should preserve the message
        let result = external_product(&rlwe, &rgsw_one, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

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
    fn test_external_product_scalar_multiplication() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt message with small values
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 10).collect();
        let msg = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(3)
        let scalar = 3u64;
        let rgsw_scalar = super::super::RgswCiphertext::encrypt_scalar(&sk, scalar, &gadget, &mut sampler, &ctx);

        // External product should multiply by 3
        let result = external_product(&rlwe, &rgsw_scalar, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg_coeffs[i] * scalar) % params.p;
            assert_eq!(
                decrypted.coeff(i),
                expected,
                "Mismatch at coefficient {}: expected {}, got {}",
                i,
                expected,
                decrypted.coeff(i)
            );
        }
    }

    #[test]
    fn test_external_product_monomial() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt constant message
        let mut msg_coeffs = vec![0u64; params.ring_dim];
        msg_coeffs[0] = 5;
        let msg = Poly::from_coeffs(msg_coeffs, params.q);
        let a = Poly::random(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(X) - monomial
        let mut monomial_coeffs = vec![0u64; params.ring_dim];
        monomial_coeffs[1] = 1;
        let monomial = Poly::from_coeffs(monomial_coeffs, params.q);
        let rgsw_mono = super::super::RgswCiphertext::encrypt(&sk, &monomial, &gadget, &mut sampler, &ctx);

        // External product: 5 * X = 5X
        let result = external_product(&rlwe, &rgsw_mono, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        assert_eq!(decrypted.coeff(0), 0, "Constant term should be 0");
        assert_eq!(decrypted.coeff(1), 5, "X coefficient should be 5");
        for i in 2..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Higher terms should be 0");
        }
    }
}
