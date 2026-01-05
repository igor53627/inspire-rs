//! RLWE encryption and decryption
//!
//! Implements encryption: b = -a·s + e + Δ·m
//! where Δ = ⌊q/p⌋ is the scaling factor.

use crate::lwe::LweCiphertext;
use crate::math::{GaussianSampler, ModQ, NttContext, Poly};
use crate::params::InspireParams;

use super::types::{RlweCiphertext, RlweSecretKey};

impl RlweSecretKey {
    /// Generate a secret key from Gaussian distribution
    pub fn generate(params: &InspireParams, sampler: &mut GaussianSampler) -> Self {
        let coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|_| {
                let sample = sampler.sample();
                ModQ::from_signed(sample, params.q)
            })
            .collect();
        let poly = Poly::from_coeffs(coeffs, params.q);
        Self { poly }
    }
}

impl RlweCiphertext {
    /// Encrypt a message polynomial
    ///
    /// Computes: (a, b) where b = -a·s + e + Δ·m
    ///
    /// # Arguments
    /// * `sk` - Secret key
    /// * `message_poly` - Message polynomial (coefficients in [0, p))
    /// * `delta` - Scaling factor Δ = ⌊q/p⌋
    /// * `a_random` - Random polynomial a ∈ R_q
    /// * `error` - Error polynomial e sampled from Gaussian
    /// * `ctx` - NTT context for polynomial multiplication
    pub fn encrypt(
        sk: &RlweSecretKey,
        message_poly: &Poly,
        delta: u64,
        a_random: Poly,
        error: &Poly,
        ctx: &NttContext,
    ) -> Self {
        // Compute Δ·m
        let scaled_msg = message_poly.scalar_mul(delta);

        // Compute -a·s
        let a_s = a_random.mul_ntt(&sk.poly, ctx);
        let neg_a_s = -a_s;

        // b = -a·s + e + Δ·m
        let b = &(&neg_a_s + error) + &scaled_msg;

        Self { a: a_random, b }
    }

    /// Encrypt using Common Reference String (CRS) mode
    ///
    /// In CRS mode, `a` is derived from a public seed rather than randomly sampled.
    /// This reduces communication in the PIR protocol.
    pub fn encrypt_with_crs(
        sk: &RlweSecretKey,
        message_poly: &Poly,
        delta: u64,
        crs_a: &Poly,
        error: &Poly,
        ctx: &NttContext,
    ) -> Self {
        // Compute Δ·m
        let scaled_msg = message_poly.scalar_mul(delta);

        // Compute -a·s
        let a_s = crs_a.mul_ntt(&sk.poly, ctx);
        let neg_a_s = -a_s;

        // b = -a·s + e + Δ·m
        let b = &(&neg_a_s + error) + &scaled_msg;

        Self {
            a: crs_a.clone(),
            b,
        }
    }

    /// Decrypt ciphertext to recover message polynomial
    ///
    /// Computes: m = ⌊(a·s + b) · p / q⌉ mod p
    ///
    /// # Arguments
    /// * `sk` - Secret key
    /// * `delta` - Scaling factor Δ = ⌊q/p⌋
    /// * `p` - Plaintext modulus
    /// * `ctx` - NTT context for polynomial multiplication
    pub fn decrypt(&self, sk: &RlweSecretKey, delta: u64, p: u64, ctx: &NttContext) -> Poly {
        let d = self.ring_dim();

        // Compute a·s + b = e + Δ·m
        let a_s = self.a.mul_ntt(&sk.poly, ctx);
        let noisy_msg = &a_s + &self.b;

        // Round to recover message: m = ⌊(a·s + b) / Δ⌉ mod p
        let mut coeffs = vec![0u64; d];
        for i in 0..d {
            let val = noisy_msg.coeff(i);
            // Round: (val + Δ/2) / Δ mod p
            let half_delta = delta / 2;
            let rounded = ((val as u128 + half_delta as u128) / delta as u128) as u64;
            coeffs[i] = rounded % p;
        }

        Poly::from_coeffs(coeffs, p)
    }

    /// Homomorphic addition of two ciphertexts
    ///
    /// (a1, b1) + (a2, b2) = (a1 + a2, b1 + b2)
    /// Decrypts to m1 + m2
    pub fn add(&self, other: &RlweCiphertext) -> RlweCiphertext {
        RlweCiphertext {
            a: &self.a + &other.a,
            b: &self.b + &other.b,
        }
    }

    /// Homomorphic subtraction of two ciphertexts
    ///
    /// (a1, b1) - (a2, b2) = (a1 - a2, b1 - b2)
    /// Decrypts to m1 - m2
    pub fn sub(&self, other: &RlweCiphertext) -> RlweCiphertext {
        RlweCiphertext {
            a: &self.a - &other.a,
            b: &self.b - &other.b,
        }
    }

    /// Multiply ciphertext by a scalar
    ///
    /// c · (a, b) = (c·a, c·b)
    /// Decrypts to c·m
    pub fn scalar_mul(&self, scalar: u64) -> RlweCiphertext {
        RlweCiphertext {
            a: self.a.scalar_mul(scalar),
            b: self.b.scalar_mul(scalar),
        }
    }

    /// Multiply ciphertext by a plaintext polynomial
    ///
    /// p(X) · (a, b) = (p(X)·a, p(X)·b)
    /// Decrypts to p(X)·m(X) mod (X^d + 1)
    pub fn poly_mul(&self, plaintext_poly: &Poly, ctx: &NttContext) -> RlweCiphertext {
        RlweCiphertext {
            a: self.a.mul_ntt(plaintext_poly, ctx),
            b: self.b.mul_ntt(plaintext_poly, ctx),
        }
    }

    /// Create an encryption of zero with zero error
    ///
    /// This creates (0, 0) which decrypts to 0.
    /// Useful as an identity element for homomorphic addition.
    pub fn zero(params: &InspireParams) -> RlweCiphertext {
        let a = Poly::zero(params.ring_dim, params.q);
        let b = Poly::zero(params.ring_dim, params.q);
        RlweCiphertext { a, b }
    }

    /// Create a trivial encryption of a message polynomial
    ///
    /// Trivial encryption: (0, Δ·m) - decrypts correctly with any secret key.
    /// No encryption security (message is visible), but useful for homomorphic
    /// operations when we want to operate on a known plaintext.
    ///
    /// # Arguments
    /// * `message_poly` - Message polynomial (coefficients in [0, p))
    /// * `delta` - Scaling factor Δ = ⌊q/p⌋
    /// * `params` - System parameters
    pub fn trivial_encrypt(
        message_poly: &Poly,
        delta: u64,
        params: &InspireParams,
    ) -> RlweCiphertext {
        let a = Poly::zero(params.ring_dim, params.q);
        let b = message_poly.scalar_mul(delta);
        RlweCiphertext { a, b }
    }

    /// Extract an LWE ciphertext encrypting coefficient 0 from this RLWE ciphertext
    ///
    /// This is the standard RLWE-to-LWE sample extraction at coefficient 0.
    /// The resulting LWE ciphertext encrypts m_0 (the constant term of the message polynomial).
    ///
    /// Formula: If RLWE decryption is b(X) + a(X)·s(X) = m(X) + e(X),
    /// then coefficient 0 gives: b_0 + Σ_i a_i · s_{-i mod d} = m_0 + e_0
    ///
    /// The LWE ciphertext (a', b') is:
    /// - a'_i = a_{d-i mod d} for i > 0, a'_0 = a_0
    /// - b' = b_0
    pub fn sample_extract_coeff0(&self) -> LweCiphertext {
        let d = self.ring_dim();
        let q = self.modulus();

        let mut a_vec = vec![0u64; d];
        a_vec[0] = self.a.coeff(0);
        for i in 1..d {
            a_vec[i] = self.a.coeff(d - i);
        }

        let b0 = self.b.coeff(0);

        LweCiphertext { a: a_vec, b: b0, q }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        NttContext::new(params.ring_dim, params.q)
    }

    fn random_poly(dim: usize, q: u64) -> Poly {
        let mut rng = rand::thread_rng();
        let coeffs: Vec<u64> = (0..dim).map(|_| rng.gen_range(0..q)).collect();
        Poly::from_coeffs(coeffs, q)
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
    fn test_encrypt_decrypt_roundtrip() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        // Generate secret key
        let sk = RlweSecretKey::generate(&params, &mut sampler);

        // Create message polynomial with small coefficients
        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let message = Poly::from_coeffs(msg_coeffs.clone(), params.q);

        // Generate random a and error
        let a_random = random_poly(params.ring_dim, params.q);
        let error = sample_error_poly(params.ring_dim, params.q, &mut sampler);

        // Encrypt
        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a_random, &error, &ctx);

        // Decrypt
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        // Verify
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
    fn test_encrypt_decrypt_zero() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        // Encrypt zero message
        let message = Poly::zero(params.ring_dim, params.q);
        let a_random = random_poly(params.ring_dim, params.q);
        let error = sample_error_poly(params.ring_dim, params.q, &mut sampler);

        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a_random, &error, &ctx);
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Expected zero at coefficient {}", i);
        }
    }

    #[test]
    fn test_homomorphic_addition() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        // Create two message polynomials
        let msg1_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();
        let msg2_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| ((i + 50) as u64) % 100)
            .collect();

        let msg1 = Poly::from_coeffs(msg1_coeffs.clone(), params.q);
        let msg2 = Poly::from_coeffs(msg2_coeffs.clone(), params.q);

        // Encrypt both
        let a1 = random_poly(params.ring_dim, params.q);
        let e1 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk, &msg1, delta, a1, &e1, &ctx);

        let a2 = random_poly(params.ring_dim, params.q);
        let e2 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct2 = RlweCiphertext::encrypt(&sk, &msg2, delta, a2, &e2, &ctx);

        // Homomorphic add
        let ct_sum = ct1.add(&ct2);
        let decrypted = ct_sum.decrypt(&sk, delta, params.p, &ctx);

        // Verify
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

    #[test]
    fn test_homomorphic_subtraction() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg1_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| 200 + (i as u64) % 100)
            .collect();
        let msg2_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();

        let msg1 = Poly::from_coeffs(msg1_coeffs.clone(), params.q);
        let msg2 = Poly::from_coeffs(msg2_coeffs.clone(), params.q);

        let a1 = random_poly(params.ring_dim, params.q);
        let e1 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk, &msg1, delta, a1, &e1, &ctx);

        let a2 = random_poly(params.ring_dim, params.q);
        let e2 = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct2 = RlweCiphertext::encrypt(&sk, &msg2, delta, a2, &e2, &ctx);

        let ct_diff = ct1.sub(&ct2);
        let decrypted = ct_diff.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg1_coeffs[i] - msg2_coeffs[i]) % params.p;
            assert_eq!(
                decrypted.coeff(i),
                expected,
                "Mismatch at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_scalar_multiplication() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 50).collect();
        let message = Poly::from_coeffs(msg_coeffs.clone(), params.q);

        let a = random_poly(params.ring_dim, params.q);
        let e = sample_error_poly(params.ring_dim, params.q, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a, &e, &ctx);

        let scalar = 3u64;
        let ct_scaled = ct.scalar_mul(scalar);
        let decrypted = ct_scaled.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg_coeffs[i] * scalar) % params.p;
            assert_eq!(
                decrypted.coeff(i),
                expected,
                "Mismatch at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_zero_ciphertext() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let zero_ct = RlweCiphertext::zero(&params);
        let decrypted = zero_ct.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0);
        }
    }

    #[test]
    fn test_crs_mode_encryption() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        // Simulate CRS: a publicly known random polynomial
        let crs_a = random_poly(params.ring_dim, params.q);

        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let message = Poly::from_coeffs(msg_coeffs.clone(), params.q);
        let error = sample_error_poly(params.ring_dim, params.q, &mut sampler);

        let ct = RlweCiphertext::encrypt_with_crs(&sk, &message, delta, &crs_a, &error, &ctx);
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(
                decrypted.coeff(i),
                msg_coeffs[i],
                "Mismatch at coefficient {}",
                i
            );
        }
    }
}
