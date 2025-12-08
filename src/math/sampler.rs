//! Gaussian sampling for error generation

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

/// Gaussian sampler for error polynomials
pub struct GaussianSampler {
    sigma: f64,
    rng: ChaCha20Rng,
}

impl GaussianSampler {
    /// Create a new Gaussian sampler with given standard deviation
    pub fn new(sigma: f64) -> Self {
        Self {
            sigma,
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    /// Create a seeded sampler for reproducibility
    pub fn with_seed(sigma: f64, seed: u64) -> Self {
        Self {
            sigma,
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Sample from discrete Gaussian using Box-Muller transform
    pub fn sample(&mut self) -> i64 {
        // Box-Muller transform for Gaussian sampling
        let u1: f64 = self.rng.gen_range(0.0001..1.0);
        let u2: f64 = self.rng.gen_range(0.0..1.0);

        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (z * self.sigma).round() as i64
    }

    /// Sample a vector of n discrete Gaussian values centered in Z_q
    pub fn sample_vec_centered(&mut self, n: usize, q: u64) -> Vec<u64> {
        (0..n)
            .map(|_| {
                let sample = self.sample();
                if sample >= 0 {
                    (sample as u64) % q
                } else {
                    q - ((-sample) as u64 % q)
                }
            })
            .collect()
    }

    /// Get the standard deviation
    pub fn sigma(&self) -> f64 {
        self.sigma
    }
}
