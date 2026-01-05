//! Discrete Gaussian sampling
//!
//! Provides samplers for discrete Gaussian distributions over Z,
//! used for generating error terms in lattice-based cryptography.

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Default Gaussian standard deviation
pub const DEFAULT_SIGMA: f64 = 3.2;

/// Discrete Gaussian sampler over Z using rejection sampling
#[derive(Clone)]
pub struct GaussianSampler {
    /// Standard deviation σ
    sigma: f64,
    /// Tailcut: reject samples beyond this many standard deviations
    tailcut: usize,
    /// RNG for sampling
    rng: ChaCha20Rng,
}

impl GaussianSampler {
    /// Create a new Gaussian sampler with given standard deviation
    pub fn new(sigma: f64) -> Self {
        Self::with_seed(sigma, 0)
    }

    /// Create a new Gaussian sampler with given seed for deterministic sampling
    pub fn with_seed(sigma: f64, seed: u64) -> Self {
        let tailcut = (sigma * 6.0).ceil() as usize;
        let rng = ChaCha20Rng::seed_from_u64(seed);

        Self {
            sigma,
            tailcut,
            rng,
        }
    }

    /// Create sampler from byte seed
    pub fn from_seed(sigma: f64, seed: [u8; 32]) -> Self {
        let tailcut = (sigma * 6.0).ceil() as usize;
        let rng = ChaCha20Rng::from_seed(seed);

        Self {
            sigma,
            tailcut,
            rng,
        }
    }

    /// Get the standard deviation
    pub fn sigma(&self) -> f64 {
        self.sigma
    }

    /// Sample a single value from the discrete Gaussian D_σ
    /// Returns a signed integer in centered representation
    pub fn sample(&mut self) -> i64 {
        self.sample_rejection()
    }

    /// Sample a single value as unsigned, centered around 0
    /// Positive values: 0, 1, 2, ...
    /// Negative values: q-1, q-2, ... (represented as large positive in Z_q)
    pub fn sample_centered(&mut self, q: u64) -> u64 {
        let s = self.sample();
        if s >= 0 {
            s as u64
        } else {
            q.wrapping_add(s as u64)
        }
    }

    /// Sample a vector of Gaussian values
    pub fn sample_vec(&mut self, len: usize) -> Vec<i64> {
        (0..len).map(|_| self.sample()).collect()
    }

    /// Sample a vector of Gaussian values as unsigned mod q
    pub fn sample_vec_centered(&mut self, len: usize, q: u64) -> Vec<u64> {
        (0..len).map(|_| self.sample_centered(q)).collect()
    }

    /// Rejection sampling for discrete Gaussian
    fn sample_rejection(&mut self) -> i64 {
        let sigma_sq_2 = 2.0 * self.sigma * self.sigma;
        let bound = self.tailcut as i64;

        loop {
            // Sample uniformly from [-bound, bound]
            let x = self.rng.gen_range(-bound..=bound);

            // Accept with probability proportional to exp(-x²/(2σ²))
            let x_sq = (x * x) as f64;
            let prob = (-x_sq / sigma_sq_2).exp();

            let u: f64 = self.rng.gen();
            if u < prob {
                return x;
            }
        }
    }

    /// Reseed the sampler
    pub fn reseed(&mut self, seed: u64) {
        self.rng = ChaCha20Rng::seed_from_u64(seed);
    }
}

impl std::fmt::Debug for GaussianSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GaussianSampler")
            .field("sigma", &self.sigma)
            .field("tailcut", &self.tailcut)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_basic_sampling() {
        let mut sampler = GaussianSampler::new(DEFAULT_SIGMA);

        let tailcut_bound = (6.0 * DEFAULT_SIGMA).ceil() as i64;
        for _ in 0..1000 {
            let s = sampler.sample();
            assert!(
                s.abs() <= tailcut_bound,
                "Sample {} exceeds tailcut bound {}",
                s,
                tailcut_bound
            );
        }
    }

    #[test]
    fn test_deterministic_seeding() {
        let mut sampler1 = GaussianSampler::with_seed(DEFAULT_SIGMA, 12345);
        let mut sampler2 = GaussianSampler::with_seed(DEFAULT_SIGMA, 12345);

        for _ in 0..100 {
            assert_eq!(sampler1.sample(), sampler2.sample());
        }
    }

    #[test]
    fn test_different_seeds() {
        let mut sampler1 = GaussianSampler::with_seed(DEFAULT_SIGMA, 12345);
        let mut sampler2 = GaussianSampler::with_seed(DEFAULT_SIGMA, 54321);

        let samples1: Vec<i64> = (0..100).map(|_| sampler1.sample()).collect();
        let samples2: Vec<i64> = (0..100).map(|_| sampler2.sample()).collect();

        assert_ne!(samples1, samples2);
    }

    #[test]
    fn test_centered_representation() {
        let q: u64 = 1152921504606830593;
        let mut sampler = GaussianSampler::new(DEFAULT_SIGMA);

        for _ in 0..1000 {
            let s = sampler.sample_centered(q);
            let centered = if s <= q / 2 {
                s as i64
            } else {
                s as i64 - q as i64
            };
            assert!(centered.abs() <= (6.0 * DEFAULT_SIGMA).ceil() as i64);
        }
    }

    #[test]
    fn test_sample_vec() {
        let mut sampler = GaussianSampler::new(DEFAULT_SIGMA);
        let vec = sampler.sample_vec(100);
        assert_eq!(vec.len(), 100);
    }

    #[test]
    fn test_distribution_symmetry() {
        let mut sampler = GaussianSampler::with_seed(DEFAULT_SIGMA, 42);
        let n = 100_000;

        let mut pos_count = 0;
        let mut neg_count = 0;
        let mut zero_count = 0;

        for _ in 0..n {
            let s = sampler.sample();
            if s > 0 {
                pos_count += 1;
            } else if s < 0 {
                neg_count += 1;
            } else {
                zero_count += 1;
            }
        }

        let ratio = pos_count as f64 / neg_count as f64;
        assert!(
            (ratio - 1.0).abs() < 0.05,
            "Distribution not symmetric: pos={}, neg={}, ratio={}",
            pos_count,
            neg_count,
            ratio
        );

        assert!(zero_count > n / 50, "Zero count {} is too low", zero_count);
    }

    #[test]
    fn test_distribution_mean() {
        let mut sampler = GaussianSampler::with_seed(DEFAULT_SIGMA, 42);
        let n = 100_000;

        let sum: i64 = (0..n).map(|_| sampler.sample()).sum();
        let mean = sum as f64 / n as f64;

        assert!(mean.abs() < 0.1, "Mean {} is too far from 0", mean);
    }

    #[test]
    fn test_distribution_variance() {
        let mut sampler = GaussianSampler::with_seed(DEFAULT_SIGMA, 42);
        let n = 100_000;

        let samples: Vec<i64> = (0..n).map(|_| sampler.sample()).collect();
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let variance: f64 = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n as f64;

        let expected_variance = DEFAULT_SIGMA * DEFAULT_SIGMA;
        let relative_error = (variance - expected_variance).abs() / expected_variance;

        assert!(
            relative_error < 0.1,
            "Variance {} differs from expected {} by {:.1}%",
            variance,
            expected_variance,
            relative_error * 100.0
        );
    }

    #[test]
    fn test_distribution_shape() {
        let mut sampler = GaussianSampler::with_seed(DEFAULT_SIGMA, 42);
        let n = 100_000;

        let mut histogram: HashMap<i64, usize> = HashMap::new();
        for _ in 0..n {
            let s = sampler.sample();
            *histogram.entry(s).or_insert(0) += 1;
        }

        let count_0 = *histogram.get(&0).unwrap_or(&0);
        let count_5 = *histogram.get(&5).unwrap_or(&0) + *histogram.get(&-5).unwrap_or(&0);
        let count_10 = *histogram.get(&10).unwrap_or(&0) + *histogram.get(&-10).unwrap_or(&0);

        assert!(
            count_0 > count_5,
            "0 should be more frequent than ±5: {} vs {}",
            count_0,
            count_5
        );
        assert!(
            count_5 > count_10,
            "±5 should be more frequent than ±10: {} vs {}",
            count_5,
            count_10
        );
    }

    #[test]
    fn test_tailcut_bounds() {
        let sigma = 3.2;
        let mut sampler = GaussianSampler::new(sigma);
        let tailcut_bound = (6.0 * sigma).ceil() as i64;

        for _ in 0..100_000 {
            let s = sampler.sample();
            assert!(
                s.abs() <= tailcut_bound,
                "Sample {} exceeds 6σ bound of {}",
                s,
                tailcut_bound
            );
        }
    }

    #[test]
    fn test_reseed() {
        let mut sampler = GaussianSampler::new(DEFAULT_SIGMA);

        sampler.reseed(12345);
        let samples1: Vec<i64> = (0..10).map(|_| sampler.sample()).collect();

        sampler.reseed(12345);
        let samples2: Vec<i64> = (0..10).map(|_| sampler.sample()).collect();

        assert_eq!(samples1, samples2);
    }

    #[test]
    fn test_different_sigma() {
        let small_sigma = 1.0;
        let large_sigma = 10.0;

        let mut small_sampler = GaussianSampler::with_seed(small_sigma, 42);
        let mut large_sampler = GaussianSampler::with_seed(large_sigma, 42);

        let n = 10_000;
        let small_variance: f64 = {
            let samples: Vec<i64> = (0..n).map(|_| small_sampler.sample()).collect();
            let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
            samples
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / n as f64
        };

        let large_variance: f64 = {
            let samples: Vec<i64> = (0..n).map(|_| large_sampler.sample()).collect();
            let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
            samples
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / n as f64
        };

        assert!(
            large_variance > small_variance * 10.0,
            "Large sigma should have much larger variance"
        );
    }
}
