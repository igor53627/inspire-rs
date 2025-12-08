//! Discrete Gaussian sampling

use rand::Rng;

/// Discrete Gaussian sampler with standard deviation σ
#[derive(Debug, Clone)]
pub struct GaussianSampler {
    sigma: f64,
}

impl GaussianSampler {
    /// Create a new Gaussian sampler with given standard deviation
    pub fn new(sigma: f64) -> Self {
        Self { sigma }
    }

    /// Sample from discrete Gaussian distribution
    ///
    /// Uses Box-Muller transform with rounding for simplicity.
    /// For production, consider using a constant-time sampler.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> i64 {
        // Box-Muller transform
        let u1: f64 = rng.gen();
        let u2: f64 = rng.gen();

        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample = z * self.sigma;

        sample.round() as i64
    }

    /// Sample a vector of n discrete Gaussian values
    pub fn sample_vec<R: Rng>(&self, n: usize, rng: &mut R) -> Vec<i64> {
        (0..n).map(|_| self.sample(rng)).collect()
    }

    /// Get the standard deviation
    pub fn sigma(&self) -> f64 {
        self.sigma
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_gaussian_distribution() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
        let sampler = GaussianSampler::new(3.2);

        let samples: Vec<i64> = (0..10000).map(|_| sampler.sample(&mut rng)).collect();

        // Check mean is close to 0
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.5, "Mean {} should be close to 0", mean);

        // Check standard deviation is close to sigma
        let variance: f64 = samples
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64;
        let std_dev = variance.sqrt();
        assert!(
            (std_dev - 3.2).abs() < 0.5,
            "Std dev {} should be close to 3.2",
            std_dev
        );
    }

    #[test]
    fn test_sample_vec() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(123);
        let sampler = GaussianSampler::new(3.2);

        let samples = sampler.sample_vec(100, &mut rng);
        assert_eq!(samples.len(), 100);
    }
}
