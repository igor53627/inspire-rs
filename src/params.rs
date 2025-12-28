//! Parameter sets for InsPIRe PIR
//!
//! Based on the paper's 128-bit security parameters validated via lattice-estimator.

use serde::{Deserialize, Serialize};

/// Security level for parameter selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit security (recommended)
    Bits128,
    /// 256-bit security (conservative)
    Bits256,
}

/// InsPIRe protocol variant
///
/// Different variants trade off communication size vs server computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InspireVariant {
    /// InsPIRe^0: No packing
    ///
    /// - Response: One RLWE ciphertext per database column
    /// - Server: Faster (no packing step)
    /// - Use case: Latency-critical, small entries, debugging
    #[default]
    NoPacking,

    /// InsPIRe^1: Single-level InspiRING packing (future)
    ///
    /// - Response: Packed ciphertexts using automorphisms
    /// - Server: Medium (packing overhead)
    /// - Use case: Balanced communication/computation
    #[allow(dead_code)]
    OnePacking,

    /// InsPIRe^2: Two-level InspiRING packing (future)
    ///
    /// - Response: Further packed for minimal communication
    /// - Server: Slower (double packing)
    /// - Use case: Bandwidth-constrained environments
    #[allow(dead_code)]
    TwoPacking,
}

/// Core cryptographic parameters for InsPIRe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspireParams {
    /// Ring dimension d (power of two)
    /// Typical values: 2048, 4096
    pub ring_dim: usize,

    /// Ciphertext modulus q
    /// Must be NTT-friendly: q ≡ 1 (mod 2d)
    pub q: u64,

    /// Plaintext modulus p
    /// For 32-byte entries, we use p = 2^16 and pack across coefficients
    pub p: u64,

    /// Standard deviation for Gaussian error sampling
    pub sigma: f64,

    /// Gadget decomposition base z
    /// Typically a power of two (e.g., 2^16 or 2^26)
    pub gadget_base: u64,

    /// Number of digits in gadget decomposition: ℓ = ⌈log_z(q)⌉
    pub gadget_len: usize,

    /// Target security level
    pub security_level: SecurityLevel,
}

impl InspireParams {
    /// 128-bit secure parameters for d=2048
    /// Suitable for databases up to ~1GB per shard
    pub fn secure_128_d2048() -> Self {
        // NTT-friendly prime: q ≡ 1 (mod 4096)
        // q = 2^60 - 2^14 + 1 = 1152921504606830593
        let q: u64 = 1152921504606830593;
        let gadget_base: u64 = 1 << 20; // 2^20
        let gadget_len = ((q as f64).log2() / 20.0).ceil() as usize; // 3

        Self {
            ring_dim: 2048,
            q,
            p: 65537, // Fermat prime F4, coprime with any power-of-2 ring dimension
            sigma: 6.4,
            gadget_base,
            gadget_len,
            security_level: SecurityLevel::Bits128,
        }
    }

    /// 128-bit secure parameters for d=4096 (more noise margin)
    pub fn secure_128_d4096() -> Self {
        // NTT-friendly prime: q ≡ 1 (mod 8192)
        let q: u64 = 1152921504606830593;
        let gadget_base: u64 = 1 << 20;
        let gadget_len = 3;

        Self {
            ring_dim: 4096,
            q,
            p: 65537, // Fermat prime F4, coprime with any power-of-2 ring dimension
            sigma: 6.4,
            gadget_base,
            gadget_len,
            security_level: SecurityLevel::Bits128,
        }
    }

    /// Scaling factor Δ = ⌊q/p⌋
    pub fn delta(&self) -> u64 {
        self.q / self.p
    }

    /// Check if parameters are valid
    pub fn validate(&self) -> Result<(), &'static str> {
        // Ring dimension must be power of two
        if !self.ring_dim.is_power_of_two() {
            return Err("ring_dim must be a power of two");
        }

        // q must be NTT-friendly: q ≡ 1 (mod 2d)
        if self.q % (2 * self.ring_dim as u64) != 1 {
            return Err("q must be ≡ 1 (mod 2d) for NTT");
        }

        // p must divide q cleanly enough
        if self.q < self.p {
            return Err("q must be >= p");
        }

        Ok(())
    }
}

impl Default for InspireParams {
    fn default() -> Self {
        Self::secure_128_d2048()
    }
}

/// Database sharding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Size of each shard in bytes (default: 1 GB)
    pub shard_size_bytes: u64,

    /// Entry size in bytes (default: 32 for Ethereum state)
    pub entry_size_bytes: usize,

    /// Total number of entries in the database
    pub total_entries: u64,
}

impl ShardConfig {
    /// Create config for Ethereum state database
    pub fn ethereum_state(total_entries: u64) -> Self {
        Self {
            shard_size_bytes: 1 << 30, // 1 GB
            entry_size_bytes: 32,
            total_entries,
        }
    }

    /// Number of entries per shard
    pub fn entries_per_shard(&self) -> u64 {
        self.shard_size_bytes / self.entry_size_bytes as u64
    }

    /// Total number of shards needed
    pub fn num_shards(&self) -> u64 {
        (self.total_entries + self.entries_per_shard() - 1) / self.entries_per_shard()
    }

    /// Convert global index to (shard_id, local_index)
    pub fn index_to_shard(&self, global_idx: u64) -> (u32, u64) {
        let entries_per_shard = self.entries_per_shard();
        let shard_id = (global_idx / entries_per_shard) as u32;
        let local_idx = global_idx % entries_per_shard;
        (shard_id, local_idx)
    }

    /// Convert (shard_id, local_index) to global index
    pub fn shard_to_index(&self, shard_id: u32, local_idx: u64) -> u64 {
        shard_id as u64 * self.entries_per_shard() + local_idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params_valid() {
        let params = InspireParams::default();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_delta_calculation() {
        let params = InspireParams::secure_128_d2048();
        let delta = params.delta();
        // delta = q / p ≈ 2^60 / 2^16 = 2^44
        assert!(delta > 0);
        assert!(delta > (1 << 40)); // Should be large
    }

    #[test]
    fn test_shard_config() {
        // Ethereum mainnet: ~2.4 billion entries
        let config = ShardConfig::ethereum_state(2_417_514_276);

        // Each shard: 1GB / 32B = ~33M entries
        let entries_per_shard = config.entries_per_shard();
        assert_eq!(entries_per_shard, 1 << 25); // 33554432

        // Should need ~72 shards
        let num_shards = config.num_shards();
        assert!(num_shards > 70 && num_shards < 80);
    }

    #[test]
    fn test_index_conversion() {
        let config = ShardConfig::ethereum_state(2_417_514_276);

        // Test roundtrip
        let global_idx = 100_000_000u64;
        let (shard_id, local_idx) = config.index_to_shard(global_idx);
        let recovered = config.shard_to_index(shard_id, local_idx);
        assert_eq!(global_idx, recovered);
    }
}
