//! Parameter sets for InsPIRe PIR
//!
//! This module defines the cryptographic parameters for the InsPIRe protocol,
//! including ring dimensions, moduli, and security levels. Parameters are
//! validated via lattice-estimator to ensure 128-bit or 256-bit security.
//!
//! # Overview
//!
//! The InsPIRe protocol requires careful parameter selection to balance:
//! - **Security**: Lattice-based hardness assumptions (LWE/RLWE)
//! - **Correctness**: Noise growth during homomorphic operations
//! - **Efficiency**: Communication and computation costs
//!
//! # Example
//!
//! ```
//! use inspire_pir::params::{InspireParams, SecurityLevel};
//!
//! // Use recommended 128-bit secure parameters
//! let params = InspireParams::secure_128_d2048();
//! assert!(params.validate().is_ok());
//!
//! // Access scaling factor for encoding
//! let delta = params.delta();
//! ```

use serde::{Deserialize, Serialize};

/// Security level for parameter selection.
///
/// Determines the cryptographic strength of the PIR protocol. Higher security
/// levels require larger parameters, increasing communication and computation costs.
///
/// # Variants
///
/// * `Bits128` - 128-bit security, recommended for most applications
/// * `Bits256` - 256-bit security, for high-security environments
///
/// # Example
///
/// ```
/// use inspire_pir::params::SecurityLevel;
///
/// let level = SecurityLevel::Bits128;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit security (recommended for most applications)
    Bits128,
    /// 256-bit security (conservative, for high-security environments)
    Bits256,
}

/// InsPIRe protocol variant controlling the packing strategy.
///
/// Different variants trade off communication size versus server computation time.
/// The InspiRING packing algorithm reduces response size by combining multiple
/// ciphertexts into fewer packed ciphertexts.
///
/// # Variants
///
/// * `NoPacking` - No packing, fastest server response
/// * `OnePacking` - Single-level packing, balanced tradeoff
/// * `TwoPacking` - Two-level packing, minimal communication
///
/// # Example
///
/// ```
/// use inspire_pir::params::InspireVariant;
///
/// let variant = InspireVariant::default(); // NoPacking
/// assert_eq!(variant, InspireVariant::NoPacking);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InspireVariant {
    /// InsPIRe^0: No packing.
    ///
    /// Returns one RLWE ciphertext per database column. This is the fastest
    /// variant on the server side but has the largest response size.
    /// Best for latency-critical applications, small entries, or debugging.
    #[default]
    NoPacking,

    /// InsPIRe^1: Single-level InspiRING packing.
    ///
    /// Packs multiple ciphertexts using automorphism-based tree packing.
    /// Provides a balanced tradeoff between communication and computation.
    /// Best for general-purpose applications.
    #[allow(dead_code)]
    OnePacking,

    /// InsPIRe^2: Two-level InspiRING packing.
    ///
    /// Applies packing twice for minimal communication overhead.
    /// Slower server response but smallest response size.
    /// Best for bandwidth-constrained environments.
    #[allow(dead_code)]
    TwoPacking,
}

/// Core cryptographic parameters for the InsPIRe PIR protocol.
///
/// These parameters control the security, correctness, and efficiency of the protocol.
/// Parameters must satisfy certain constraints for the NTT and lattice-based security.
///
/// # Fields
///
/// * `ring_dim` - Ring dimension d, must be a power of two (typically 2048 or 4096)
/// * `q` - Ciphertext modulus, must be NTT-friendly: q ≡ 1 (mod 2d)
/// * `p` - Plaintext modulus for message encoding
/// * `sigma` - Standard deviation for discrete Gaussian error sampling
/// * `gadget_base` - Base for gadget decomposition (typically 2^20)
/// * `gadget_len` - Number of gadget digits: ℓ = ⌈log_z(q)⌉
/// * `security_level` - Target security level (128-bit or 256-bit)
///
/// # Example
///
/// ```
/// use inspire_pir::params::InspireParams;
///
/// // Use recommended parameters
/// let params = InspireParams::secure_128_d2048();
///
/// // Validate parameters
/// assert!(params.validate().is_ok());
///
/// // Get scaling factor for encoding
/// let delta = params.delta();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspireParams {
    /// Ring dimension d (power of two).
    ///
    /// Determines the polynomial ring R_q = Z_q[X]/(X^d + 1).
    /// Larger values provide more noise margin but increase computation.
    /// Typical values: 2048, 4096.
    pub ring_dim: usize,

    /// Ciphertext modulus q.
    ///
    /// Must be NTT-friendly: q ≡ 1 (mod 2d) to enable fast polynomial multiplication.
    /// Typical value: 2^60 - 2^14 + 1 = 1152921504606830593.
    pub q: u64,

    /// Plaintext modulus p.
    ///
    /// Messages are encoded in Z_p before scaling by Δ = ⌊q/p⌋.
    /// For 32-byte entries, we use p = 65537 (Fermat prime F4).
    pub p: u64,

    /// Standard deviation for discrete Gaussian error sampling.
    ///
    /// Controls the noise added during encryption for security.
    /// Typical value: 6.4 for 128-bit security.
    pub sigma: f64,

    /// Gadget decomposition base z.
    ///
    /// Used for decomposing polynomials into small-norm components.
    /// Larger bases reduce decomposition length but increase noise.
    /// Typical value: 2^20.
    pub gadget_base: u64,

    /// Number of digits in gadget decomposition: ℓ = ⌈log_z(q)⌉.
    ///
    /// Determines the size of key-switching matrices and RGSW ciphertexts.
    /// Typical value: 3 for q ≈ 2^60 and z = 2^20.
    pub gadget_len: usize,

    /// Target security level.
    ///
    /// Validated via lattice-estimator to ensure cryptographic strength.
    pub security_level: SecurityLevel,
}

impl InspireParams {
    /// Creates 128-bit secure parameters with ring dimension d=2048.
    ///
    /// These are the recommended parameters for most applications, providing
    /// a good balance between security, performance, and noise margin.
    /// Suitable for databases up to ~1GB per shard.
    ///
    /// # Returns
    ///
    /// A new `InspireParams` instance with:
    /// - `ring_dim`: 2048
    /// - `q`: 2^60 - 2^14 + 1 (NTT-friendly prime)
    /// - `p`: 65537 (Fermat prime F4)
    /// - `sigma`: 6.4
    /// - `gadget_base`: 2^20
    /// - `gadget_len`: 3
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::InspireParams;
    ///
    /// let params = InspireParams::secure_128_d2048();
    /// assert_eq!(params.ring_dim, 2048);
    /// assert!(params.validate().is_ok());
    /// ```
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

    /// Creates 128-bit secure parameters with ring dimension d=4096.
    ///
    /// These parameters provide more noise margin than d=2048, suitable for
    /// applications requiring additional homomorphic operations or higher
    /// noise tolerance.
    ///
    /// # Returns
    ///
    /// A new `InspireParams` instance with:
    /// - `ring_dim`: 4096
    /// - `q`: 2^60 - 2^14 + 1 (NTT-friendly prime)
    /// - `p`: 65537 (Fermat prime F4)
    /// - `sigma`: 6.4
    /// - `gadget_base`: 2^20
    /// - `gadget_len`: 3
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::InspireParams;
    ///
    /// let params = InspireParams::secure_128_d4096();
    /// assert_eq!(params.ring_dim, 4096);
    /// assert!(params.validate().is_ok());
    /// ```
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

    /// Computes the scaling factor Δ = ⌊q/p⌋.
    ///
    /// The scaling factor is used to encode plaintext messages into ciphertext space.
    /// A message m ∈ Z_p is encoded as Δ·m before encryption, and recovered by
    /// computing ⌊(decrypted_value + Δ/2) / Δ⌋ mod p.
    ///
    /// # Returns
    ///
    /// The scaling factor Δ = ⌊q/p⌋.
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::InspireParams;
    ///
    /// let params = InspireParams::secure_128_d2048();
    /// let delta = params.delta();
    /// // delta ≈ 2^44 for q ≈ 2^60 and p ≈ 2^16
    /// assert!(delta > (1 << 40));
    /// ```
    pub fn delta(&self) -> u64 {
        self.q / self.p
    }

    /// Validates that the parameters satisfy required constraints.
    ///
    /// Checks that:
    /// - `ring_dim` is a power of two
    /// - `q` is NTT-friendly: q ≡ 1 (mod 2d)
    /// - `q >= p` for valid scaling
    ///
    /// # Returns
    ///
    /// `Ok(())` if all constraints are satisfied.
    ///
    /// # Errors
    ///
    /// Returns an error string describing the constraint violation:
    /// - `"ring_dim must be a power of two"` if ring_dim is not a power of 2
    /// - `"q must be ≡ 1 (mod 2d) for NTT"` if q is not NTT-friendly
    /// - `"q must be >= p"` if q < p
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::InspireParams;
    ///
    /// let params = InspireParams::secure_128_d2048();
    /// assert!(params.validate().is_ok());
    ///
    /// // Invalid parameters would fail validation
    /// let invalid = InspireParams {
    ///     ring_dim: 1000, // Not a power of two
    ///     ..params
    /// };
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), &'static str> {
        // Ring dimension must be power of two
        if !self.ring_dim.is_power_of_two() {
            return Err("ring_dim must be a power of two");
        }

        // q must be NTT-friendly: q ≡ 1 (mod 2d)
        if self.q % (2 * self.ring_dim as u64) != 1 {
            return Err("q must be ≡ 1 (mod 2d) for NTT");
        }

        // p must be at most q to allow scaling (Δ = ⌊q/p⌋)
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

/// Database sharding configuration for large-scale PIR.
///
/// Sharding divides a large database into smaller chunks that can be processed
/// independently. This enables memory-mapped access for databases that exceed
/// available RAM (e.g., Ethereum's 73 GB state).
///
/// # Fields
///
/// * `shard_size_bytes` - Size of each shard in bytes (default: 1 GB)
/// * `entry_size_bytes` - Size of each database entry in bytes (default: 32)
/// * `total_entries` - Total number of entries in the database
///
/// # Example
///
/// ```
/// use inspire_pir::params::ShardConfig;
///
/// // Configure for Ethereum state database
/// let config = ShardConfig::ethereum_state(2_417_514_276);
///
/// // Each shard holds ~33M entries (1GB / 32 bytes)
/// assert_eq!(config.entries_per_shard(), 1 << 25);
///
/// // Convert global index to shard coordinates
/// let (shard_id, local_idx) = config.index_to_shard(100_000_000);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Size of each shard in bytes.
    ///
    /// Default: 1 GB (1 << 30 bytes). Larger shards reduce overhead but
    /// require more memory per query.
    pub shard_size_bytes: u64,

    /// Size of each database entry in bytes.
    ///
    /// Default: 32 bytes for Ethereum state (account data or storage slots).
    pub entry_size_bytes: usize,

    /// Total number of entries in the database.
    ///
    /// For Ethereum mainnet, this is approximately 2.4 billion entries.
    pub total_entries: u64,
}

impl ShardConfig {
    /// Creates a shard configuration for Ethereum state database.
    ///
    /// Uses standard Ethereum parameters: 1 GB shards with 32-byte entries.
    /// This configuration is optimized for querying account balances and
    /// storage slots from the Ethereum state trie.
    ///
    /// # Arguments
    ///
    /// * `total_entries` - Total number of entries in the database
    ///
    /// # Returns
    ///
    /// A new `ShardConfig` with:
    /// - `shard_size_bytes`: 1 GB (1 << 30)
    /// - `entry_size_bytes`: 32 bytes
    /// - `total_entries`: as specified
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::ShardConfig;
    ///
    /// // Ethereum mainnet has ~2.4 billion entries
    /// let config = ShardConfig::ethereum_state(2_417_514_276);
    /// assert_eq!(config.entry_size_bytes, 32);
    /// ```
    pub fn ethereum_state(total_entries: u64) -> Self {
        Self {
            shard_size_bytes: 1 << 30, // 1 GB
            entry_size_bytes: 32,
            total_entries,
        }
    }

    /// Computes the number of entries that fit in each shard.
    ///
    /// # Returns
    ///
    /// The number of entries per shard: `shard_size_bytes / entry_size_bytes`.
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::ShardConfig;
    ///
    /// let config = ShardConfig::ethereum_state(1_000_000);
    /// // 1 GB / 32 bytes = 33,554,432 entries per shard
    /// assert_eq!(config.entries_per_shard(), 1 << 25);
    /// ```
    pub fn entries_per_shard(&self) -> u64 {
        self.shard_size_bytes / self.entry_size_bytes as u64
    }

    /// Computes the total number of shards needed for the database.
    ///
    /// Uses ceiling division to ensure all entries are covered.
    ///
    /// # Returns
    ///
    /// The number of shards: `ceil(total_entries / entries_per_shard)`.
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::ShardConfig;
    ///
    /// // Ethereum mainnet needs ~72 shards
    /// let config = ShardConfig::ethereum_state(2_417_514_276);
    /// let num_shards = config.num_shards();
    /// assert!(num_shards > 70 && num_shards < 80);
    /// ```
    pub fn num_shards(&self) -> u64 {
        (self.total_entries + self.entries_per_shard() - 1) / self.entries_per_shard()
    }

    /// Converts a global index to shard coordinates.
    ///
    /// Maps a global database index to the (shard_id, local_index) pair
    /// needed to locate the entry within the sharded database.
    ///
    /// # Arguments
    ///
    /// * `global_idx` - The global index of the entry (0-indexed)
    ///
    /// # Returns
    ///
    /// A tuple `(shard_id, local_index)` where:
    /// - `shard_id` is the shard containing the entry
    /// - `local_index` is the entry's position within that shard
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::ShardConfig;
    ///
    /// let config = ShardConfig::ethereum_state(2_417_514_276);
    /// let (shard_id, local_idx) = config.index_to_shard(100_000_000);
    ///
    /// // Verify roundtrip
    /// let recovered = config.shard_to_index(shard_id, local_idx);
    /// assert_eq!(recovered, 100_000_000);
    /// ```
    pub fn index_to_shard(&self, global_idx: u64) -> (u32, u64) {
        let entries_per_shard = self.entries_per_shard();
        let shard_id = (global_idx / entries_per_shard) as u32;
        let local_idx = global_idx % entries_per_shard;
        (shard_id, local_idx)
    }

    /// Converts shard coordinates to a global index.
    ///
    /// Maps a (shard_id, local_index) pair back to the global database index.
    /// This is the inverse of [`index_to_shard`](Self::index_to_shard).
    ///
    /// # Arguments
    ///
    /// * `shard_id` - The shard identifier
    /// * `local_idx` - The entry's position within the shard
    ///
    /// # Returns
    ///
    /// The global index of the entry.
    ///
    /// # Example
    ///
    /// ```
    /// use inspire_pir::params::ShardConfig;
    ///
    /// let config = ShardConfig::ethereum_state(2_417_514_276);
    ///
    /// // Entry 10 in shard 2
    /// let global_idx = config.shard_to_index(2, 10);
    /// assert_eq!(global_idx, 2 * config.entries_per_shard() + 10);
    /// ```
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
