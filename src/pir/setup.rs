//! PIR Setup: Server preprocessing and CRS generation
//!
//! Implements PIR.Setup(1^λ, D) → (crs, D')

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::inspiring::PackingPrecomputation;
use crate::ks::{generate_automorphism_ks_matrix, KeySwitchingMatrix};
use crate::math::{GaussianSampler, NttContext, Poly};
use crate::params::{InspireParams, ShardConfig};
use crate::rgsw::GadgetVector;
use crate::rlwe::{galois_generators, RlweSecretKey};

use super::encode_db::encode_database;

/// Common Reference String containing public parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspireCrs {
    /// System parameters
    pub params: InspireParams,
    /// First key-switching matrix (for cyclic generator g)
    pub k_g: KeySwitchingMatrix,
    /// Second key-switching matrix (for conjugation h)
    pub k_h: KeySwitchingMatrix,
    /// Galois keys for automorphisms
    pub galois_keys: Vec<KeySwitchingMatrix>,
    /// RGSW gadget vector parameters
    pub rgsw_gadget: GadgetVector,
    /// Fixed random vectors for CRS mode (one per LWE ciphertext slot)
    pub crs_a_vectors: Vec<Vec<u64>>,
    /// RLWE secret key (used for consistent encryption across setup and query)
    pub rlwe_secret_key: RlweSecretKey,
}

impl InspireCrs {
    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.params.ring_dim
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.params.q
    }
}

/// Encoded database ready for PIR queries
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedDatabase {
    /// Database shards
    pub shards: Vec<ShardData>,
    /// Shard configuration
    pub config: ShardConfig,
}

/// Single database shard with encoded polynomials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardData {
    /// Shard identifier
    pub id: u32,
    /// Database entries encoded as polynomial coefficients
    pub polynomials: Vec<Poly>,
    /// Precomputed packing data for this shard
    pub precomputation: PackingPrecomputation,
}

/// PIR.Setup(1^λ, D) → (crs, D')
///
/// Generates the Common Reference String and encodes the database.
///
/// # Arguments
/// * `params` - System parameters
/// * `database` - Raw database bytes (entries concatenated)
/// * `entry_size` - Size of each database entry in bytes
/// * `sampler` - Gaussian sampler for key generation
///
/// # Returns
/// * `InspireCrs` - Common reference string with public parameters
/// * `EncodedDatabase` - Database encoded as polynomials ready for PIR
pub fn setup(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    sampler: &mut GaussianSampler,
) -> Result<(InspireCrs, EncodedDatabase)> {
    params.validate().map_err(|e| eyre::eyre!(e))?;

    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    let total_entries = database.len() / entry_size;
    let shard_config = ShardConfig {
        shard_size_bytes: (d as u64) * (entry_size as u64),
        entry_size_bytes: entry_size,
        total_entries: total_entries as u64,
    };

    let rlwe_sk = RlweSecretKey::generate(params, sampler);

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

    let (g1, g2) = galois_generators(d);

    let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g1, &gadget, sampler, &ctx);
    let k_h = generate_automorphism_ks_matrix(&rlwe_sk, g2, &gadget, sampler, &ctx);

    let mut galois_keys = Vec::new();
    let mut g_power = g1;
    let log_d = (d as f64).log2() as usize;
    for _ in 0..log_d {
        let ks_matrix = generate_automorphism_ks_matrix(&rlwe_sk, g_power, &gadget, sampler, &ctx);
        galois_keys.push(ks_matrix);
        g_power = (g_power * g_power) % (2 * d);
    }

    let crs_a_vectors: Vec<Vec<u64>> = (0..d)
        .map(|_| {
            let poly = Poly::random(d, q);
            poly.coeffs().to_vec()
        })
        .collect();

    let shard_data = encode_database(database, entry_size, params, &shard_config, &crs_a_vectors, &k_g, &k_h);

    let crs = InspireCrs {
        params: params.clone(),
        k_g,
        k_h,
        galois_keys,
        rgsw_gadget: gadget,
        crs_a_vectors,
        rlwe_secret_key: rlwe_sk,
    };

    let encoded_db = EncodedDatabase {
        shards: shard_data,
        config: shard_config,
    };

    Ok((crs, encoded_db))
}

/// Generate CRS for testing (with known secret key)
///
/// This variant returns the secret key for testing purposes.
#[allow(dead_code)]
pub fn setup_with_secret_key(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    sampler: &mut GaussianSampler,
) -> Result<(InspireCrs, EncodedDatabase, RlweSecretKey)> {
    params.validate().map_err(|e| eyre::eyre!(e))?;

    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);

    let total_entries = database.len() / entry_size;
    let shard_config = ShardConfig {
        shard_size_bytes: (d as u64) * (entry_size as u64),
        entry_size_bytes: entry_size,
        total_entries: total_entries as u64,
    };

    let rlwe_sk = RlweSecretKey::generate(params, sampler);

    let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, q);

    let (g1, g2) = galois_generators(d);

    let k_g = generate_automorphism_ks_matrix(&rlwe_sk, g1, &gadget, sampler, &ctx);
    let k_h = generate_automorphism_ks_matrix(&rlwe_sk, g2, &gadget, sampler, &ctx);

    let mut galois_keys = Vec::new();
    let mut g_power = g1;
    let log_d = (d as f64).log2() as usize;
    for _ in 0..log_d {
        let ks_matrix = generate_automorphism_ks_matrix(&rlwe_sk, g_power, &gadget, sampler, &ctx);
        galois_keys.push(ks_matrix);
        g_power = (g_power * g_power) % (2 * d);
    }

    let crs_a_vectors: Vec<Vec<u64>> = (0..d)
        .map(|_| {
            let poly = Poly::random(d, q);
            poly.coeffs().to_vec()
        })
        .collect();

    let shard_data = encode_database(database, entry_size, params, &shard_config, &crs_a_vectors, &k_g, &k_h);

    let crs = InspireCrs {
        params: params.clone(),
        k_g,
        k_h,
        galois_keys,
        rgsw_gadget: gadget,
        crs_a_vectors,
        rlwe_secret_key: rlwe_sk.clone(),
    };

    let encoded_db = EncodedDatabase {
        shards: shard_data,
        config: shard_config,
    };

    Ok((crs, encoded_db, rlwe_sk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            p: 65536,
            sigma: 3.2,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    #[test]
    fn test_setup_produces_valid_crs() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let result = setup(&params, &database, entry_size, &mut sampler);
        assert!(result.is_ok());

        let (crs, encoded_db) = result.unwrap();

        assert_eq!(crs.ring_dim(), params.ring_dim);
        assert_eq!(crs.modulus(), params.q);
        assert_eq!(crs.crs_a_vectors.len(), params.ring_dim);
        assert_eq!(crs.k_g.gadget_len(), params.gadget_len);
        assert_eq!(crs.k_h.gadget_len(), params.gadget_len);

        assert!(!encoded_db.shards.is_empty());
    }

    #[test]
    fn test_setup_with_secret_key() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let result = setup_with_secret_key(&params, &database, entry_size, &mut sampler);
        assert!(result.is_ok());

        let (crs, encoded_db, sk) = result.unwrap();

        assert_eq!(sk.ring_dim(), params.ring_dim);
        assert!(!encoded_db.shards.is_empty());
        assert_eq!(crs.params.ring_dim, params.ring_dim);
    }

    #[test]
    fn test_setup_empty_database() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let database: Vec<u8> = vec![];

        let result = setup(&params, &database, entry_size, &mut sampler);
        assert!(result.is_ok());

        let (_, encoded_db) = result.unwrap();
        assert!(encoded_db.shards.is_empty() || encoded_db.shards[0].polynomials.is_empty());
    }
}
