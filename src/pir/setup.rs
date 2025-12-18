//! PIR Setup: Server preprocessing and CRS generation
//!
//! Implements PIR.Setup(1^λ, D) → (crs, D', sk)
//!
//! The setup phase generates:
//! - `ServerCrs`: Public parameters (key-switching matrices, gadget, CRS vectors)
//! - `EncodedDatabase`: Database encoded as polynomials
//! - `RlweSecretKey`: Client secret key for encryption/decryption

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::ks::{generate_automorphism_ks_matrix, generate_packing_ks_matrix, KeySwitchingMatrix};
use crate::lwe::LweSecretKey;
use crate::math::{GaussianSampler, NttContext, Poly};
use crate::params::{InspireParams, ShardConfig};
use crate::rgsw::GadgetVector;
use crate::rlwe::{galois_generators, RlweSecretKey};

use super::encode_db::encode_database;

/// Server Common Reference String containing public parameters only
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerCrs {
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
    /// Key-switching matrix for InspiRING packing (LWE→RLWE, generator g)
    /// Required for OnePacking/TwoPacking variants
    pub packing_k_g: Option<KeySwitchingMatrix>,
    /// Key-switching matrix for InspiRING packing (LWE→RLWE, conjugation h)
    /// Required for full packing (d ciphertexts)
    pub packing_k_h: Option<KeySwitchingMatrix>,
}

impl ServerCrs {
    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.params.ring_dim
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.params.q
    }
}

/// Type alias for backward compatibility - InspireCrs is now ServerCrs
pub type InspireCrs = ServerCrs;

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
}

/// PIR.Setup(1^λ, D) → (crs, D', sk)
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
/// * `ServerCrs` - Common reference string with public parameters
/// * `EncodedDatabase` - Database encoded as polynomials ready for PIR
/// * `RlweSecretKey` - Secret key for client queries (kept separate from public CRS)
pub fn setup(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    sampler: &mut GaussianSampler,
) -> Result<(ServerCrs, EncodedDatabase, RlweSecretKey)> {
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

    // Generate galois keys for tree packing automorphisms
    // For tree packing we need τ_t where t = d/2^i + 1 for i = 0..log_d
    // These allow combining ciphertexts in the packing tree
    let log_d = (d as f64).log2() as usize;
    let mut galois_keys = Vec::with_capacity(log_d);
    for i in 0..log_d {
        let t = (d >> i) + 1; // t = d/2^i + 1
        let ks_matrix = generate_automorphism_ks_matrix(&rlwe_sk, t, &gadget, sampler, &ctx);
        galois_keys.push(ks_matrix);
    }

    let crs_a_vectors: Vec<Vec<u64>> = (0..d)
        .map(|_| {
            let poly = Poly::random(d, q);
            poly.coeffs().to_vec()
        })
        .collect();

    let lwe_sk = LweSecretKey::from_rlwe(&rlwe_sk);
    let packing_k_g = generate_packing_ks_matrix(&lwe_sk, &rlwe_sk, &gadget, sampler, &ctx);
    let packing_k_h = generate_packing_ks_matrix(&lwe_sk, &rlwe_sk, &gadget, sampler, &ctx);

    let shard_data = encode_database(database, entry_size, params, &shard_config);

    let crs = ServerCrs {
        params: params.clone(),
        k_g,
        k_h,
        galois_keys,
        rgsw_gadget: gadget,
        crs_a_vectors,
        packing_k_g: Some(packing_k_g),
        packing_k_h: Some(packing_k_h),
    };

    let encoded_db = EncodedDatabase {
        shards: shard_data,
        config: shard_config,
    };

    Ok((crs, encoded_db, rlwe_sk))
}

/// Alias for setup() - kept for backward compatibility
///
/// Both `setup` and `setup_with_secret_key` now return the secret key separately.
#[deprecated(since = "0.2.0", note = "Use setup() directly - both now return the secret key")]
#[allow(dead_code)]
pub fn setup_with_secret_key(
    params: &InspireParams,
    database: &[u8],
    entry_size: usize,
    sampler: &mut GaussianSampler,
) -> Result<(ServerCrs, EncodedDatabase, RlweSecretKey)> {
    setup(params, database, entry_size, sampler)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            p: 65536,
            sigma: 6.4,
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

        let (crs, encoded_db, _sk) = result.unwrap();

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

        let (_, encoded_db, _sk) = result.unwrap();
        assert!(encoded_db.shards.is_empty() || encoded_db.shards[0].polynomials.is_empty());
    }
}
