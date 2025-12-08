//! PIR Query: Client query generation
//!
//! Implements PIR.Query(crs, idx) → (state, query)
//!
//! # Query Mechanism
//!
//! The database polynomial h(X) stores values as coefficients: h(X) = Σ y_k · X^k
//! To retrieve y_k, the client encrypts the inverse monomial X^(-k).
//! When the server multiplies h(X) · RGSW(X^(-k)), the result has y_k at coefficient 0.

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::lwe::LweSecretKey;
use crate::math::{GaussianSampler, NttContext};
use crate::params::ShardConfig;
use crate::rgsw::RgswCiphertext;
use crate::rlwe::RlweSecretKey;

use super::encode_db::inverse_monomial;
use super::setup::ServerCrs;

/// Client state for extracting response
///
/// Contains secret keys and query metadata needed to decrypt the server's response.
///
/// # Security Note
///
/// The `secret_key` and `rlwe_secret_key` fields are marked with `#[serde(skip)]`
/// to prevent accidental serialization over the network. When this struct is
/// deserialized, those fields will be set to `Default` (empty/zero), making the
/// state unusable for decryption. Only the index metadata will be preserved.
///
/// For local storage of secret keys, serialize the `RlweSecretKey` directly
/// to a separate file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    /// LWE secret key (derived from RLWE key) - NOT serialized
    #[serde(skip, default)]
    pub secret_key: LweSecretKey,
    /// RLWE secret key for decrypting packed response - NOT serialized
    #[serde(skip, default)]
    pub rlwe_secret_key: RlweSecretKey,
    /// Queried index (global)
    pub index: u64,
    /// Shard containing the queried entry
    pub shard_id: u32,
    /// Index within the shard
    pub local_index: u64,
}

/// Client query sent to server
///
/// Contains encrypted index information for PIR retrieval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientQuery {
    /// Target shard ID
    pub shard_id: u32,
    /// RGSW ciphertext of evaluation point for polynomial evaluation
    pub rgsw_ciphertext: RgswCiphertext,
}

/// PIR.Query(crs, idx, sk) → (state, query)
///
/// Generates a PIR query for the given index.
///
/// The query encrypts the inverse monomial X^(-local_index), which when multiplied
/// with the database polynomial h(X), rotates the target value to coefficient 0.
///
/// # Arguments
/// * `crs` - Common reference string (public parameters)
/// * `global_index` - Index of the entry to retrieve
/// * `shard_config` - Database shard configuration
/// * `rlwe_sk` - RLWE secret key (kept separate from public CRS)
/// * `sampler` - Gaussian sampler for encryption
///
/// # Returns
/// * `ClientState` - Client-side state for response extraction
/// * `ClientQuery` - Query to send to server
pub fn query(
    crs: &ServerCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, ClientQuery)> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let ctx = NttContext::new(d, q);

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let inv_mono = inverse_monomial(local_index as usize, d, q);
    let rgsw_ciphertext = RgswCiphertext::encrypt(
        rlwe_sk,
        &inv_mono,
        &crs.rgsw_gadget,
        sampler,
        &ctx,
    );

    let state = ClientState {
        secret_key: lwe_sk,
        rlwe_secret_key: rlwe_sk.clone(),
        index: global_index,
        shard_id,
        local_index,
    };

    let query = ClientQuery {
        shard_id,
        rgsw_ciphertext,
    };

    Ok((state, query))
}

/// Convert RLWE secret key to LWE secret key
///
/// The LWE key is the coefficient vector of the RLWE key polynomial.
fn rlwe_to_lwe_key(rlwe_sk: &RlweSecretKey) -> LweSecretKey {
    let coeffs = rlwe_sk.poly.coeffs().to_vec();
    let q = rlwe_sk.modulus();
    LweSecretKey::from_coeffs(coeffs, q)
}

/// Alias for query() - kept for backward compatibility
#[allow(dead_code)]
pub fn query_with_key(
    crs: &ServerCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, ClientQuery)> {
    query(crs, global_index, shard_config, rlwe_sk, sampler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir::setup::setup;

    fn test_params() -> crate::params::InspireParams {
        crate::params::InspireParams {
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
    fn test_query_generates_valid_output() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        assert_eq!(state.index, target_index);
        assert_eq!(state.shard_id, client_query.shard_id);
    }

    #[test]
    fn test_query_shard_assignment() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim * 2;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = params.ring_dim as u64 + 10;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        assert_eq!(state.shard_id, 1);
        assert_eq!(state.local_index, 10);
        assert_eq!(client_query.shard_id, 1);
    }

    #[test]
    fn test_rlwe_to_lwe_key_conversion() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = rlwe_to_lwe_key(&rlwe_sk);

        assert_eq!(lwe_sk.dim, params.ring_dim);
        assert_eq!(lwe_sk.q, params.q);
        assert_eq!(lwe_sk.coeffs.len(), params.ring_dim);
    }
}
