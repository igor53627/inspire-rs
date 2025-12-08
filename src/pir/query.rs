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
use crate::math::{GaussianSampler, ModQ, NttContext};
use crate::params::ShardConfig;
use crate::rgsw::RgswCiphertext;
use crate::rlwe::RlweSecretKey;

use super::encode_db::inverse_monomial;
use super::setup::InspireCrs;

/// Client state for extracting response
///
/// Contains secret keys and query metadata needed to decrypt the server's response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    /// LWE secret key (derived from RLWE key)
    pub secret_key: LweSecretKey,
    /// RLWE secret key for decrypting packed response
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
    /// LWE b-values only (a vectors are in CRS)
    pub lwe_b_values: Vec<u64>,
    /// RGSW ciphertext of evaluation point for polynomial evaluation
    pub rgsw_ciphertext: RgswCiphertext,
}

/// PIR.Query(crs, idx) → (state, query)
///
/// Generates a PIR query for the given index.
///
/// The query encrypts the inverse monomial X^(-local_index), which when multiplied
/// with the database polynomial h(X), rotates the target value to coefficient 0.
///
/// # Arguments
/// * `crs` - Common reference string
/// * `global_index` - Index of the entry to retrieve
/// * `shard_config` - Database shard configuration
/// * `sampler` - Gaussian sampler for encryption
///
/// # Returns
/// * `ClientState` - Client-side state for response extraction
/// * `ClientQuery` - Query to send to server
pub fn query(
    crs: &InspireCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, ClientQuery)> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let rlwe_sk = &crs.rlwe_secret_key;
    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let lwe_b_values = generate_indicator_lwe(
        &lwe_sk,
        local_index as usize,
        d,
        delta,
        q,
        &crs.crs_a_vectors,
        sampler,
    );

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
        lwe_b_values,
        rgsw_ciphertext,
    };

    Ok((state, query))
}

/// Generate LWE encryptions of indicator vector
///
/// Creates d LWE ciphertexts where ciphertext i encrypts 1 if i == target_index, else 0.
/// Uses CRS mode: only b values are computed, a vectors are from CRS.
fn generate_indicator_lwe(
    sk: &LweSecretKey,
    target_index: usize,
    d: usize,
    delta: u64,
    q: u64,
    crs_a_vectors: &[Vec<u64>],
    sampler: &mut GaussianSampler,
) -> Vec<u64> {
    let mut b_values = Vec::with_capacity(d);

    for i in 0..d {
        let message = if i == target_index { 1u64 } else { 0u64 };

        let error = sampler.sample();

        let a = &crs_a_vectors[i % crs_a_vectors.len()];
        let inner_product = inner_product_mod(a, &sk.coeffs, q);

        let neg_inner = ModQ::negate(inner_product, q);
        let e_mod = ModQ::from_signed(error, q);
        let delta_m = ModQ::mul(delta, message, q);

        let b = ModQ::add(neg_inner, ModQ::add(e_mod, delta_m, q), q);
        b_values.push(b);
    }

    b_values
}

/// Compute inner product mod q
fn inner_product_mod(a: &[u64], b: &[u64], q: u64) -> u64 {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(0u64, |acc, (&x, &y)| ModQ::add(acc, ModQ::mul(x, y, q), q))
}

/// Convert RLWE secret key to LWE secret key
///
/// The LWE key is the coefficient vector of the RLWE key polynomial.
fn rlwe_to_lwe_key(rlwe_sk: &RlweSecretKey) -> LweSecretKey {
    let coeffs = rlwe_sk.poly.coeffs().to_vec();
    let q = rlwe_sk.modulus();
    LweSecretKey::from_coeffs(coeffs, q)
}

/// Generate query with explicit secret key (for testing)
#[allow(dead_code)]
pub fn query_with_key(
    crs: &InspireCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, ClientQuery)> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let lwe_b_values = generate_indicator_lwe(
        &lwe_sk,
        local_index as usize,
        d,
        delta,
        q,
        &crs.crs_a_vectors,
        sampler,
    );

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
        lwe_b_values,
        rgsw_ciphertext,
    };

    Ok((state, query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lwe::LweCiphertext;
    use crate::math::Poly;
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

        let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &mut sampler).unwrap();

        assert_eq!(state.index, target_index);
        assert_eq!(state.shard_id, client_query.shard_id);
        assert_eq!(client_query.lwe_b_values.len(), params.ring_dim);
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

        let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = params.ring_dim as u64 + 10;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &mut sampler).unwrap();

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

    #[test]
    fn test_indicator_lwe_encryption() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        let d = params.ring_dim;
        let q = params.q;
        let delta = params.delta();

        let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
        let lwe_sk = rlwe_to_lwe_key(&rlwe_sk);

        let crs_a_vectors: Vec<Vec<u64>> = (0..d)
            .map(|_| {
                let poly = Poly::random(d, q);
                poly.coeffs().to_vec()
            })
            .collect();

        let target = 17;
        let b_values = generate_indicator_lwe(
            &lwe_sk,
            target,
            d,
            delta,
            q,
            &crs_a_vectors,
            &mut sampler,
        );

        assert_eq!(b_values.len(), d);

        for (i, &b) in b_values.iter().enumerate() {
            let a = &crs_a_vectors[i];
            let ct = LweCiphertext { a: a.clone(), b, q };
            let decrypted = ct.decrypt(&lwe_sk, delta, params.p);

            if i == target {
                assert_eq!(decrypted, 1, "Target index {} should decrypt to 1", i);
            } else {
                assert_eq!(decrypted, 0, "Non-target index {} should decrypt to 0", i);
            }
        }
    }
}
