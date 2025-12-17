//! PIR Respond: Server response computation
//!
//! Implements PIR.Respond(crs, D', query) → response
//!
//! # Direct Coefficient Retrieval via Rotation
//!
//! The database polynomial h(X) stores values as coefficients: h(X) = Σ y_k · X^k
//! The client sends RGSW(X^(-k)) (the inverse monomial for target index k).
//!
//! The server computes: RLWE(h(X)) ⊡ RGSW(X^(-k)) = RLWE(h(X) · X^(-k))
//!
//! This rotation brings y_k to coefficient 0 of the result polynomial.

use eyre::{eyre, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::math::NttContext;
use crate::rgsw::external_product;
use crate::rlwe::RlweCiphertext;

use super::query::ClientQuery;
use super::setup::{EncodedDatabase, ServerCrs};

/// Server response containing RLWE ciphertexts for each column
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    /// RLWE ciphertext encrypting the retrieved entry
    /// For multi-column entries, this contains one ciphertext per column
    pub ciphertext: RlweCiphertext,
    /// Per-column ciphertexts (for proper multi-column extraction)
    pub column_ciphertexts: Vec<RlweCiphertext>,
}

/// PIR.Respond(crs, D', query) → response
///
/// Computes the PIR response using homomorphic rotation (parallel version).
///
/// # Algorithm
/// 1. For each database polynomial h(X) (one per column):
///    - Create trivial RLWE encryption of h(X)
///    - Compute external product: RLWE(h) ⊡ RGSW(X^(-k)) = RLWE(h · X^(-k))
///    - The target value is now at coefficient 0
/// 2. Return encrypted column values
///
/// # Arguments
/// * `crs` - Common reference string (public parameters)
/// * `encoded_db` - Pre-encoded database (polynomials with values as coefficients)
/// * `query` - Client's PIR query containing RGSW encryption of X^(-k)
///
/// # Returns
/// Server response containing encrypted entry value
pub fn respond(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let delta = crs.params.delta();

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| eyre!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
        });
    }

    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            let local_ctx = NttContext::new(d, q);
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product(&rlwe_db, &query.rgsw_ciphertext, &local_ctx)
        })
        .collect();

    let combined = if column_ciphertexts.len() == 1 {
        column_ciphertexts[0].clone()
    } else {
        column_ciphertexts
            .iter()
            .skip(1)
            .fold(column_ciphertexts[0].clone(), |acc, ct| acc.add(ct))
    };

    Ok(ServerResponse {
        ciphertext: combined,
        column_ciphertexts,
    })
}

/// Sequential respond using homomorphic rotation
///
/// Same as `respond` but processes columns sequentially.
/// Useful for benchmarking parallel vs sequential performance.
pub fn respond_sequential(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| eyre!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
        });
    }

    let mut column_ciphertexts = Vec::with_capacity(shard.polynomials.len());
    for db_poly in &shard.polynomials {
        let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
        let rotated = external_product(&rlwe_db, &query.rgsw_ciphertext, &ctx);
        column_ciphertexts.push(rotated);
    }

    let combined = if column_ciphertexts.len() == 1 {
        column_ciphertexts[0].clone()
    } else {
        column_ciphertexts
            .iter()
            .skip(1)
            .fold(column_ciphertexts[0].clone(), |acc, ct| acc.add(ct))
    };

    Ok(ServerResponse {
        ciphertext: combined,
        column_ciphertexts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{GaussianSampler, Poly};
    use crate::pir::query::query;
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
    fn test_respond_produces_valid_ciphertext() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (_state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response = respond(&crs, &encoded_db, &client_query);
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.ciphertext.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_respond_invalid_shard() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 0u64;
        let (_, mut client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        client_query.shard_id = 999;

        let response = respond(&crs, &encoded_db, &client_query);
        assert!(response.is_err());
    }

    #[test]
    fn test_ciphertext_addition() {
        let params = test_params();
        let d = params.ring_dim;
        let q = params.q;

        let a1 = Poly::zero(d, q);
        let mut b1_coeffs = vec![0u64; d];
        b1_coeffs[0] = 100;
        let b1 = Poly::from_coeffs(b1_coeffs, q);
        let ct1 = RlweCiphertext::from_parts(a1, b1);

        let a2 = Poly::zero(d, q);
        let mut b2_coeffs = vec![0u64; d];
        b2_coeffs[0] = 200;
        let b2 = Poly::from_coeffs(b2_coeffs, q);
        let ct2 = RlweCiphertext::from_parts(a2, b2);

        let combined = ct1.add(&ct2);

        assert_eq!(combined.b.coeff(0), 300);
    }
}
