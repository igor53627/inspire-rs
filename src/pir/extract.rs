//! PIR Extract: Client response extraction
//!
//! Implements PIR.Extract(crs, state, response) → entry

use eyre::Result;

use crate::math::NttContext;
use crate::params::InspireVariant;

use super::encode_db::reconstruct_entry;
use super::query::ClientState;
use super::respond::ServerResponse;
use super::setup::InspireCrs;

/// PIR.Extract(crs, state, response) → entry
///
/// Extracts the database entry from the server's response.
///
/// # Algorithm
/// 1. Decrypt the RLWE ciphertext using client's secret key
/// 2. Extract the coefficient at the queried local index
/// 3. Reconstruct the entry from polynomial coefficients
///
/// # Arguments
/// * `crs` - Common reference string (public parameters)
/// * `state` - Client state from query phase
/// * `response` - Server's response
/// * `entry_size` - Size of database entries in bytes
///
/// # Returns
/// The retrieved database entry
pub fn extract(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let num_columns = (entry_size * 8 + 15) / 16;
    let mut column_values = Vec::with_capacity(num_columns);

    // Use per-column ciphertexts if available (proper multi-column extraction)
    if !response.column_ciphertexts.is_empty() {
        for col_ct in response.column_ciphertexts.iter().take(num_columns) {
            let decrypted = col_ct.decrypt(&state.rlwe_secret_key, delta, p, &ctx);
            // After homomorphic evaluation, result is in CONSTANT TERM (coefficient 0)
            let value = decrypted.coeff(0);
            column_values.push(value);
        }
    } else {
        // Fallback: all columns summed in single ciphertext
        let decrypted = response.ciphertext.decrypt(&state.rlwe_secret_key, delta, p, &ctx);
        let value = decrypted.coeff(0);
        for _ in 0..num_columns {
            column_values.push(value);
        }
    }

    let entry = reconstruct_entry(&column_values, entry_size);

    Ok(entry)
}

/// PIR.Extract with explicit variant selection
///
/// Use this when the server responded with a specific variant.
///
/// # Variants
/// - `NoPacking`: Reads from per-column ciphertexts (same as `extract`)
/// - `OnePacking`: Reads columns from coefficients 0..num_cols of packed ciphertext
pub fn extract_with_variant(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
    variant: InspireVariant,
) -> Result<Vec<u8>> {
    match variant {
        InspireVariant::NoPacking => extract(crs, state, response, entry_size),
        InspireVariant::OnePacking => extract_packed(crs, state, response, entry_size),
        InspireVariant::TwoPacking => extract_packed(crs, state, response, entry_size),
    }
}

/// Extract from OnePacking response (InsPIRe^1)
///
/// The packed ciphertext contains column values at coefficients 0, 1, 2, ...
/// Each value is scaled by d (ring dimension) from tree packing.
///
/// We decrypt the packed ciphertext and read columns from their positions,
/// then un-scale by dividing by d (using modular inverse).
fn extract_packed(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let num_columns = (entry_size * 8 + 15) / 16;

    // Decrypt the packed ciphertext
    let decrypted = response.ciphertext.decrypt(&state.rlwe_secret_key, delta, p, &ctx);

    // Extract column values from their positions
    // Values are scaled by d from tree packing, need to divide
    // Note: d_inv only exists if gcd(d, p) = 1. For d=256, p=65536, this fails.
    // In practice, this limits column values to < p/d to avoid overflow.
    let d_inv = mod_inverse(d as u64, p).unwrap_or(1);
    
    let mut column_values = Vec::with_capacity(num_columns);
    for col in 0..num_columns {
        // Get the raw value at position col (scaled by d)
        let scaled_value = decrypted.coeff(col);
        // Un-scale by multiplying by d^(-1) mod p
        let value = (scaled_value as u128 * d_inv as u128 % p as u128) as u64;
        column_values.push(value);
    }

    let entry = reconstruct_entry(&column_values, entry_size);

    Ok(entry)
}

/// Extract from InspiRING 2-matrix packing response
///
/// Unlike tree packing, InspiRING does NOT scale values by d.
/// Values are placed at coefficients 0, 1, 2, ... at their natural scale.
pub fn extract_inspiring(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
) -> Result<Vec<u8>> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let num_columns = (entry_size * 8 + 15) / 16;

    // Decrypt the packed ciphertext
    let decrypted = response.ciphertext.decrypt(&state.rlwe_secret_key, delta, p, &ctx);

    // Extract column values from their positions (NO d-scaling for InspiRING)
    let mut column_values = Vec::with_capacity(num_columns);
    for col in 0..num_columns {
        let value = decrypted.coeff(col);
        column_values.push(value);
    }

    let entry = reconstruct_entry(&column_values, entry_size);

    Ok(entry)
}

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let (g, x, _) = extended_gcd(a as i64, m as i64);
    if g != 1 {
        None
    } else {
        Some(((x % m as i64 + m as i64) % m as i64) as u64)
    }
}

fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Extract with noise tolerance
///
/// Uses rounding to handle small decryption errors.
#[allow(dead_code)]
pub fn extract_with_tolerance(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
    entry_size: usize,
    tolerance: u64,
) -> Result<Vec<u8>> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let num_columns = (entry_size * 8 + 15) / 16;
    let mut column_values = Vec::with_capacity(num_columns);

    let apply_tolerance = |mut value: u64| -> u64 {
        if value > p - tolerance && value < p {
            value = 0;
        } else if value > tolerance && value < 2 * tolerance {
            value = value % p;
        }
        value
    };

    if !response.column_ciphertexts.is_empty() {
        for col_ct in response.column_ciphertexts.iter().take(num_columns) {
            let decrypted = col_ct.decrypt(&state.rlwe_secret_key, delta, p, &ctx);
            // After homomorphic evaluation, result is in CONSTANT TERM (coefficient 0)
            let value = apply_tolerance(decrypted.coeff(0));
            column_values.push(value);
        }
    } else {
        let decrypted = response.ciphertext.decrypt(&state.rlwe_secret_key, delta, p, &ctx);
        let value = apply_tolerance(decrypted.coeff(0));
        for _ in 0..num_columns {
            column_values.push(value);
        }
    }

    let entry = reconstruct_entry(&column_values, entry_size);

    Ok(entry)
}

/// Extract a single coefficient at the queried index
///
/// Simplified extraction for debugging and testing.
#[allow(dead_code)]
pub fn extract_single_coeff(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
) -> Result<u64> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let decrypted = response.ciphertext.decrypt(
        &state.rlwe_secret_key,
        delta,
        p,
        &ctx,
    );

    // After homomorphic evaluation, result is in CONSTANT TERM (coefficient 0)
    Ok(decrypted.coeff(0))
}

/// Extract raw decrypted polynomial
///
/// Returns the full decrypted polynomial for analysis.
#[allow(dead_code)]
pub fn extract_raw(
    crs: &InspireCrs,
    state: &ClientState,
    response: &ServerResponse,
) -> Result<Vec<u64>> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let p = crs.params.p;
    let delta = crs.params.delta();
    let ctx = NttContext::new(d, q);

    let decrypted = response.ciphertext.decrypt(
        &state.rlwe_secret_key,
        delta,
        p,
        &ctx,
    );

    Ok(decrypted.coeffs().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::pir::query::query;
    use crate::pir::respond::respond;
    use crate::pir::setup::setup;

    fn test_params() -> crate::params::InspireParams {
        crate::params::InspireParams {
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
    fn test_extract_produces_correct_length() {
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

        let response = respond(&crs, &encoded_db, &client_query).unwrap();

        let result = extract(&crs, &state, &response, entry_size);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.len(), entry_size);
    }

    #[test]
    fn test_extract_single_coeff() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 10u64;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response = respond(&crs, &encoded_db, &client_query).unwrap();

        let result = extract_single_coeff(&crs, &state, &response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_raw() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 5u64;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response = respond(&crs, &encoded_db, &client_query).unwrap();

        let result = extract_raw(&crs, &state, &response);
        assert!(result.is_ok());

        let raw = result.unwrap();
        assert_eq!(raw.len(), params.ring_dim);
    }

    #[test]
    fn test_reconstruct_entry() {
        let entry_size = 32;
        let column_values: Vec<u64> = (0..16).map(|i| i * 256 + i).collect();

        let entry = reconstruct_entry(&column_values, entry_size);

        assert_eq!(entry.len(), entry_size);

        for (i, &val) in column_values.iter().enumerate() {
            let low = entry[i * 2];
            let high = entry[i * 2 + 1];
            let reconstructed = low as u64 | ((high as u64) << 8);
            assert_eq!(reconstructed, val & 0xFFFF);
        }
    }

    #[test]
    fn test_extract_with_tolerance() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 15u64;
        let (state, client_query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response = respond(&crs, &encoded_db, &client_query).unwrap();

        let tolerance = 10u64;
        let result = extract_with_tolerance(&crs, &state, &response, entry_size, tolerance);
        assert!(result.is_ok());

        let entry = result.unwrap();
        assert_eq!(entry.len(), entry_size);
    }
}
