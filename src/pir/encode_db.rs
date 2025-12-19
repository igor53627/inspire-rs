//! Database encoding for PIR
//!
//! Encodes database entries as polynomial coefficients for PIR queries.
//!
//! # Direct Coefficient Encoding
//!
//! Values are stored directly as polynomial coefficients:
//! - Given values [y_0, y_1, ..., y_{t-1}], create polynomial h(X) = Σ y_k · X^k
//! - The value y_k is stored at coefficient k
//!
//! To retrieve y_k, the query encrypts X^(-k) (the inverse monomial).
//! Multiplying h(X) · X^(-k) rotates coefficients so y_k appears at position 0.
//!
//! In R_q = Z_q[X]/(X^d + 1), we have X^d = -1, so:
//! - X^(-k) = -X^(d-k) for k > 0
//! - X^(-0) = X^0 = 1

use crate::math::Poly;
use crate::params::{InspireParams, ShardConfig};

use super::setup::ShardData;

/// Encode a database column as polynomial coefficients
///
/// Given t values [y_0, y_1, ..., y_{t-1}], creates polynomial h(X) where
/// the coefficient of X^k is y_k. This allows retrieval via monomial multiplication.
///
/// # Arguments
/// * `column` - Column values to encode (t values)
/// * `params` - System parameters
///
/// # Returns
/// Polynomial h(X) = Σ y_k · X^k
pub fn encode_column(column: &[u64], params: &InspireParams) -> Poly {
    let d = params.ring_dim;
    let q = params.q;

    if column.is_empty() {
        return Poly::zero(d, q);
    }

    encode_direct(column, d, q)
}

/// Direct coefficient encoding: store values as polynomial coefficients
///
/// Creates h(X) = y_0 + y_1·X + y_2·X² + ... + y_{t-1}·X^{t-1}
///
/// # Arguments
/// * `values` - Values to encode at positions 0, 1, ..., t-1
/// * `d` - Ring dimension
/// * `q` - Modulus
///
/// # Returns
/// Polynomial with values stored as coefficients
pub fn encode_direct(values: &[u64], d: usize, q: u64) -> Poly {
    let mut coeffs = vec![0u64; d];
    for (i, &val) in values.iter().enumerate() {
        if i < d {
            coeffs[i] = val % q;
        }
    }
    Poly::from_coeffs(coeffs, q)
}

/// Create inverse monomial X^(-k) mod (X^d + 1)
///
/// In R_q = Z_q[X]/(X^d + 1), we have X^d = -1, so:
/// - X^(-k) = X^(2d-k) mod (X^d + 1)
/// - For k > 0: X^(2d-k) = X^(d + (d-k)) = -X^(d-k)
/// - For k = 0: X^0 = 1
///
/// # Arguments
/// * `k` - The exponent (index to retrieve)
/// * `d` - Ring dimension
/// * `q` - Modulus
///
/// # Returns
/// Polynomial representing X^(-k) = -X^(d-k) for k > 0, or 1 for k = 0
pub fn inverse_monomial(k: usize, d: usize, q: u64) -> Poly {
    let mut coeffs = vec![0u64; d];

    if k == 0 {
        coeffs[0] = 1;
    } else {
        let pos = d - k;
        coeffs[pos] = q - 1; // -1 mod q
    }

    Poly::from_coeffs(coeffs, q)
}

/// Encode full database into polynomial representation
///
/// Splits the database into shards, each containing at most d entries.
/// Each shard is encoded as polynomials ready for PIR queries.
///
/// # Arguments
/// * `database` - Raw database bytes (entries concatenated)
/// * `entry_size` - Size of each entry in bytes
/// * `params` - System parameters
/// * `shard_config` - Configuration for database sharding
///
/// # Returns
/// Vector of ShardData, each containing encoded polynomials
pub fn encode_database(
    database: &[u8],
    entry_size: usize,
    params: &InspireParams,
    shard_config: &ShardConfig,
) -> Vec<ShardData> {
    if database.is_empty() || entry_size == 0 {
        return vec![];
    }

    let total_entries = database.len() / entry_size;
    let entries_per_shard = shard_config.entries_per_shard() as usize;

    debug_assert!(
        entries_per_shard <= params.ring_dim,
        "entries_per_shard ({}) must be <= ring_dim ({})",
        entries_per_shard,
        params.ring_dim
    );

    let mut shards = Vec::new();
    let mut entry_offset = 0;
    let mut shard_id = 0u32;

    while entry_offset < total_entries {
        let actual_entries = std::cmp::min(entries_per_shard, total_entries - entry_offset);

        let num_polys = (entry_size * 8 + 15) / 16;
        let mut polynomials = Vec::with_capacity(num_polys);

        for poly_idx in 0..num_polys {
            let mut column = vec![0u64; entries_per_shard];

            for local_idx in 0..actual_entries {
                let global_entry_idx = entry_offset + local_idx;
                let entry_start = global_entry_idx * entry_size;
                let entry_end = entry_start + entry_size;

                if entry_end <= database.len() {
                    let entry_bytes = &database[entry_start..entry_end];
                    column[local_idx] = extract_column_value(entry_bytes, poly_idx);
                }
            }

            let poly = encode_column(&column, params);
            polynomials.push(poly);
        }

        shards.push(ShardData {
            id: shard_id,
            polynomials,
        });

        entry_offset += actual_entries;
        shard_id += 1;
    }

    shards
}

/// Extract a 16-bit column value from an entry
///
/// Splits entry into 16-bit chunks for polynomial encoding.
fn extract_column_value(entry: &[u8], column_idx: usize) -> u64 {
    let byte_offset = column_idx * 2;

    if byte_offset + 1 < entry.len() {
        let low = entry[byte_offset] as u64;
        let high = entry[byte_offset + 1] as u64;
        low | (high << 8)
    } else if byte_offset < entry.len() {
        entry[byte_offset] as u64
    } else {
        0
    }
}

/// Reconstruct entry from column values
///
/// Inverse of extract_column_value: combines 16-bit values back into bytes.
pub fn reconstruct_entry(column_values: &[u64], entry_size: usize) -> Vec<u8> {
    let mut entry = vec![0u8; entry_size];

    for (col_idx, &val) in column_values.iter().enumerate() {
        let byte_offset = col_idx * 2;

        if byte_offset < entry_size {
            entry[byte_offset] = (val & 0xFF) as u8;
        }
        if byte_offset + 1 < entry_size {
            entry[byte_offset + 1] = ((val >> 8) & 0xFF) as u8;
        }
    }

    entry
}

/// Generate evaluation points (unit monomials ±X^k)
///
/// z_k = X^(2d*k/t) for k = 0..t-1
/// These are t-th roots of unity in the ring R_q = Z_q[X]/(X^d + 1).
///
/// # Arguments
/// * `t` - Number of evaluation points
/// * `d` - Ring dimension
/// * `q` - Modulus
///
/// # Returns
/// Vector of polynomials representing z_k = X^(2d*k/t)
#[allow(dead_code)]
pub fn generate_eval_points_poly(t: usize, d: usize, q: u64) -> Vec<Poly> {
    if t == 0 {
        return vec![];
    }

    let step = (2 * d) / t;
    let mut points = Vec::with_capacity(t);

    for k in 0..t {
        let power = (k * step) % (2 * d);
        let poly = monomial(power, d, q);
        points.push(poly);
    }

    points
}

/// Create monomial X^power mod (X^d + 1)
///
/// X^d = -1, so X^(d+k) = -X^k
#[allow(dead_code)]
fn monomial(power: usize, d: usize, q: u64) -> Poly {
    let mut coeffs = vec![0u64; d];

    if power < d {
        coeffs[power] = 1;
    } else {
        let reduced_power = power - d;
        coeffs[reduced_power] = q - 1;
    }

    Poly::from_coeffs(coeffs, q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::NttContext;

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
    fn test_encode_column_simple() {
        let params = test_params();
        let column = vec![1, 2, 3, 4];

        let poly = encode_column(&column, &params);

        assert_eq!(poly.dimension(), params.ring_dim);
        assert_eq!(poly.coeff(0), 1);
        assert_eq!(poly.coeff(1), 2);
        assert_eq!(poly.coeff(2), 3);
        assert_eq!(poly.coeff(3), 4);
    }

    #[test]
    fn test_encode_direct_stores_coefficients() {
        let d = 256;
        let q = 1152921504606830593u64;
        let values: Vec<u64> = (0..16).map(|i| (i * 7 + 3) as u64).collect();

        let poly = encode_direct(&values, d, q);

        for (i, &val) in values.iter().enumerate() {
            assert_eq!(poly.coeff(i), val, "Coefficient {} should be {}", i, val);
        }
        for i in values.len()..d {
            assert_eq!(poly.coeff(i), 0, "Coefficient {} should be 0", i);
        }
    }

    #[test]
    fn test_encode_direct_empty() {
        let d = 256;
        let q = 1152921504606830593u64;

        let poly = encode_direct(&[], d, q);

        assert!(poly.is_zero());
    }

    #[test]
    fn test_encode_column_empty() {
        let params = test_params();

        let poly = encode_column(&[], &params);

        assert!(poly.is_zero());
    }

    #[test]
    fn test_inverse_monomial_zero() {
        let d = 256;
        let q = 1152921504606830593u64;

        let inv_m0 = inverse_monomial(0, d, q);

        assert_eq!(inv_m0.coeff(0), 1);
        for i in 1..d {
            assert_eq!(inv_m0.coeff(i), 0);
        }
    }

    #[test]
    fn test_inverse_monomial_one() {
        let d = 256;
        let q = 1152921504606830593u64;

        let inv_m1 = inverse_monomial(1, d, q);

        assert_eq!(inv_m1.coeff(d - 1), q - 1);
        for i in 0..(d - 1) {
            assert_eq!(inv_m1.coeff(i), 0);
        }
    }

    #[test]
    fn test_inverse_monomial_rotation() {
        let d = 256;
        let q = 1152921504606830593u64;
        let ctx = NttContext::new(d, q);

        let values: Vec<u64> = (0..d).map(|i| (i + 1) as u64).collect();
        let h = encode_direct(&values, d, q);

        for k in 0..16 {
            let inv_mono = inverse_monomial(k, d, q);
            let rotated = h.mul_ntt(&inv_mono, &ctx);

            let expected = values[k];
            assert_eq!(
                rotated.coeff(0),
                expected,
                "Rotation by {} should bring value {} to position 0",
                k,
                expected
            );
        }
    }

    #[test]
    fn test_extract_reconstruct_entry() {
        let entry: Vec<u8> = (0..32).collect();
        let entry_size = 32;
        let num_cols = (entry_size * 8 + 15) / 16;

        let mut column_values = Vec::new();
        for col_idx in 0..num_cols {
            column_values.push(extract_column_value(&entry, col_idx));
        }

        let reconstructed = reconstruct_entry(&column_values, entry_size);

        assert_eq!(entry, reconstructed);
    }

    #[test]
    fn test_monomial_in_ring() {
        let d = 256;
        let q = 1152921504606830593u64;

        let m0 = monomial(0, d, q);
        assert_eq!(m0.coeff(0), 1);
        for i in 1..d {
            assert_eq!(m0.coeff(i), 0);
        }

        let m1 = monomial(1, d, q);
        assert_eq!(m1.coeff(0), 0);
        assert_eq!(m1.coeff(1), 1);

        let m_d = monomial(d, d, q);
        assert_eq!(m_d.coeff(0), q - 1);
        for i in 1..d {
            assert_eq!(m_d.coeff(i), 0);
        }
    }

    #[test]
    fn test_generate_eval_points_count() {
        let d = 256;
        let q = 1152921504606830593u64;

        for t in [1, 2, 4, 8, 16, 32] {
            let points = generate_eval_points_poly(t, d, q);
            assert_eq!(points.len(), t);
        }
    }

    #[test]
    fn test_generate_eval_points_first() {
        let d = 256;
        let q = 1152921504606830593u64;
        let t = 8;

        let points = generate_eval_points_poly(t, d, q);

        assert_eq!(points[0].coeff(0), 1);
        for i in 1..d {
            assert_eq!(points[0].coeff(i), 0);
        }
    }
}
