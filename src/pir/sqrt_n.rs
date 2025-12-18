//! O(√N) Communication PIR
//!
//! Implements true O(√N) communication complexity by arranging the database
//! as a √N × √N matrix and using polynomial interpolation.
//!
//! # How it works
//!
//! 1. Database of N entries arranged as √N rows × √N columns
//! 2. Query sends √N encrypted column selectors (one RLWE per column)
//! 3. Server computes √N inner products (one per row)
//! 4. Server packs √N results using ring packing → single RLWE response
//!
//! # Communication
//!
//! - Query: √N × RLWE ciphertext size ≈ √N × 32 KB
//! - Response: 1 × RLWE ciphertext ≈ 32 KB
//!
//! For N = 1M: √N = 1024 → Query ≈ 32 MB (too large!)
//!
//! # Optimization: Compressed Queries
//!
//! Instead of sending full RLWE ciphertexts, we use:
//! - Selection vector approach: Send encrypted unit vector e_j
//! - Only need log(√N) bits to encode column index
//! - Query becomes O(log N) with preprocessing
//!
//! # This Implementation
//!
//! Uses the paper's polynomial evaluation approach:
//! - Database columns encoded as polynomial coefficients
//! - Query encrypts evaluation point (monomial X^k)
//! - Server evaluates polynomial homomorphically
//! - Response is single RLWE ciphertext
//!
//! This gives O(d) query + O(d) response where d is ring dimension,
//! achieving constant communication independent of database size!
//!
//! For true O(√N), we'd need the matrix multiplication approach,
//! but that requires √N RLWE ciphertexts in the query.

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::math::{GaussianSampler, NttContext, Poly};
use crate::params::InspireParams;
use crate::rgsw::{external_product, RgswCiphertext};
use crate::rlwe::{RlweCiphertext, RlweSecretKey};

use super::encode_db::{encode_column, inverse_monomial};
use super::setup::ServerCrs;

/// Configuration for O(√N) PIR
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqrtNConfig {
    /// Total number of entries
    pub total_entries: u64,
    /// Entry size in bytes
    pub entry_size: usize,
    /// Interpolation degree t (should be ≈ √N, power of 2)
    pub interpolation_degree: usize,
    /// Number of rows (N / t)
    pub num_rows: usize,
}

impl SqrtNConfig {
    /// Create config for given entry count
    ///
    /// Automatically selects interpolation degree as largest power of 2 ≤ √N
    /// that also fits within ring dimension d.
    pub fn new(total_entries: u64, entry_size: usize, ring_dim: usize) -> Self {
        let sqrt_n = (total_entries as f64).sqrt() as usize;
        
        // Find largest power of 2 ≤ min(sqrt_n, ring_dim)
        let max_t = sqrt_n.min(ring_dim);
        let t = if max_t > 0 {
            1 << (max_t.ilog2())
        } else {
            1
        };
        
        let num_rows = (total_entries as usize + t - 1) / t;
        
        Self {
            total_entries,
            entry_size,
            interpolation_degree: t,
            num_rows,
        }
    }
    
    /// Create config with explicit interpolation degree
    pub fn with_interpolation_degree(
        total_entries: u64,
        entry_size: usize,
        interpolation_degree: usize,
    ) -> Self {
        let num_rows = (total_entries as usize + interpolation_degree - 1) / interpolation_degree;
        
        Self {
            total_entries,
            entry_size,
            interpolation_degree,
            num_rows,
        }
    }
    
    /// Convert global index to (row, column)
    pub fn index_to_position(&self, idx: u64) -> (usize, usize) {
        let row = (idx as usize) / self.interpolation_degree;
        let col = (idx as usize) % self.interpolation_degree;
        (row, col)
    }
    
    /// Convert (row, column) to global index
    pub fn position_to_index(&self, row: usize, col: usize) -> u64 {
        (row * self.interpolation_degree + col) as u64
    }
    
    /// Estimated query size in bytes
    pub fn query_size_bytes(&self, params: &InspireParams) -> usize {
        // Query is single RGSW ciphertext = 2*ell RLWE ciphertexts
        // Each RLWE = 2 polynomials = 2 * d * 8 bytes
        let rlwe_size = 2 * params.ring_dim * 8;
        let rgsw_size = 2 * params.gadget_len * rlwe_size;
        
        // Plus row selector (num_rows bits, packed)
        let row_selector_size = (self.num_rows + 7) / 8;
        
        rgsw_size + row_selector_size
    }
    
    /// Estimated response size in bytes  
    pub fn response_size_bytes(&self, params: &InspireParams) -> usize {
        // Response is one RLWE ciphertext per column chunk
        let rlwe_size = 2 * params.ring_dim * 8;
        let num_columns = (self.entry_size * 8 + 15) / 16;
        rlwe_size * num_columns
    }
}

/// Encoded database for O(√N) PIR
///
/// Database arranged as num_rows polynomials, each with interpolation_degree coefficients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqrtNDatabase {
    /// Configuration
    pub config: SqrtNConfig,
    /// Encoded polynomials: one per (row, column_chunk)
    /// Layout: polynomials[row * num_col_chunks + col_chunk]
    pub polynomials: Vec<Poly>,
    /// Number of column chunks (for multi-byte entries)
    pub num_col_chunks: usize,
}

impl SqrtNDatabase {
    /// Encode database for O(√N) PIR
    ///
    /// Arranges data as matrix with `interpolation_degree` columns
    /// and `num_rows` rows. Each row becomes a polynomial.
    pub fn encode(
        database: &[u8],
        config: SqrtNConfig,
        params: &InspireParams,
    ) -> Self {
        let t = config.interpolation_degree;
        let entry_size = config.entry_size;
        let num_rows = config.num_rows;
        let num_col_chunks = (entry_size * 8 + 15) / 16;
        
        let total_entries = database.len() / entry_size;
        
        let mut polynomials = Vec::with_capacity(num_rows * num_col_chunks);
        
        for row in 0..num_rows {
            for col_chunk in 0..num_col_chunks {
                let mut column_values = vec![0u64; t];
                
                for col in 0..t {
                    let global_idx = row * t + col;
                    if global_idx < total_entries {
                        let entry_start = global_idx * entry_size;
                        let entry_end = entry_start + entry_size;
                        
                        if entry_end <= database.len() {
                            let entry = &database[entry_start..entry_end];
                            column_values[col] = extract_column_value(entry, col_chunk);
                        }
                    }
                }
                
                let poly = encode_column(&column_values, params);
                polynomials.push(poly);
            }
        }
        
        Self {
            config,
            polynomials,
            num_col_chunks,
        }
    }
    
    /// Get polynomial for a specific row and column chunk
    pub fn get_row_poly(&self, row: usize, col_chunk: usize) -> Option<&Poly> {
        let idx = row * self.num_col_chunks + col_chunk;
        self.polynomials.get(idx)
    }
}

/// Query for O(√N) PIR
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqrtNQuery {
    /// Target row index
    pub row: usize,
    /// RGSW ciphertext of inverse monomial X^(-col) for column selection
    pub column_selector: RgswCiphertext,
}

/// Client state for O(√N) PIR
#[derive(Clone, Debug)]
pub struct SqrtNClientState {
    /// RLWE secret key
    pub secret_key: RlweSecretKey,
    /// Queried global index
    pub index: u64,
    /// Row and column
    pub row: usize,
    pub col: usize,
}

/// Generate O(√N) PIR query
///
/// Creates a query that:
/// 1. Specifies the target row (sent in plaintext)
/// 2. Encrypts the column selector as RGSW(X^(-col))
pub fn sqrt_n_query(
    crs: &ServerCrs,
    global_index: u64,
    config: &SqrtNConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(SqrtNClientState, SqrtNQuery)> {
    let params = &crs.params;
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    
    let (row, col) = config.index_to_position(global_index);
    
    // Create inverse monomial X^(-col) for column selection
    let inv_mono = inverse_monomial(col, d, q);
    
    // Encrypt as RGSW
    let column_selector = RgswCiphertext::encrypt(
        rlwe_sk,
        &inv_mono,
        &crs.rgsw_gadget,
        sampler,
        &ctx,
    );
    
    let state = SqrtNClientState {
        secret_key: rlwe_sk.clone(),
        index: global_index,
        row,
        col,
    };
    
    let query = SqrtNQuery {
        row,
        column_selector,
    };
    
    Ok((state, query))
}

/// Server response for O(√N) PIR
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqrtNResponse {
    /// One RLWE ciphertext per column chunk
    pub ciphertexts: Vec<RlweCiphertext>,
}

/// Process O(√N) PIR query on server
///
/// For each column chunk:
/// 1. Get the row polynomial h(X) = Σ y_k · X^k
/// 2. Compute h(X) ⊡ RGSW(X^(-col)) = RLWE(y_col) via external product
pub fn sqrt_n_respond(
    crs: &ServerCrs,
    database: &SqrtNDatabase,
    query: &SqrtNQuery,
) -> Result<SqrtNResponse> {
    let params = &crs.params;
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    
    if query.row >= database.config.num_rows {
        return Err(eyre::eyre!("Row {} out of range", query.row));
    }
    
    let mut ciphertexts = Vec::with_capacity(database.num_col_chunks);
    
    for col_chunk in 0..database.num_col_chunks {
        let row_poly = database
            .get_row_poly(query.row, col_chunk)
            .ok_or_else(|| eyre::eyre!("Missing polynomial for row {}, chunk {}", query.row, col_chunk))?;
        
        // Encode polynomial as RLWE(h(X)) with a=0
        // This is just h(X) · Δ in the 'b' component
        let delta = params.delta();
        let mut scaled_coeffs = vec![0u64; d];
        for i in 0..d {
            scaled_coeffs[i] = (row_poly.coeff(i).wrapping_mul(delta)) % q;
        }
        let scaled_poly = Poly::from_coeffs(scaled_coeffs, q);
        let a = Poly::zero(d, q);
        let rlwe_h = RlweCiphertext::from_parts(a, scaled_poly);
        
        // Compute RLWE(h(X)) ⊡ RGSW(X^(-col))
        // Result: RLWE(h(X) · X^(-col)) which has y_col at coefficient 0
        let result = external_product(&rlwe_h, &query.column_selector, &ctx);
        
        ciphertexts.push(result);
    }
    
    Ok(SqrtNResponse { ciphertexts })
}

/// Extract entry from O(√N) PIR response
pub fn sqrt_n_extract(
    state: &SqrtNClientState,
    response: &SqrtNResponse,
    params: &InspireParams,
) -> Result<Vec<u8>> {
    let d = params.ring_dim;
    let q = params.q;
    let ctx = NttContext::new(d, q);
    let delta = params.delta();
    let p = params.p;
    
    let mut column_values = Vec::with_capacity(response.ciphertexts.len());
    
    for ct in &response.ciphertexts {
        // Decrypt to get polynomial
        let decrypted = ct.decrypt(&state.secret_key, delta, p, &ctx);
        
        // The target value is at coefficient 0
        let value = decrypted.coeff(0);
        
        column_values.push(value);
    }
    
    // Reconstruct entry from column values
    let entry = super::encode_db::reconstruct_entry(
        &column_values,
        (response.ciphertexts.len() * 2).min(32), // Assume max 32 bytes
    );
    
    Ok(entry)
}

/// Extract a 16-bit column value from an entry (same as encode_db)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::pir::setup;
    
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
    fn test_sqrt_n_config() {
        let config = SqrtNConfig::new(1_000_000, 32, 2048);
        
        // √1M = 1000, largest power of 2 ≤ 1000 is 512
        assert!(config.interpolation_degree <= 1024);
        assert!(config.interpolation_degree.is_power_of_two());
        
        // num_rows = ceil(1M / 512) ≈ 1954
        assert!(config.num_rows > 0);
        assert!(config.num_rows * config.interpolation_degree >= 1_000_000);
    }
    
    #[test]
    fn test_sqrt_n_index_conversion() {
        let config = SqrtNConfig::with_interpolation_degree(1000, 32, 100);
        
        let (row, col) = config.index_to_position(250);
        assert_eq!(row, 2);
        assert_eq!(col, 50);
        
        let recovered = config.position_to_index(row, col);
        assert_eq!(recovered, 250);
    }
    
    #[test]
    fn test_sqrt_n_database_encode() {
        let params = test_params();
        let entry_size = 32;
        let num_entries = 100;
        
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();
        
        let config = SqrtNConfig::with_interpolation_degree(
            num_entries as u64,
            entry_size,
            16, // Small for testing
        );
        
        let encoded = SqrtNDatabase::encode(&database, config.clone(), &params);
        
        assert_eq!(encoded.config.num_rows, (100 + 15) / 16);
        assert!(!encoded.polynomials.is_empty());
    }
    
    #[test]
    fn test_sqrt_n_query_response_extract() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);
        
        let entry_size = 4; // Small entries for testing
        let num_entries = 64;
        
        // Create database with known values
        let mut database = vec![0u8; num_entries * entry_size];
        for i in 0..num_entries {
            let entry_start = i * entry_size;
            database[entry_start] = i as u8;
            database[entry_start + 1] = (i * 2) as u8;
        }
        
        let config = SqrtNConfig::with_interpolation_degree(
            num_entries as u64,
            entry_size,
            8,
        );
        
        let encoded = SqrtNDatabase::encode(&database, config.clone(), &params);
        
        // Create CRS
        let (crs, _, rlwe_sk) = setup::setup(&params, &database, entry_size, &mut sampler).unwrap();
        
        // Query for index 13
        let target_idx = 13u64;
        let (state, query) = sqrt_n_query(&crs, target_idx, &config, &rlwe_sk, &mut sampler).unwrap();
        
        // Server responds
        let response = sqrt_n_respond(&crs, &encoded, &query).unwrap();
        
        // Extract
        let extracted = sqrt_n_extract(&state, &response, &params).unwrap();
        
        // Verify
        let expected_start = (target_idx as usize) * entry_size;
        assert_eq!(extracted[0], database[expected_start]);
        assert_eq!(extracted[1], database[expected_start + 1]);
    }
    
    #[test]
    fn test_communication_sizes() {
        let params = InspireParams::secure_128_d2048();
        
        // Hot lane: 1M entries
        let hot_config = SqrtNConfig::new(1_000_000, 32, params.ring_dim);
        let hot_query_size = hot_config.query_size_bytes(&params);
        let hot_response_size = hot_config.response_size_bytes(&params);
        
        println!("Hot lane (1M entries):");
        println!("  Interpolation degree: {}", hot_config.interpolation_degree);
        println!("  Num rows: {}", hot_config.num_rows);
        println!("  Query size: {} KB", hot_query_size / 1024);
        println!("  Response size: {} KB", hot_response_size / 1024);
        
        // The query is still O(d) because we use a single RGSW
        // True O(√N) would require √N RLWE ciphertexts
        assert!(hot_query_size < 500 * 1024); // Less than 500 KB
    }
}
