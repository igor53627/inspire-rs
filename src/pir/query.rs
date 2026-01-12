//! PIR Query: Client query generation
//!
//! Implements PIR.Query(crs, idx) → (state, query)
//!
//! # Query Mechanism
//!
//! The database polynomial h(X) stores values as coefficients: h(X) = Σ y_k · X^k
//! To retrieve y_k, the client encrypts the inverse monomial X^(-k).
//! When the server multiplies h(X) · RGSW(X^(-k)), the result has y_k at coefficient 0.

use serde::{Deserialize, Serialize};

use crate::inspiring::{ClientPackingKeys, PackParams};
use crate::lwe::LweSecretKey;
use crate::math::GaussianSampler;
use crate::params::ShardConfig;
use crate::rgsw::{
    GadgetVector, RgswCiphertext, SeededRgswCiphertext,
};
use crate::rlwe::RlweSecretKey;

use super::encode_db::inverse_monomial;
use super::setup::ServerCrs;
use super::error::Result;

/// Packing algorithm selection for server responses.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackingMode {
    /// Default: require InspiRING packing keys (fast path).
    Inspiring,
    /// Explicitly request tree packing (slower, log(d) matrices).
    Tree,
}

impl Default for PackingMode {
    fn default() -> Self {
        PackingMode::Inspiring
    }
}

/// Build a seeded query using a specific gadget vector.
fn seeded_query_with_gadget(
    crs: &ServerCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
    gadget: &GadgetVector,
) -> Result<(ClientState, SeededClientQuery)> {
    let d = crs.ring_dim();
    let q = crs.modulus();
    let ctx = crs.params.ntt_context();

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let inv_mono = inverse_monomial(local_index as usize, d, q, crs.params.moduli());
    let rgsw_ciphertext = SeededRgswCiphertext::encrypt(rlwe_sk, &inv_mono, gadget, sampler, &ctx);

    let state = ClientState {
        secret_key: lwe_sk,
        rlwe_secret_key: rlwe_sk.clone(),
        index: global_index,
        shard_id,
        local_index,
    };

    let inspiring_packing_keys = maybe_generate_packing_keys(crs, rlwe_sk, sampler);

    let query = SeededClientQuery {
        shard_id,
        rgsw_ciphertext,
        packing_mode: PackingMode::default(),
        inspiring_packing_keys,
    };

    Ok((state, query))
}

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
    /// Packing algorithm selection (default: InspiRING).
    #[serde(default)]
    pub packing_mode: PackingMode,
    /// InspiRING client packing keys (optional, for InspiRING packing)
    /// Contains y_body derived from the client's secret key and shared seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspiring_packing_keys: Option<ClientPackingKeys>,
}

/// Seeded client query for network transmission
///
/// Uses seed expansion to reduce query size by ~50%.
/// Server expands seeds before processing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededClientQuery {
    /// Target shard ID
    pub shard_id: u32,
    /// Seeded RGSW ciphertext (stores seeds instead of full `a` polynomials)
    pub rgsw_ciphertext: SeededRgswCiphertext,
    /// Packing algorithm selection (default: InspiRING).
    #[serde(default)]
    pub packing_mode: PackingMode,
    /// InspiRING client packing keys (optional, for InspiRING packing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspiring_packing_keys: Option<ClientPackingKeys>,
}

impl SeededClientQuery {
    /// Expand to full ClientQuery by regenerating `a` polynomials from seeds
    ///
    /// Note: This preserves InspiRING packing keys when provided.
    pub fn expand(&self) -> ClientQuery {
        ClientQuery {
            shard_id: self.shard_id,
            rgsw_ciphertext: self.rgsw_ciphertext.expand(),
            packing_mode: self.packing_mode,
            inspiring_packing_keys: self.inspiring_packing_keys.clone(),
        }
    }
}

fn maybe_generate_packing_keys(
    crs: &ServerCrs,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Option<ClientPackingKeys> {
    if crs.packing_k_g.is_none() || crs.inspiring_num_columns == 0 {
        return None;
    }

    let pack_params = PackParams::new(&crs.params, crs.inspiring_num_columns);
    Some(ClientPackingKeys::generate(
        rlwe_sk,
        &pack_params,
        crs.inspiring_w_seed,
        sampler,
    ))
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
    let ctx = crs.params.ntt_context();

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let inv_mono = inverse_monomial(local_index as usize, d, q, crs.params.moduli());
    let rgsw_ciphertext =
        RgswCiphertext::encrypt(rlwe_sk, &inv_mono, &crs.rgsw_gadget, sampler, &ctx);

    let state = ClientState {
        secret_key: lwe_sk,
        rlwe_secret_key: rlwe_sk.clone(),
        index: global_index,
        shard_id,
        local_index,
    };

    // Generate InspiRING client packing keys if server supports it
    let inspiring_packing_keys = maybe_generate_packing_keys(crs, rlwe_sk, sampler);

    let query = ClientQuery {
        shard_id,
        rgsw_ciphertext,
        packing_mode: PackingMode::default(),
        inspiring_packing_keys,
    };

    Ok((state, query))
}

/// PIR.Query with seed expansion for reduced bandwidth
///
/// Same as `query()` but returns a SeededClientQuery that's ~50% smaller.
/// Server must call `expand()` before processing.
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
/// * `SeededClientQuery` - Compact query to send to server
pub fn query_seeded(
    crs: &ServerCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, SeededClientQuery)> {
    seeded_query_with_gadget(
        crs,
        global_index,
        shard_config,
        rlwe_sk,
        sampler,
        &crs.rgsw_gadget,
    )
}

/// Convert RLWE secret key to LWE secret key
///
/// The LWE key is the coefficient vector of the RLWE key polynomial.
fn rlwe_to_lwe_key(rlwe_sk: &RlweSecretKey) -> LweSecretKey {
    let d = rlwe_sk.ring_dim();
    let mut coeffs = Vec::with_capacity(d);
    for i in 0..d {
        coeffs.push(rlwe_sk.poly.coeff(i));
    }
    let q = rlwe_sk.modulus();
    LweSecretKey::from_coeffs(coeffs, q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir::setup::setup;

    fn test_params() -> crate::params::InspireParams {
        crate::params::InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            crt_moduli: vec![1152921504606830593],
            p: 65536,
            sigma: 6.4,
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

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (state, client_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

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

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = params.ring_dim as u64 + 10;
        let (state, client_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

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
    fn test_query_size_comparison() {
        // Use production parameters for realistic size comparison
        let params = crate::params::InspireParams {
            ring_dim: 2048,
            q: 1152921504606830593,
            crt_moduli: vec![1152921504606830593],
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        };
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;

        // Generate both query types
        let (_, full_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();
        let (_, seeded_query) = query_seeded(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        // Serialize and compare sizes
        let full_size = bincode::serialize(&full_query).unwrap().len();
        let seeded_size = bincode::serialize(&seeded_query).unwrap().len();

        println!(
            "\n=== Query Size Comparison (d={}, l_full={}) ===",
            params.ring_dim, params.gadget_len
        );
        println!(
            "Full query:     {:>8} bytes ({:.1} KB)",
            full_size,
            full_size as f64 / 1024.0
        );
        println!(
            "Seeded query:   {:>8} bytes ({:.1} KB)",
            seeded_size,
            seeded_size as f64 / 1024.0
        );
        println!("\nReductions:");
        println!(
            "  Seeded vs Full:   {:.1}%",
            100.0 * (1.0 - seeded_size as f64 / full_size as f64)
        );

        // Assertions
        assert!(
            seeded_size < full_size,
            "Seeded should be smaller than full"
        );
    }
}
