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

use crate::inspiring::ClientPackingKeys;
use crate::lwe::LweSecretKey;
use crate::math::{GaussianSampler, NttContext};
use crate::modulus_switch::{SwitchedSeededRgswCiphertext, DEFAULT_SWITCHED_Q};
use crate::params::ShardConfig;
use crate::rgsw::{
    switched_gadget_for_params, DEFAULT_SWITCHED_NOISE_SAFETY_FACTOR, GadgetVector,
    RgswCiphertext, SeededRgswCiphertext,
};
use crate::rlwe::RlweSecretKey;

use super::encode_db::inverse_monomial;
use super::setup::ServerCrs;
use super::{error::pir_err, error::Result};

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
    let ctx = NttContext::new(d, q);

    let (shard_id, local_index) = shard_config.index_to_shard(global_index);

    let lwe_sk = rlwe_to_lwe_key(rlwe_sk);

    let inv_mono = inverse_monomial(local_index as usize, d, q);
    let rgsw_ciphertext =
        SeededRgswCiphertext::encrypt(rlwe_sk, &inv_mono, gadget, sampler, &ctx);

    let state = ClientState {
        secret_key: lwe_sk,
        rlwe_secret_key: rlwe_sk.clone(),
        index: global_index,
        shard_id,
        local_index,
    };

    let query = SeededClientQuery {
        shard_id,
        rgsw_ciphertext,
    };

    Ok((state, query))
}

/// Select a switched-query gadget that keeps modulus-switch noise within bounds.
fn switched_gadget_for_params_checked(
    q: u64,
    p: u64,
    switched_q: u64,
) -> Result<GadgetVector> {
    switched_gadget_for_params(q, p, switched_q).ok_or_else(|| {
        let min_switched_q =
            4u64.saturating_mul(p).saturating_mul(DEFAULT_SWITCHED_NOISE_SAFETY_FACTOR as u64);
        pir_err!(
            "No switched gadget satisfies q'={} for q={}, p={} (needs q' >= 4*p*safety_factor ≈ {}). Reduce gadget base or increase q'.",
            switched_q,
            q,
            p,
            min_switched_q
        )
    })
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
    /// InspiRING client packing keys (optional, for InspiRING packing)
    /// Contains y_all = τ_{g^i}(y_body) where y_body = τ_g(s)·G - s·w_mask + error
    #[serde(skip)]
    // Skip during serialization since it's large - generated on server side if needed
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
}

impl SeededClientQuery {
    /// Expand to full ClientQuery by regenerating `a` polynomials from seeds
    ///
    /// Note: This does NOT include InspiRING packing keys since those require
    /// the secret key to generate. Use `expand_with_packing_keys()` if needed.
    pub fn expand(&self) -> ClientQuery {
        ClientQuery {
            shard_id: self.shard_id,
            rgsw_ciphertext: self.rgsw_ciphertext.expand(),
            inspiring_packing_keys: None, // Not available for seeded queries
        }
    }
}

/// Switched seeded client query for maximum bandwidth efficiency
///
/// Combines seed expansion (~50% reduction) with modulus switching (~50% reduction)
/// for approximately 75% total query size reduction.
///
/// For d=2048, ℓ=3:
/// - Full query: ~196 KB
/// - Seeded: ~98 KB
/// - Seeded + Switched: ~50 KB
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchedClientQuery {
    /// Target shard ID
    pub shard_id: u32,
    /// Switched seeded RGSW ciphertext
    pub rgsw_ciphertext: SwitchedSeededRgswCiphertext,
}

impl SwitchedClientQuery {
    /// Expand to full ClientQuery
    ///
    /// First expands modulus (q' → q), then expands seeds (seed → polynomial).
    ///
    /// Note: This does NOT include InspiRING packing keys.
    pub fn expand(&self) -> ClientQuery {
        let seeded = self.rgsw_ciphertext.expand();
        ClientQuery {
            shard_id: self.shard_id,
            rgsw_ciphertext: seeded.expand(),
            inspiring_packing_keys: None,
        }
    }

    /// Expand to SeededClientQuery (intermediate step)
    pub fn expand_to_seeded(&self) -> SeededClientQuery {
        SeededClientQuery {
            shard_id: self.shard_id,
            rgsw_ciphertext: self.rgsw_ciphertext.expand(),
        }
    }
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
    let rgsw_ciphertext =
        RgswCiphertext::encrypt(rlwe_sk, &inv_mono, &crs.rgsw_gadget, sampler, &ctx);

    let state = ClientState {
        secret_key: lwe_sk,
        rlwe_secret_key: rlwe_sk.clone(),
        index: global_index,
        shard_id,
        local_index,
    };

    // Generate InspiRING client packing keys if pack_params available
    let inspiring_packing_keys = if let Some(ref pack_params) = crs.inspiring_pack_params {
        Some(ClientPackingKeys::generate(
            rlwe_sk,
            pack_params,
            crs.inspiring_w_seed,
            sampler,
        ))
    } else {
        None
    };

    let query = ClientQuery {
        shard_id,
        rgsw_ciphertext,
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

/// PIR.Query with seed expansion AND modulus switching for maximum compression
///
/// Combines two compression techniques:
/// - Seed expansion: stores 32-byte seed instead of full `a` polynomial (~50% reduction)
/// - Modulus switching: reduces coefficient size from 8 to 4 bytes (~50% reduction)
///
/// Total reduction: ~75% compared to full query
///
/// # Size Comparison (d=2048)
/// - Full query (ℓ=3): ~196 KB
/// - Seeded query (ℓ=3): ~98 KB  
/// - Switched query size depends on the gadget base chosen to satisfy
///   the noise bound. With the auto-selected gadget for q'=2^30, size is
///   closer to ~95–115 KB (ℓ=6–7).
///
/// # Warning: Noise Amplification
///
/// **This function may produce incorrect results with default parameters.**
///
/// Modulus switching on RGSW ciphertexts introduces rounding errors that are
/// amplified by the external product during server response. With typical
/// parameters (q ≈ 2^60, q' = 2^30, B = 2^20, ℓ = 3), the amplified error
/// exceeds the decryption threshold.
///
/// **Recommended**: Use `query_seeded()` for reliable operation.
/// This function selects a smaller gadget base (larger ℓ) to keep the
/// modulus-switching noise within the decryption bound. This increases
/// query size relative to the idealized ℓ=3 estimate but restores correctness.
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
/// * `SwitchedClientQuery` - Maximum-compression query to send to server
pub fn query_switched(
    crs: &ServerCrs,
    global_index: u64,
    shard_config: &ShardConfig,
    rlwe_sk: &RlweSecretKey,
    sampler: &mut GaussianSampler,
) -> Result<(ClientState, SwitchedClientQuery)> {
    let switched_gadget = switched_gadget_for_params_checked(
        crs.params.q,
        crs.params.p,
        DEFAULT_SWITCHED_Q,
    )?;

    // First create the seeded query with a switched-safe gadget.
    let (state, seeded_query) = seeded_query_with_gadget(
        crs,
        global_index,
        shard_config,
        rlwe_sk,
        sampler,
        &switched_gadget,
    )?;

    // Apply modulus switching for additional compression
    let switched_rgsw = SwitchedSeededRgswCiphertext::from_seeded(
        &seeded_query.rgsw_ciphertext,
        DEFAULT_SWITCHED_Q,
    );

    let query = SwitchedClientQuery {
        shard_id: seeded_query.shard_id,
        rgsw_ciphertext: switched_rgsw,
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

#[cfg(test)]
mod tests {
    use super::*;
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
        use crate::params::InspireParams;

        // Use production parameters for realistic size comparison
        let params = InspireParams::secure_128_d2048();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;

        // Generate all three query types
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
        let (_, switched_query) = query_switched(
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
        let switched_size = bincode::serialize(&switched_query).unwrap().len();

        println!("\n=== Query Size Comparison (d=2048, l=3) ===");
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
        println!(
            "Switched query: {:>8} bytes ({:.1} KB)",
            switched_size,
            switched_size as f64 / 1024.0
        );
        println!("\nReductions:");
        println!(
            "  Seeded vs Full:   {:.1}%",
            100.0 * (1.0 - seeded_size as f64 / full_size as f64)
        );
        println!(
            "  Switched vs Full: {:.1}%",
            100.0 * (1.0 - switched_size as f64 / full_size as f64)
        );

        // Assertions
        assert!(
            seeded_size < full_size,
            "Seeded should be smaller than full"
        );
        assert!(
            switched_size < seeded_size,
            "Switched should be smaller than seeded"
        );
        assert!(
            switched_size < full_size / 2,
            "Switched should be less than half of full"
        );
    }
}
