//! InsPIRe PIR Protocol Implementation
//!
//! This module implements the InsPIRe PIR (Private Information Retrieval) protocol
//! using RGSW encryption and homomorphic polynomial rotation.
//!
//! # Protocol Overview
//!
//! 1. **Setup**: Encode database as polynomials, generate CRS and secret key
//! 2. **Query**: Client sends RGSW ciphertext encoding the inverse monomial X^(-k)
//! 3. **Respond**: Server performs homomorphic rotation to move target to coefficient 0
//! 4. **Extract**: Client decrypts RLWE response and reads coefficient 0
//!
//! # Key Features
//!
//! - Direct coefficient encoding with RGSW monomial rotation
//! - Only 2 key-switching matrices (InspiRING)
//! - CRS model for server-side preprocessing
//!
//! # Example
//!
//! ```ignore
//! use inspire_pir::pir::{setup, query, respond, extract};
//! use inspire_pir::params::InspireParams;
//! use inspire_pir::math::GaussianSampler;
//!
//! let params = InspireParams::default();
//! let database = vec![0u8; 1024 * 32]; // 1024 entries of 32 bytes each
//! let entry_size = 32;
//! let mut sampler = GaussianSampler::new(params.sigma);
//!
//! // Server setup (returns CRS, encoded DB, and secret key)
//! let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler)?;
//!
//! // Client query (requires secret key)
//! let target_index = 42u64;
//! let (state, query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler)?;
//!
//! // Server response
//! let response = respond(&crs, &encoded_db, &query)?;
//!
//! // Client extraction
//! let entry = extract(&crs, &state, &response, entry_size)?;
//! ```

mod encode_db;
mod error;
mod eval_poly;
mod extract;
#[cfg(feature = "server")]
mod mmap;
mod query;
mod respond;
mod setup;

pub use error::Result;

pub use encode_db::{encode_column, encode_database, encode_direct, inverse_monomial};
pub use extract::{extract, extract_inspiring, extract_two_packing, extract_with_variant};
#[cfg(feature = "server")]
pub use mmap::{load_shard_binary, save_shards_binary, MmapDatabase};
pub use query::{
    query, query_seeded, query_switched, ClientQuery, ClientState, SeededClientQuery,
    SwitchedClientQuery,
};
pub use respond::{
    respond, respond_inspiring, respond_one_packing, respond_seeded, respond_seeded_inspiring,
    respond_seeded_packed, respond_seeded_with_variant, respond_sequential, respond_switched,
    respond_switched_packed, respond_with_variant, ServerResponse,
};
#[cfg(feature = "server")]
pub use respond::{respond_mmap, respond_mmap_one_packing};
pub use setup::{setup, EncodedDatabase, InspireCrs, ServerCrs, ShardData};
