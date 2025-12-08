//! InsPIRe PIR Protocol Implementation
//!
//! This module implements the InsPIRe PIR (Private Information Retrieval) protocol
//! using ring packing (InspiRING) and homomorphic polynomial evaluation.
//!
//! # Protocol Overview
//!
//! 1. **Setup**: Encode database as polynomials, generate CRS (Common Reference String)
//! 2. **Query**: Client sends LWE ciphertexts for index
//! 3. **Respond**: Server packs LWE→RLWE, evaluates polynomials
//! 4. **Extract**: Client decrypts RLWE response
//!
//! # Key Features
//!
//! - Ring packing with only 2 key-switching matrices (InspiRING)
//! - Homomorphic polynomial evaluation for reduced response size
//! - CRS model for server-side preprocessing
//!
//! # Example
//!
//! ```ignore
//! use inspire_pir::pir::{setup, query, respond, extract};
//! use inspire_pir::params::InspireParams;
//!
//! let params = InspireParams::default();
//! let database = vec![0u8; 1024 * 32]; // 1024 entries of 32 bytes each
//! let entry_size = 32;
//!
//! // Server setup
//! let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler)?;
//!
//! // Client query
//! let (state, query) = query(&crs, target_index, &encoded_db.config, &mut sampler)?;
//!
//! // Server response
//! let response = respond(&crs, &encoded_db, &query)?;
//!
//! // Client extraction
//! let entry = extract(&crs, &state, &response, entry_size)?;
//! ```

mod encode_db;
mod eval_poly;
mod extract;
mod query;
mod respond;
mod setup;

pub use encode_db::{encode_column, encode_database, encode_direct, inverse_monomial};
pub use extract::extract;
pub use query::{query, ClientQuery, ClientState};
pub use respond::{respond, ServerResponse};
pub use setup::{setup, EncodedDatabase, InspireCrs, ShardData};
