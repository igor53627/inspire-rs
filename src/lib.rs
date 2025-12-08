//! InsPIRe: Communication-Efficient PIR with Server-side Preprocessing
//!
//! This crate implements the InsPIRe PIR protocol from the paper:
//! "InsPIRe: Communication-Efficient PIR with Server-side Preprocessing"
//!
//! Key components:
//! - InspiRING: Novel ring packing algorithm (LWE → RLWE) using only 2 key-switching matrices
//! - Homomorphic polynomial evaluation for reduced response size
//! - CRS model for server-side preprocessing

pub mod params;
pub mod math;
pub mod lwe;
pub mod rlwe;
pub mod rgsw;
pub mod ks;
pub mod inspiring;
pub mod pir;
pub mod ethereum_db;

pub use pir::{
    setup, query, respond, extract,
    ServerCrs, InspireCrs, EncodedDatabase, ShardData,
    ClientQuery, ClientState, ServerResponse,
    encode_column, encode_database, encode_direct, inverse_monomial,
    save_shards_binary, load_shard_binary, MmapDatabase,
};

pub use params::{InspireParams, SecurityLevel};
