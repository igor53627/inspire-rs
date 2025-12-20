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
#[cfg(feature = "server")]
pub mod ethereum_db;
pub mod modulus_switch;

pub use pir::{
    setup, query, query_seeded, query_switched, 
    respond, respond_with_variant, respond_one_packing,
    respond_seeded, respond_seeded_packed, respond_switched, respond_switched_packed,
    extract, extract_with_variant,
    ServerCrs, InspireCrs, EncodedDatabase, ShardData,
    ClientQuery, ClientState, SeededClientQuery, SwitchedClientQuery, ServerResponse,
    encode_column, encode_database, encode_direct, inverse_monomial,
};

#[cfg(feature = "server")]
pub use pir::{respond_mmap, MmapDatabase, save_shards_binary, load_shard_binary};

pub use params::{InspireParams, InspireVariant, SecurityLevel};
