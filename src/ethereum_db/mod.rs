//! Ethereum database integration for InsPIRe PIR
//!
//! This module provides integration with Ethereum state databases in STATE_FORMAT,
//! enabling PIR queries over storage slots.
//!
//! # File Format
//!
//! Expects a `state.bin` file with:
//! - 64-byte header: magic ("PIR2"), version, entry_size, entry_count,
//!   block_number, chain_id, block_hash
//! - 84-byte entries: address(20) + slot(32) + value(32)
//!
//! See docs/STATE_FORMAT.md in inspire-exex for the full specification.

mod adapter;
mod state_format;

pub use adapter::{EncodedDatabase, EthereumStateDb};
pub use state_format::{
    StateFormatError, StateHeader, StorageEntry, STATE_ENTRY_SIZE, STATE_HEADER_SIZE, STATE_MAGIC,
};
