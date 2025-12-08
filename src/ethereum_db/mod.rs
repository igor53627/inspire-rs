//! Ethereum database integration for InsPIRe PIR
//!
//! This module provides integration with Ethereum state databases produced by
//! plinko-extractor, enabling PIR queries over account balances and storage slots.
//!
//! # File Formats
//!
//! - `database.bin`: Flat binary with 32-byte words
//!   - Accounts: 3 words (nonce, balance, bytecode_hash) = 96 bytes
//!   - Storage: 1 word (value) = 32 bytes
//! - `account-mapping.bin`: Address(20 bytes) + Index(4 bytes LE)
//! - `storage-mapping.bin`: Address(20 bytes) + SlotKey(32 bytes) + Index(4 bytes LE)

mod mapping;
mod adapter;

pub use mapping::{AccountMapping, StorageMapping};
pub use adapter::{AccountData, EthereumStateDb, EthPirClient, LogicalItem};
