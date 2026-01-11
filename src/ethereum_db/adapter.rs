//! Ethereum state database adapter for InsPIRe PIR
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

use std::fs::File;
use std::path::Path;

use eyre::{ensure, Context, Result};
use memmap2::Mmap;

use crate::params::{InspireParams, ShardConfig};

use super::state_format::{StateHeader, StorageEntry, STATE_ENTRY_SIZE, STATE_HEADER_SIZE};

/// PIR entry size in bytes (32-byte value only)
const PIR_ENTRY_SIZE: usize = 32;

/// Ethereum state database handle
///
/// Provides efficient access to Ethereum state data in STATE_FORMAT.
pub struct EthereumStateDb {
    mmap: Mmap,
    header: StateHeader,
    entry_count: u64,
}

impl std::fmt::Debug for EthereumStateDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthereumStateDb")
            .field("entry_count", &self.entry_count)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl EthereumStateDb {
    /// Open database from STATE_FORMAT state.bin file
    ///
    /// Accepts either:
    /// - A directory containing `state.bin`
    /// - A direct path to the state file
    pub fn open(data_path: &Path) -> Result<Self> {
        let state_path = if data_path.is_dir() {
            let new_path = data_path.join("state.bin");
            if !new_path.exists() {
                if data_path.join("database.bin").exists() {
                    eyre::bail!(
                        "Found legacy plinko-extractor files but no state.bin; \
                         plinko format is no longer supported. Please regenerate state in STATE_FORMAT."
                    );
                }
                eyre::bail!("state.bin not found in directory: {}", data_path.display());
            }
            new_path
        } else {
            data_path.to_path_buf()
        };

        let file = File::open(&state_path)
            .with_context(|| format!("Failed to open state file: {}", state_path.display()))?;

        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        ensure!(
            file_size >= STATE_HEADER_SIZE,
            "State file too small: {} bytes (expected at least header size {})",
            file_size,
            STATE_HEADER_SIZE
        );

        // SAFETY: read-only mapping
        let mmap = unsafe { Mmap::map(&file)? };

        let header = StateHeader::from_bytes(&mmap[..STATE_HEADER_SIZE])
            .map_err(|e| eyre::eyre!("Failed to parse state header: {}", e))?;

        ensure!(
            header.version == StateHeader::VERSION,
            "Unsupported state file version: {} (expected {})",
            header.version,
            StateHeader::VERSION
        );

        ensure!(
            header.entry_size as usize == STATE_ENTRY_SIZE,
            "Unsupported entry size in state file: {} (expected {})",
            header.entry_size,
            STATE_ENTRY_SIZE
        );

        let entry_count = header.entry_count;
        let expected_size = STATE_HEADER_SIZE + entry_count as usize * STATE_ENTRY_SIZE;
        ensure!(
            file_size == expected_size,
            "State file size mismatch: got {}, expected {} (header says {} entries)",
            file_size,
            expected_size,
            entry_count
        );

        Ok(Self {
            mmap,
            header,
            entry_count,
        })
    }

    /// Get total number of entries in the database
    #[inline]
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Get PIR entry size in bytes (32-byte value)
    #[inline]
    pub fn entry_size(&self) -> usize {
        PIR_ENTRY_SIZE
    }

    /// Get reference to the state header
    #[inline]
    pub fn header(&self) -> &StateHeader {
        &self.header
    }

    /// Read a single 32-byte value at the given index
    ///
    /// Returns only the value portion of the 84-byte entry.
    pub fn read_entry(&self, index: u64) -> Result<[u8; 32]> {
        ensure!(
            index < self.entry_count,
            "Entry index {} out of bounds (max {})",
            index,
            self.entry_count
        );

        let row_offset = STATE_HEADER_SIZE + index as usize * STATE_ENTRY_SIZE;
        let value_offset = row_offset + 52; // address(20) + slot(32) = 52

        let mut value = [0u8; 32];
        value.copy_from_slice(&self.mmap[value_offset..value_offset + 32]);
        Ok(value)
    }

    /// Read a full storage entry (address, slot, value) at the given index
    ///
    /// Used for bucket index construction.
    pub fn read_storage_entry(&self, index: u64) -> Result<StorageEntry> {
        ensure!(
            index < self.entry_count,
            "Entry index {} out of bounds (max {})",
            index,
            self.entry_count
        );

        let row_offset = STATE_HEADER_SIZE + index as usize * STATE_ENTRY_SIZE;
        let row_bytes = &self.mmap[row_offset..row_offset + STATE_ENTRY_SIZE];

        StorageEntry::from_bytes(row_bytes)
            .map_err(|e| eyre::eyre!("Failed to parse storage entry: {}", e))
    }

    /// Iterate over all storage entries
    pub fn iter_entries(&self) -> impl Iterator<Item = StorageEntry> + '_ {
        (0..self.entry_count).map(move |i| self.read_storage_entry(i).expect("valid entry"))
    }

    /// Get shard configuration for this database
    pub fn shard_config(&self) -> ShardConfig {
        ShardConfig::ethereum_state(self.entry_count)
    }

    /// Encode database for InsPIRe PIR
    ///
    /// This prepares the database for PIR queries by organizing entries
    /// into the format expected by the PIR protocol.
    pub fn encode_for_pir(&self, _params: &InspireParams) -> Result<EncodedDatabase> {
        let shard_config = self.shard_config();
        let num_shards = shard_config.num_shards() as usize;
        let entries_per_shard = shard_config.entries_per_shard() as usize;

        let mut shards = Vec::with_capacity(num_shards);

        for shard_id in 0..num_shards {
            let start_idx = shard_id * entries_per_shard;
            let end_idx = std::cmp::min(start_idx + entries_per_shard, self.entry_count as usize);

            let mut shard_data = Vec::with_capacity((end_idx - start_idx) * PIR_ENTRY_SIZE);
            for idx in start_idx..end_idx {
                let entry = self.read_entry(idx as u64)?;
                shard_data.extend_from_slice(&entry);
            }

            if shard_data.len() < entries_per_shard * PIR_ENTRY_SIZE {
                shard_data.resize(entries_per_shard * PIR_ENTRY_SIZE, 0);
            }

            shards.push(shard_data);
        }

        Ok(EncodedDatabase {
            shards,
            shard_config,
            entry_size: PIR_ENTRY_SIZE,
        })
    }

    /// Stream entries for a specific shard
    pub fn iter_shard(&self, shard_id: u32) -> impl Iterator<Item = [u8; 32]> + '_ {
        let config = self.shard_config();
        let entries_per_shard = config.entries_per_shard();
        let start_idx = shard_id as u64 * entries_per_shard;
        let end_idx = std::cmp::min(start_idx + entries_per_shard, self.entry_count);

        (start_idx..end_idx).map(move |idx| {
            let row_offset = STATE_HEADER_SIZE + idx as usize * STATE_ENTRY_SIZE;
            let value_offset = row_offset + 52;
            let mut value = [0u8; 32];
            value.copy_from_slice(&self.mmap[value_offset..value_offset + 32]);
            value
        })
    }
}

/// Encoded database ready for PIR queries
#[derive(Debug, Clone)]
pub struct EncodedDatabase {
    /// Shard data (each shard is a Vec<u8> of packed entries)
    pub shards: Vec<Vec<u8>>,
    /// Shard configuration
    pub shard_config: ShardConfig,
    /// Entry size in bytes
    pub entry_size: usize,
}

impl EncodedDatabase {
    /// Get number of shards
    #[inline]
    pub fn num_shards(&self) -> usize {
        self.shards.len()
    }

    /// Get shard data by ID
    #[inline]
    pub fn get_shard(&self, shard_id: u32) -> Option<&[u8]> {
        self.shards.get(shard_id as usize).map(|s| s.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_state_file(entries: &[StorageEntry]) -> TempDir {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state.bin");

        let header = StateHeader::new(entries.len() as u64, 20_000_000, 1, [0xab; 32]);

        let mut file = File::create(&state_path).unwrap();
        file.write_all(&header.to_bytes()).unwrap();
        for entry in entries {
            file.write_all(&entry.to_bytes()).unwrap();
        }
        file.flush().unwrap();

        dir
    }

    #[test]
    fn test_open_database() {
        let entries = vec![
            StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32]),
            StorageEntry::new([0x42; 20], [0x02; 32], [0xee; 32]),
        ];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        assert_eq!(db.entry_count(), 2);
        assert_eq!(db.entry_size(), 32);
        assert_eq!(db.header().block_number, 20_000_000);
        assert_eq!(db.header().chain_id, 1);
    }

    #[test]
    fn test_read_entry() {
        let entries = vec![
            StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32]),
            StorageEntry::new([0x43; 20], [0x02; 32], [0xee; 32]),
        ];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let value0 = db.read_entry(0).unwrap();
        assert_eq!(value0, [0xff; 32]);

        let value1 = db.read_entry(1).unwrap();
        assert_eq!(value1, [0xee; 32]);
    }

    #[test]
    fn test_read_storage_entry() {
        let entries = vec![StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32])];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let entry = db.read_storage_entry(0).unwrap();
        assert_eq!(entry.address, [0x42; 20]);
        assert_eq!(entry.slot, [0x01; 32]);
        assert_eq!(entry.value, [0xff; 32]);
    }

    #[test]
    fn test_iter_entries() {
        let entries = vec![
            StorageEntry::new([0x01; 20], [0x01; 32], [0x11; 32]),
            StorageEntry::new([0x02; 20], [0x02; 32], [0x22; 32]),
            StorageEntry::new([0x03; 20], [0x03; 32], [0x33; 32]),
        ];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let collected: Vec<_> = db.iter_entries().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0], entries[0]);
        assert_eq!(collected[1], entries[1]);
        assert_eq!(collected[2], entries[2]);
    }

    #[test]
    fn test_shard_config() {
        let entries = vec![StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32])];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let config = db.shard_config();
        assert_eq!(config.total_entries, 1);
        assert_eq!(config.entry_size_bytes, 32);
    }

    #[test]
    fn test_iter_shard() {
        let entries = vec![
            StorageEntry::new([0x01; 20], [0x01; 32], [0x11; 32]),
            StorageEntry::new([0x02; 20], [0x02; 32], [0x22; 32]),
        ];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let values: Vec<_> = db.iter_shard(0).collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], [0x11; 32]);
        assert_eq!(values[1], [0x22; 32]);
    }

    #[test]
    fn test_encode_for_pir() {
        let entries = vec![StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32])];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let params = InspireParams::default();
        let encoded = db.encode_for_pir(&params).unwrap();

        assert_eq!(encoded.num_shards(), 1);
        assert!(encoded.get_shard(0).is_some());
    }

    #[test]
    fn test_legacy_format_error() {
        let dir = TempDir::new().unwrap();
        File::create(dir.path().join("database.bin")).unwrap();

        let result = EthereumStateDb::open(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("plinko format is no longer supported"));
    }

    #[test]
    fn test_open_direct_file_path() {
        let entries = vec![StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32])];

        let dir = create_test_state_file(&entries);
        let state_path = dir.path().join("state.bin");
        let db = EthereumStateDb::open(&state_path).unwrap();

        assert_eq!(db.entry_count(), 1);
    }

    #[test]
    fn test_entry_out_of_bounds() {
        let entries = vec![StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32])];

        let dir = create_test_state_file(&entries);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let result = db.read_entry(1);
        assert!(result.is_err());
    }
}
