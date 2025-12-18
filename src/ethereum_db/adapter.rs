//! Ethereum state database adapter for InsPIRe PIR

use std::fs::File;
use std::path::Path;

use eyre::{ensure, Context, Result};
use memmap2::Mmap;

use crate::params::{InspireParams, ShardConfig};

use super::mapping::{AccountMapping, StorageMapping};

/// Entry size in bytes (32-byte words)
const ENTRY_SIZE: usize = 32;

/// Number of words per account (nonce, balance, bytecode_hash)
const WORDS_PER_ACCOUNT: usize = 3;

/// Logical item types for Ethereum state queries
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalItem {
    /// Account query by address
    Account { address: [u8; 20] },
    /// Storage slot query by address and slot key
    Storage { address: [u8; 20], slot: [u8; 32] },
}

/// Decoded account data from database
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountData {
    /// Account nonce
    pub nonce: u64,
    /// Account balance as U256 bytes (big-endian)
    pub balance: [u8; 32],
    /// Keccak256 hash of account bytecode
    pub bytecode_hash: [u8; 32],
}

impl AccountData {
    /// Decode account data from 3 consecutive 32-byte words
    pub fn from_words(words: &[[u8; 32]; 3]) -> Self {
        let nonce = {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&words[0][24..32]);
            u64::from_be_bytes(bytes)
        };

        Self {
            nonce,
            balance: words[1],
            bytecode_hash: words[2],
        }
    }

    /// Encode account data to 3 consecutive 32-byte words
    pub fn to_words(&self) -> [[u8; 32]; 3] {
        let mut nonce_word = [0u8; 32];
        nonce_word[24..32].copy_from_slice(&self.nonce.to_be_bytes());

        [nonce_word, self.balance, self.bytecode_hash]
    }
}

/// Ethereum state database handle
///
/// Provides efficient access to Ethereum state data produced by plinko-extractor.
pub struct EthereumStateDb {
    database: Mmap,
    account_map: AccountMapping,
    storage_map: StorageMapping,
    entry_count: u64,
    entry_size: usize,
}

impl EthereumStateDb {
    /// Open database from plinko-extractor output directory
    ///
    /// Expects the directory to contain:
    /// - `database.bin`: Flat binary with 32-byte entries
    /// - `account-mapping.bin`: Address → Index mapping
    /// - `storage-mapping.bin`: (Address, SlotKey) → Index mapping
    pub fn open(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("database.bin");
        let account_map_path = data_dir.join("account-mapping.bin");
        let storage_map_path = data_dir.join("storage-mapping.bin");

        let db_file = File::open(&db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

        let metadata = db_file.metadata()?;
        let file_size = metadata.len() as usize;

        ensure!(
            file_size % ENTRY_SIZE == 0,
            "Database file size {} is not a multiple of entry size {}",
            file_size,
            ENTRY_SIZE
        );

        let entry_count = (file_size / ENTRY_SIZE) as u64;

        // SAFETY: File is opened read-only
        let database = unsafe { Mmap::map(&db_file)? };

        let account_map = AccountMapping::load(&account_map_path)?;
        let storage_map = StorageMapping::load(&storage_map_path)?;

        Ok(Self {
            database,
            account_map,
            storage_map,
            entry_count,
            entry_size: ENTRY_SIZE,
        })
    }

    /// Get total number of 32-byte entries in the database
    #[inline]
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Get entry size in bytes
    #[inline]
    pub fn entry_size(&self) -> usize {
        self.entry_size
    }

    /// Get reference to account mapping
    #[inline]
    pub fn account_map(&self) -> &AccountMapping {
        &self.account_map
    }

    /// Get reference to storage mapping
    #[inline]
    pub fn storage_map(&self) -> &StorageMapping {
        &self.storage_map
    }

    /// Convert logical item to flat database index
    ///
    /// Returns None if the item is not found in the mappings.
    pub fn logical_to_index(&self, item: &LogicalItem) -> Option<u64> {
        match item {
            LogicalItem::Account { address } => self.account_map.lookup(address),
            LogicalItem::Storage { address, slot } => self.storage_map.lookup(address, slot),
        }
    }

    /// Read a single 32-byte entry at the given index
    pub fn read_entry(&self, index: u64) -> Result<[u8; 32]> {
        ensure!(
            index < self.entry_count,
            "Entry index {} out of bounds (max {})",
            index,
            self.entry_count
        );

        let offset = index as usize * ENTRY_SIZE;
        let mut entry = [0u8; 32];
        entry.copy_from_slice(&self.database[offset..offset + ENTRY_SIZE]);
        Ok(entry)
    }

    /// Read account data (3 consecutive entries = 96 bytes)
    pub fn read_account(&self, address: &[u8; 20]) -> Result<AccountData> {
        let base_idx = self
            .account_map
            .lookup(address)
            .ok_or_else(|| eyre::eyre!("Account not found: 0x{}", hex::encode(address)))?;

        let words = [
            self.read_entry(base_idx)?,
            self.read_entry(base_idx + 1)?,
            self.read_entry(base_idx + 2)?,
        ];

        Ok(AccountData::from_words(&words))
    }

    /// Read storage value (1 entry = 32 bytes)
    pub fn read_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> Result<[u8; 32]> {
        let idx = self.storage_map.lookup(address, slot).ok_or_else(|| {
            eyre::eyre!(
                "Storage slot not found: 0x{} slot 0x{}",
                hex::encode(address),
                hex::encode(slot)
            )
        })?;

        self.read_entry(idx)
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

            let mut shard_data = Vec::with_capacity((end_idx - start_idx) * ENTRY_SIZE);
            for idx in start_idx..end_idx {
                let entry = self.read_entry(idx as u64)?;
                shard_data.extend_from_slice(&entry);
            }

            if shard_data.len() < entries_per_shard * ENTRY_SIZE {
                shard_data.resize(entries_per_shard * ENTRY_SIZE, 0);
            }

            shards.push(shard_data);
        }

        Ok(EncodedDatabase {
            shards,
            shard_config,
            entry_size: ENTRY_SIZE,
        })
    }

    /// Stream entries for a specific shard
    pub fn iter_shard(&self, shard_id: u32) -> impl Iterator<Item = [u8; 32]> + '_ {
        let config = self.shard_config();
        let entries_per_shard = config.entries_per_shard();
        let start_idx = shard_id as u64 * entries_per_shard;
        let end_idx = std::cmp::min(start_idx + entries_per_shard, self.entry_count);

        (start_idx..end_idx).map(move |idx| {
            let offset = idx as usize * ENTRY_SIZE;
            let mut entry = [0u8; 32];
            entry.copy_from_slice(&self.database[offset..offset + ENTRY_SIZE]);
            entry
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

/// PIR query builder for Ethereum state
///
/// Helps construct PIR queries for account balances and storage slots.
pub struct EthPirClient {
    shard_config: ShardConfig,
}

impl EthPirClient {
    /// Create a new PIR client with the given shard configuration
    pub fn new(shard_config: ShardConfig) -> Self {
        Self { shard_config }
    }

    /// Prepare query for account data
    ///
    /// Returns (shard_id, local_index) for the first word of the account,
    /// or None if the account is not found.
    pub fn query_account(
        &self,
        address: &[u8; 20],
        account_map: &AccountMapping,
    ) -> Option<(u32, u64)> {
        let global_idx = account_map.lookup(address)?;
        Some(self.shard_config.index_to_shard(global_idx))
    }

    /// Prepare query for storage slot
    ///
    /// Returns (shard_id, local_index) for the storage value,
    /// or None if the slot is not found.
    pub fn query_storage(
        &self,
        address: &[u8; 20],
        slot: &[u8; 32],
        storage_map: &StorageMapping,
    ) -> Option<(u32, u64)> {
        let global_idx = storage_map.lookup(address, slot)?;
        Some(self.shard_config.index_to_shard(global_idx))
    }

    /// Batch multiple queries for efficiency
    ///
    /// Groups queries by shard to minimize the number of PIR operations.
    /// Returns a list of (shard_id, local_indices) pairs.
    pub fn batch_queries<F>(&self, items: &[LogicalItem], lookup: F) -> Vec<(u32, Vec<u64>)>
    where
        F: Fn(&LogicalItem) -> Option<u64>,
    {
        use std::collections::BTreeMap;

        let mut shard_queries: BTreeMap<u32, Vec<u64>> = BTreeMap::new();

        for item in items {
            if let Some(global_idx) = lookup(item) {
                let (shard_id, local_idx) = self.shard_config.index_to_shard(global_idx);
                shard_queries.entry(shard_id).or_default().push(local_idx);
            }
        }

        shard_queries.into_iter().collect()
    }

    /// Get account data indices (all 3 words)
    ///
    /// For accounts, we need to query 3 consecutive entries.
    /// This returns the shard positions for all 3 words.
    pub fn query_account_full(
        &self,
        address: &[u8; 20],
        account_map: &AccountMapping,
    ) -> Option<Vec<(u32, u64)>> {
        let base_idx = account_map.lookup(address)?;

        let positions: Vec<_> = (0..WORDS_PER_ACCOUNT as u64)
            .map(|offset| self.shard_config.index_to_shard(base_idx + offset))
            .collect();

        Some(positions)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_database(
        accounts: &[([u8; 20], AccountData)],
        storage: &[([u8; 20], [u8; 32], [u8; 32])],
    ) -> TempDir {
        let dir = TempDir::new().unwrap();

        let mut db_file = File::create(dir.path().join("database.bin")).unwrap();
        let mut account_map_file = File::create(dir.path().join("account-mapping.bin")).unwrap();
        let mut storage_map_file = File::create(dir.path().join("storage-mapping.bin")).unwrap();

        let mut current_idx: u64 = 0;

        let mut sorted_accounts = accounts.to_vec();
        sorted_accounts.sort_by_key(|(addr, _)| *addr);

        for (addr, data) in &sorted_accounts {
            let words = data.to_words();
            for word in &words {
                db_file.write_all(word).unwrap();
            }

            account_map_file.write_all(addr).unwrap();
            // Use 4-byte LE index to match plinko-extractor format
            account_map_file.write_all(&(current_idx as u32).to_le_bytes()).unwrap();

            current_idx += WORDS_PER_ACCOUNT as u64;
        }

        let mut sorted_storage = storage.to_vec();
        sorted_storage.sort_by_key(|(addr, slot, _)| (*addr, *slot));

        for (addr, slot, value) in &sorted_storage {
            db_file.write_all(value).unwrap();

            storage_map_file.write_all(addr).unwrap();
            storage_map_file.write_all(slot).unwrap();
            // Use 4-byte LE index to match plinko-extractor format
            storage_map_file
                .write_all(&(current_idx as u32).to_le_bytes())
                .unwrap();

            current_idx += 1;
        }

        dir
    }

    #[test]
    fn test_account_data_roundtrip() {
        let data = AccountData {
            nonce: 42,
            balance: [0xAB; 32],
            bytecode_hash: [0xCD; 32],
        };

        let words = data.to_words();
        let recovered = AccountData::from_words(&words);

        assert_eq!(data.nonce, recovered.nonce);
        assert_eq!(data.balance, recovered.balance);
        assert_eq!(data.bytecode_hash, recovered.bytecode_hash);
    }

    #[test]
    fn test_open_database() {
        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0x01; 32],
            bytecode_hash: [0x02; 32],
        };

        let dir = create_test_database(&[(addr, account.clone())], &[]);

        let db = EthereumStateDb::open(dir.path()).unwrap();

        assert_eq!(db.entry_count(), 3);
        assert_eq!(db.account_map().len(), 1);
        assert_eq!(db.storage_map().len(), 0);
    }

    #[test]
    fn test_read_account() {
        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 12345,
            balance: [0xAB; 32],
            bytecode_hash: [0xCD; 32],
        };

        let dir = create_test_database(&[(addr, account.clone())], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let read_account = db.read_account(&addr).unwrap();
        assert_eq!(read_account.nonce, account.nonce);
        assert_eq!(read_account.balance, account.balance);
        assert_eq!(read_account.bytecode_hash, account.bytecode_hash);
    }

    #[test]
    fn test_read_storage() {
        let addr = [0x42u8; 20];
        let slot = [0x01u8; 32];
        let value = [0xEFu8; 32];

        let account = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[(addr, slot, value)]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let read_value = db.read_storage(&addr, &slot).unwrap();
        assert_eq!(read_value, value);
    }

    #[test]
    fn test_logical_to_index() {
        let addr = [0x42u8; 20];
        let slot = [0x01u8; 32];

        let account = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[(addr, slot, [0xFF; 32])]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let account_idx = db.logical_to_index(&LogicalItem::Account { address: addr });
        assert_eq!(account_idx, Some(0));

        let storage_idx = db.logical_to_index(&LogicalItem::Storage {
            address: addr,
            slot,
        });
        assert_eq!(storage_idx, Some(3));

        let missing = db.logical_to_index(&LogicalItem::Account {
            address: [0xFF; 20],
        });
        assert_eq!(missing, None);
    }

    #[test]
    fn test_shard_config() {
        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let config = db.shard_config();
        assert_eq!(config.total_entries, 3);
        assert_eq!(config.entry_size_bytes, 32);
    }

    #[test]
    fn test_iter_shard() {
        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0xAB; 32],
            bytecode_hash: [0xCD; 32],
        };

        let dir = create_test_database(&[(addr, account.clone())], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let entries: Vec<_> = db.iter_shard(0).collect();
        assert_eq!(entries.len(), 3);

        let words = account.to_words();
        assert_eq!(entries[0], words[0]);
        assert_eq!(entries[1], words[1]);
        assert_eq!(entries[2], words[2]);
    }

    #[test]
    fn test_pir_client_query_account() {
        let config = ShardConfig::ethereum_state(1_000_000);
        let client = EthPirClient::new(config.clone());

        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let result = client.query_account(&addr, db.account_map());
        assert!(result.is_some());

        let (shard_id, local_idx) = result.unwrap();
        assert_eq!(shard_id, 0);
        assert_eq!(local_idx, 0);
    }

    #[test]
    fn test_pir_client_query_storage() {
        let addr = [0x42u8; 20];
        let slot = [0x01u8; 32];
        let account = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[(addr, slot, [0xFF; 32])]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let client = EthPirClient::new(db.shard_config());

        let result = client.query_storage(&addr, &slot, db.storage_map());
        assert!(result.is_some());

        let (shard_id, local_idx) = result.unwrap();
        assert_eq!(shard_id, 0);
        assert_eq!(local_idx, 3);
    }

    #[test]
    fn test_pir_client_batch_queries() {
        let addr1 = [0x01u8; 20];
        let addr2 = [0x02u8; 20];

        let account1 = AccountData {
            nonce: 1,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };
        let account2 = AccountData {
            nonce: 2,
            balance: [0; 32],
            bytecode_hash: [0; 32],
        };

        let dir = create_test_database(&[(addr1, account1), (addr2, account2)], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let client = EthPirClient::new(db.shard_config());

        let items = vec![
            LogicalItem::Account { address: addr1 },
            LogicalItem::Account { address: addr2 },
        ];

        let batched = client.batch_queries(&items, |item| db.logical_to_index(item));

        assert_eq!(batched.len(), 1);
        assert_eq!(batched[0].0, 0);
        assert_eq!(batched[0].1.len(), 2);
    }

    #[test]
    fn test_index_conversion_roundtrip() {
        let config = ShardConfig::ethereum_state(100_000_000);

        for global_idx in [0, 1000, 50_000_000, 99_999_999] {
            let (shard_id, local_idx) = config.index_to_shard(global_idx);
            let recovered = config.shard_to_index(shard_id, local_idx);
            assert_eq!(
                global_idx, recovered,
                "Roundtrip failed for index {}",
                global_idx
            );
        }
    }

    #[test]
    fn test_encode_for_pir() {
        let addr = [0x42u8; 20];
        let account = AccountData {
            nonce: 1,
            balance: [0xAB; 32],
            bytecode_hash: [0xCD; 32],
        };

        let dir = create_test_database(&[(addr, account)], &[]);
        let db = EthereumStateDb::open(dir.path()).unwrap();

        let params = InspireParams::default();
        let encoded = db.encode_for_pir(&params).unwrap();

        assert_eq!(encoded.num_shards(), 1);
        assert!(encoded.get_shard(0).is_some());
    }
}
