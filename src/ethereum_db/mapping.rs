//! Memory-mapped parsing for account and storage mappings

use std::fs::File;
use std::path::Path;

use eyre::{ensure, Context, Result};
use memmap2::Mmap;

/// Entry size for account mapping: Address(20) + Index(8) = 28 bytes
const ACCOUNT_ENTRY_SIZE: usize = 28;

/// Entry size for storage mapping: Address(20) + SlotKey(32) + Index(8) = 60 bytes
const STORAGE_ENTRY_SIZE: usize = 60;

/// Address type alias
pub type Address = [u8; 20];

/// Storage slot type alias
pub type Slot = [u8; 32];

/// Account mapping: Address → Index
///
/// Provides O(log n) lookup for account addresses to their database indices.
/// The mapping file must be sorted by address for binary search.
pub struct AccountMapping {
    mmap: Mmap,
    count: usize,
}

impl AccountMapping {
    /// Load from account-mapping.bin
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open account mapping: {}", path.display()))?;

        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        ensure!(
            file_size % ACCOUNT_ENTRY_SIZE == 0,
            "Account mapping file size {file_size} is not a multiple of entry size {ACCOUNT_ENTRY_SIZE}"
        );

        let count = file_size / ACCOUNT_ENTRY_SIZE;

        // SAFETY: File is opened read-only and we don't modify it
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(Self { mmap, count })
    }

    /// Lookup index for address using binary search
    pub fn lookup(&self, address: &[u8; 20]) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let mut left = 0usize;
        let mut right = self.count;

        while left < right {
            let mid = left + (right - left) / 2;
            let entry_addr = self.get_address(mid);

            match entry_addr.cmp(address) {
                std::cmp::Ordering::Equal => {
                    return Some(self.get_index(mid));
                }
                std::cmp::Ordering::Less => {
                    left = mid + 1;
                }
                std::cmp::Ordering::Greater => {
                    right = mid;
                }
            }
        }

        None
    }

    /// Number of accounts
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get address at index
    #[inline]
    fn get_address(&self, idx: usize) -> &[u8; 20] {
        let offset = idx * ACCOUNT_ENTRY_SIZE;
        self.mmap[offset..offset + 20].try_into().unwrap()
    }

    /// Get database index at entry position
    #[inline]
    fn get_index(&self, idx: usize) -> u64 {
        let offset = idx * ACCOUNT_ENTRY_SIZE + 20;
        let bytes: [u8; 8] = self.mmap[offset..offset + 8].try_into().unwrap();
        u64::from_le_bytes(bytes)
    }

    /// Iterate over all entries (address, index)
    pub fn iter(&self) -> impl Iterator<Item = ([u8; 20], u64)> + '_ {
        (0..self.count).map(|i| {
            let addr = *self.get_address(i);
            let idx = self.get_index(i);
            (addr, idx)
        })
    }
}

/// Storage mapping: (Address, SlotKey) → Index
///
/// Provides O(log n) lookup for storage slots to their database indices.
/// The mapping file must be sorted by (address, slot_key) for binary search.
pub struct StorageMapping {
    mmap: Mmap,
    count: usize,
}

impl StorageMapping {
    /// Load from storage-mapping.bin
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open storage mapping: {}", path.display()))?;

        let metadata = file.metadata()?;
        let file_size = metadata.len() as usize;

        ensure!(
            file_size % STORAGE_ENTRY_SIZE == 0,
            "Storage mapping file size {file_size} is not a multiple of entry size {STORAGE_ENTRY_SIZE}"
        );

        let count = file_size / STORAGE_ENTRY_SIZE;

        // SAFETY: File is opened read-only and we don't modify it
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(Self { mmap, count })
    }

    /// Lookup index for (address, slot_key) using binary search
    pub fn lookup(&self, address: &[u8; 20], slot_key: &[u8; 32]) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let mut left = 0usize;
        let mut right = self.count;

        while left < right {
            let mid = left + (right - left) / 2;
            let (entry_addr, entry_slot) = self.get_key(mid);

            match (entry_addr, entry_slot).cmp(&(address, slot_key)) {
                std::cmp::Ordering::Equal => {
                    return Some(self.get_index(mid));
                }
                std::cmp::Ordering::Less => {
                    left = mid + 1;
                }
                std::cmp::Ordering::Greater => {
                    right = mid;
                }
            }
        }

        None
    }

    /// Number of storage slots
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get (address, slot_key) at index
    #[inline]
    fn get_key(&self, idx: usize) -> (&[u8; 20], &[u8; 32]) {
        let offset = idx * STORAGE_ENTRY_SIZE;
        let addr: &[u8; 20] = self.mmap[offset..offset + 20].try_into().unwrap();
        let slot: &[u8; 32] = self.mmap[offset + 20..offset + 52].try_into().unwrap();
        (addr, slot)
    }

    /// Get database index at entry position
    #[inline]
    fn get_index(&self, idx: usize) -> u64 {
        let offset = idx * STORAGE_ENTRY_SIZE + 52;
        let bytes: [u8; 8] = self.mmap[offset..offset + 8].try_into().unwrap();
        u64::from_le_bytes(bytes)
    }

    /// Iterate over all entries ((address, slot_key), index)
    pub fn iter(&self) -> impl Iterator<Item = ([u8; 20], [u8; 32], u64)> + '_ {
        (0..self.count).map(|i| {
            let (addr, slot) = self.get_key(i);
            let idx = self.get_index(i);
            (*addr, *slot, idx)
        })
    }
}

/// Load account mapping from binary file
pub fn load_account_mapping(path: &Path) -> Result<AccountMapping> {
    AccountMapping::load(path)
}

/// Load storage mapping from binary file
pub fn load_storage_mapping(path: &Path) -> Result<StorageMapping> {
    StorageMapping::load(path)
}

/// Lookup account index using linear search
pub fn lookup_account_index(map: &AccountMapping, address: &[u8; 20]) -> Option<u64> {
    for (addr, idx) in map.iter() {
        if &addr == address {
            return Some(idx);
        }
    }
    None
}

/// Lookup storage index using linear search
pub fn lookup_storage_index(map: &StorageMapping, address: &[u8; 20], slot: &[u8; 32]) -> Option<u64> {
    for (addr, s, idx) in map.iter() {
        if &addr == address && &s == slot {
            return Some(idx);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_account_mapping_file(entries: &[([u8; 20], u64)]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        for (addr, idx) in entries {
            file.write_all(addr).unwrap();
            file.write_all(&idx.to_le_bytes()).unwrap();
        }
        file.flush().unwrap();
        file
    }

    fn create_storage_mapping_file(entries: &[([u8; 20], [u8; 32], u64)]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        for (addr, slot, idx) in entries {
            file.write_all(addr).unwrap();
            file.write_all(slot).unwrap();
            file.write_all(&idx.to_le_bytes()).unwrap();
        }
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_account_mapping_empty() {
        let file = NamedTempFile::new().unwrap();
        let mapping = AccountMapping::load(file.path()).unwrap();
        assert!(mapping.is_empty());
        assert_eq!(mapping.len(), 0);
        assert!(mapping.lookup(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_account_mapping_single() {
        let addr = [0x42u8; 20];
        let file = create_account_mapping_file(&[(addr, 100)]);
        let mapping = AccountMapping::load(file.path()).unwrap();

        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.lookup(&addr), Some(100));
        assert!(mapping.lookup(&[0u8; 20]).is_none());
    }

    #[test]
    fn test_account_mapping_multiple() {
        let mut entries: Vec<([u8; 20], u64)> = (0..10u8)
            .map(|i| {
                let mut addr = [0u8; 20];
                addr[0] = i;
                (addr, i as u64 * 100)
            })
            .collect();
        entries.sort_by_key(|(addr, _)| *addr);

        let file = create_account_mapping_file(&entries);
        let mapping = AccountMapping::load(file.path()).unwrap();

        assert_eq!(mapping.len(), 10);

        for (addr, expected_idx) in &entries {
            assert_eq!(mapping.lookup(addr), Some(*expected_idx));
        }

        let missing = [0xFFu8; 20];
        assert!(mapping.lookup(&missing).is_none());
    }

    #[test]
    fn test_account_mapping_iter() {
        let entries: Vec<([u8; 20], u64)> = (0..5u8)
            .map(|i| {
                let mut addr = [0u8; 20];
                addr[0] = i;
                (addr, i as u64)
            })
            .collect();

        let file = create_account_mapping_file(&entries);
        let mapping = AccountMapping::load(file.path()).unwrap();

        let collected: Vec<_> = mapping.iter().collect();
        assert_eq!(collected.len(), 5);
        for (i, (addr, idx)) in collected.iter().enumerate() {
            assert_eq!(addr[0], i as u8);
            assert_eq!(*idx, i as u64);
        }
    }

    #[test]
    fn test_storage_mapping_empty() {
        let file = NamedTempFile::new().unwrap();
        let mapping = StorageMapping::load(file.path()).unwrap();
        assert!(mapping.is_empty());
        assert!(mapping.lookup(&[0u8; 20], &[0u8; 32]).is_none());
    }

    #[test]
    fn test_storage_mapping_single() {
        let addr = [0x42u8; 20];
        let slot = [0x01u8; 32];
        let file = create_storage_mapping_file(&[(addr, slot, 200)]);
        let mapping = StorageMapping::load(file.path()).unwrap();

        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.lookup(&addr, &slot), Some(200));
        assert!(mapping.lookup(&[0u8; 20], &[0u8; 32]).is_none());
    }

    #[test]
    fn test_storage_mapping_multiple() {
        let mut entries: Vec<([u8; 20], [u8; 32], u64)> = (0..10u8)
            .map(|i| {
                let mut addr = [0u8; 20];
                addr[0] = i;
                let mut slot = [0u8; 32];
                slot[0] = i;
                (addr, slot, i as u64 * 100)
            })
            .collect();
        entries.sort_by_key(|(addr, slot, _)| (*addr, *slot));

        let file = create_storage_mapping_file(&entries);
        let mapping = StorageMapping::load(file.path()).unwrap();

        assert_eq!(mapping.len(), 10);

        for (addr, slot, expected_idx) in &entries {
            assert_eq!(mapping.lookup(addr, slot), Some(*expected_idx));
        }
    }

    #[test]
    fn test_storage_mapping_same_address_different_slots() {
        let addr = [0x42u8; 20];
        let mut entries: Vec<([u8; 20], [u8; 32], u64)> = (0..5u8)
            .map(|i| {
                let mut slot = [0u8; 32];
                slot[0] = i;
                (addr, slot, i as u64 * 50)
            })
            .collect();
        entries.sort_by_key(|(addr, slot, _)| (*addr, *slot));

        let file = create_storage_mapping_file(&entries);
        let mapping = StorageMapping::load(file.path()).unwrap();

        for (_, slot, expected_idx) in &entries {
            assert_eq!(mapping.lookup(&addr, slot), Some(*expected_idx));
        }

        let missing_slot = [0xFFu8; 32];
        assert!(mapping.lookup(&addr, &missing_slot).is_none());
    }

    #[test]
    fn test_invalid_file_size() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&[0u8; 29]).unwrap(); // Invalid size for account mapping (not multiple of 28)
        file.flush().unwrap();

        let result = AccountMapping::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_account_mapping_fn() {
        let addr = [0x42u8; 20];
        let file = create_account_mapping_file(&[(addr, 100)]);
        let mapping = load_account_mapping(file.path()).unwrap();
        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.lookup(&addr), Some(100));
    }

    #[test]
    fn test_load_storage_mapping_fn() {
        let addr = [0x42u8; 20];
        let slot = [0x01u8; 32];
        let file = create_storage_mapping_file(&[(addr, slot, 200)]);
        let mapping = load_storage_mapping(file.path()).unwrap();
        assert_eq!(mapping.len(), 1);
        assert_eq!(mapping.lookup(&addr, &slot), Some(200));
    }

    #[test]
    fn test_lookup_account_index_fn() {
        let mut entries: Vec<([u8; 20], u64)> = (0..5u8)
            .map(|i| {
                let mut addr = [0u8; 20];
                addr[0] = i;
                (addr, i as u64 * 10)
            })
            .collect();
        entries.sort_by_key(|(addr, _)| *addr);

        let file = create_account_mapping_file(&entries);
        let mapping = load_account_mapping(file.path()).unwrap();

        for (addr, expected_idx) in &entries {
            assert_eq!(lookup_account_index(&mapping, addr), Some(*expected_idx));
        }

        let missing = [0xFFu8; 20];
        assert!(lookup_account_index(&mapping, &missing).is_none());
    }

    #[test]
    fn test_lookup_storage_index_fn() {
        let addr = [0x42u8; 20];
        let mut entries: Vec<([u8; 20], [u8; 32], u64)> = (0..5u8)
            .map(|i| {
                let mut slot = [0u8; 32];
                slot[0] = i;
                (addr, slot, i as u64 * 10)
            })
            .collect();
        entries.sort_by_key(|(addr, slot, _)| (*addr, *slot));

        let file = create_storage_mapping_file(&entries);
        let mapping = load_storage_mapping(file.path()).unwrap();

        for (addr, slot, expected_idx) in &entries {
            assert_eq!(lookup_storage_index(&mapping, addr, slot), Some(*expected_idx));
        }

        let missing_slot = [0xFFu8; 32];
        assert!(lookup_storage_index(&mapping, &addr, &missing_slot).is_none());
    }
}
