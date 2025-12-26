//! State file format types for PIR database generation
//!
//! See inspire-exex docs/STATE_FORMAT.md for the full specification.

/// Magic bytes identifying an inspire state file
pub const STATE_MAGIC: [u8; 4] = *b"PIR2";

/// Header size in bytes
pub const STATE_HEADER_SIZE: usize = 64;

/// Entry size in bytes (address + slot + value)
pub const STATE_ENTRY_SIZE: usize = 84;

/// State file header
///
/// All integers are little-endian. This struct is for logical representation;
/// use `to_bytes()` and `from_bytes()` for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateHeader {
    /// Magic bytes: "PIR2" (0x50495232)
    pub magic: [u8; 4],
    /// Format version (currently 1)
    pub version: u16,
    /// Bytes per entry (84)
    pub entry_size: u16,
    /// Number of entries in the file
    pub entry_count: u64,
    /// Snapshot block number
    pub block_number: u64,
    /// Ethereum chain ID
    pub chain_id: u64,
    /// Block hash (zero if unknown)
    pub block_hash: [u8; 32],
}

impl StateHeader {
    /// Current format version
    pub const VERSION: u16 = 1;

    /// Create a new header
    pub fn new(entry_count: u64, block_number: u64, chain_id: u64, block_hash: [u8; 32]) -> Self {
        Self {
            magic: STATE_MAGIC,
            version: Self::VERSION,
            entry_size: STATE_ENTRY_SIZE as u16,
            entry_count,
            block_number,
            chain_id,
            block_hash,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; STATE_HEADER_SIZE] {
        let mut buf = [0u8; STATE_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.entry_size.to_le_bytes());
        buf[8..16].copy_from_slice(&self.entry_count.to_le_bytes());
        buf[16..24].copy_from_slice(&self.block_number.to_le_bytes());
        buf[24..32].copy_from_slice(&self.chain_id.to_le_bytes());
        buf[32..64].copy_from_slice(&self.block_hash);
        buf
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, StateFormatError> {
        if data.len() < STATE_HEADER_SIZE {
            return Err(StateFormatError::HeaderTooShort { actual: data.len() });
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if magic != STATE_MAGIC {
            return Err(StateFormatError::InvalidMagic { actual: magic });
        }

        let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let entry_size = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let entry_count = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let block_number = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let chain_id = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let block_hash: [u8; 32] = data[32..64].try_into().unwrap();

        Ok(Self {
            magic,
            version,
            entry_size,
            entry_count,
            block_number,
            chain_id,
            block_hash,
        })
    }

    /// Check if data starts with the state file magic
    pub fn has_magic(data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == STATE_MAGIC
    }
}

/// Storage entry (84 bytes)
///
/// Use `to_bytes()` and `from_bytes()` for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageEntry {
    /// Contract address (20 bytes)
    pub address: [u8; 20],
    /// Storage slot key (32 bytes)
    pub slot: [u8; 32],
    /// Storage value (32 bytes)
    pub value: [u8; 32],
}

impl StorageEntry {
    /// Create a new entry
    pub fn new(address: [u8; 20], slot: [u8; 32], value: [u8; 32]) -> Self {
        Self {
            address,
            slot,
            value,
        }
    }

    /// Serialize entry to bytes
    pub fn to_bytes(&self) -> [u8; STATE_ENTRY_SIZE] {
        let mut buf = [0u8; STATE_ENTRY_SIZE];
        buf[0..20].copy_from_slice(&self.address);
        buf[20..52].copy_from_slice(&self.slot);
        buf[52..84].copy_from_slice(&self.value);
        buf
    }

    /// Parse entry from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, StateFormatError> {
        if data.len() < STATE_ENTRY_SIZE {
            return Err(StateFormatError::EntryTooShort { actual: data.len() });
        }

        Ok(Self {
            address: data[0..20].try_into().unwrap(),
            slot: data[20..52].try_into().unwrap(),
            value: data[52..84].try_into().unwrap(),
        })
    }
}

/// Errors for state format parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateFormatError {
    /// Header is too short
    HeaderTooShort { actual: usize },
    /// Invalid magic bytes
    InvalidMagic { actual: [u8; 4] },
    /// Entry is too short
    EntryTooShort { actual: usize },
    /// File size doesn't match header
    SizeMismatch { expected: u64, actual: u64 },
}

impl core::fmt::Display for StateFormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StateFormatError::HeaderTooShort { actual } => {
                write!(
                    f,
                    "Header too short: need {} bytes, got {}",
                    STATE_HEADER_SIZE, actual
                )
            }
            StateFormatError::InvalidMagic { actual } => {
                write!(
                    f,
                    "Invalid magic: expected {:?}, got {:?}",
                    STATE_MAGIC, actual
                )
            }
            StateFormatError::EntryTooShort { actual } => {
                write!(
                    f,
                    "Entry too short: need {} bytes, got {}",
                    STATE_ENTRY_SIZE, actual
                )
            }
            StateFormatError::SizeMismatch { expected, actual } => {
                write!(
                    f,
                    "File size mismatch: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for StateFormatError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let block_hash = [0xab; 32];
        let header = StateHeader::new(1000, 20_000_000, 1, block_hash);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), STATE_HEADER_SIZE);

        let recovered = StateHeader::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.magic, STATE_MAGIC);
        assert_eq!(recovered.version, 1);
        assert_eq!(recovered.entry_size, 84);
        assert_eq!(recovered.entry_count, 1000);
        assert_eq!(recovered.block_number, 20_000_000);
        assert_eq!(recovered.chain_id, 1);
        assert_eq!(recovered.block_hash, block_hash);
    }

    #[test]
    fn test_entry_roundtrip() {
        let entry = StorageEntry::new([0x42; 20], [0x01; 32], [0xff; 32]);

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), STATE_ENTRY_SIZE);

        let recovered = StorageEntry::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, entry);
    }

    #[test]
    fn test_has_magic() {
        assert!(StateHeader::has_magic(b"PIR2...."));
        assert!(!StateHeader::has_magic(b"XXXX...."));
        assert!(!StateHeader::has_magic(b"PIR")); // too short
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = [0u8; STATE_HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");

        let result = StateHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(StateFormatError::InvalidMagic { .. })));
    }
}
