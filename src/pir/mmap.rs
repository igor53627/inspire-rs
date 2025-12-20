//! Memory-mapped database support for large datasets
//!
//! Allows loading encoded databases without loading everything into RAM.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use memmap2::Mmap;

use super::error::{pir_err, Result};

use crate::math::Poly;
use crate::params::ShardConfig;
use super::setup::ShardData;

/// Save encoded database shards to binary files for memory-mapping
pub fn save_shards_binary(shards: &[ShardData], dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    
    for shard in shards {
        let path = dir.join(format!("shard-{:04}.bin", shard.id));
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        
        // Header
        writer.write_u32::<LittleEndian>(shard.id)?;
        writer.write_u32::<LittleEndian>(shard.polynomials.len() as u32)?;
        
        if let Some(first_poly) = shard.polynomials.first() {
            writer.write_u32::<LittleEndian>(first_poly.dimension() as u32)?;
            writer.write_u64::<LittleEndian>(first_poly.modulus())?;
        } else {
            writer.write_u32::<LittleEndian>(0)?;
            writer.write_u64::<LittleEndian>(0)?;
        }
        
        // Polynomials
        for poly in &shard.polynomials {
            for &coeff in poly.coeffs() {
                writer.write_u64::<LittleEndian>(coeff)?;
            }
        }
        
        writer.flush()?;
    }
    
    Ok(())
}

/// Load a single shard from binary file
pub fn load_shard_binary(path: &Path) -> Result<ShardData> {
    let file = File::open(path)?;
    // SAFETY: File is opened read-only and not modified during the mmap lifetime.
    // The mmap is used only within this function scope for reading.
    let mmap = unsafe { Mmap::map(&file)? };
    let mut cursor = std::io::Cursor::new(&mmap[..]);
    
    let id = cursor.read_u32::<LittleEndian>()?;
    let num_polys = cursor.read_u32::<LittleEndian>()? as usize;
    let ring_dim = cursor.read_u32::<LittleEndian>()? as usize;
    let modulus = cursor.read_u64::<LittleEndian>()?;
    
    let mut polynomials = Vec::with_capacity(num_polys);
    for _ in 0..num_polys {
        let mut coeffs = Vec::with_capacity(ring_dim);
        for _ in 0..ring_dim {
            coeffs.push(cursor.read_u64::<LittleEndian>()?);
        }
        polynomials.push(Poly::from_coeffs(coeffs, modulus));
    }
    
    Ok(ShardData { id, polynomials })
}

/// Memory-mapped database that loads shards on demand
pub struct MmapDatabase {
    shard_dir: std::path::PathBuf,
    pub config: ShardConfig,
    num_shards: u32,
}

impl MmapDatabase {
    /// Open a memory-mapped database from a directory of shard files
    pub fn open(dir: &Path, config: ShardConfig) -> Result<Self> {
        let mut num_shards = 0u32;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("shard-") {
                num_shards += 1;
            }
        }
        
        Ok(Self {
            shard_dir: dir.to_path_buf(),
            config,
            num_shards,
        })
    }
    
    /// Get a shard by ID (loads from disk on demand)
    pub fn get_shard(&self, id: u32) -> Result<ShardData> {
        let path = self.shard_dir.join(format!("shard-{:04}.bin", id));
        if !path.exists() {
            return Err(pir_err!("Shard {} not found", id));
        }
        load_shard_binary(&path)
    }
    
    /// Number of shards
    pub fn num_shards(&self) -> u32 {
        self.num_shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_shard_roundtrip() {
        let dir = tempdir().unwrap();
        
        let poly1 = Poly::from_coeffs(vec![1, 2, 3, 4], 100);
        let poly2 = Poly::from_coeffs(vec![5, 6, 7, 8], 100);
        let shard = ShardData {
            id: 0,
            polynomials: vec![poly1, poly2],
        };
        
        save_shards_binary(std::slice::from_ref(&shard), dir.path()).unwrap();
        
        let loaded = load_shard_binary(&dir.path().join("shard-0000.bin")).unwrap();
        
        assert_eq!(loaded.id, 0);
        assert_eq!(loaded.polynomials.len(), 2);
        assert_eq!(loaded.polynomials[0].coeffs(), &[1, 2, 3, 4]);
        assert_eq!(loaded.polynomials[1].coeffs(), &[5, 6, 7, 8]);
    }
    
    #[test]
    fn test_mmap_database() {
        let dir = tempdir().unwrap();
        
        let shards: Vec<ShardData> = (0..3).map(|i| ShardData {
            id: i,
            polynomials: vec![Poly::from_coeffs(vec![i as u64; 4], 100)],
        }).collect();
        
        save_shards_binary(&shards, dir.path()).unwrap();
        
        let config = ShardConfig {
            shard_size_bytes: 128,
            entry_size_bytes: 32,
            total_entries: 12,
        };
        
        let db = MmapDatabase::open(dir.path(), config).unwrap();
        assert_eq!(db.num_shards(), 3);
        
        let shard1 = db.get_shard(1).unwrap();
        assert_eq!(shard1.id, 1);
        assert_eq!(shard1.polynomials[0].coeffs(), &[1, 1, 1, 1]);
    }
}
