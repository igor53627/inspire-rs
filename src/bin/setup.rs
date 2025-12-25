//! inspire-setup: Database preprocessing CLI for InsPIRe PIR
//!
//! Preprocesses a database from plinko-extractor output into the format
//! required for InsPIRe PIR queries.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use eyre::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tiny_keccak::{Hasher, Keccak};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use inspire_pir::ethereum_db::EthereumStateDb;
use inspire_pir::math::GaussianSampler;
use inspire_pir::params::InspireParams;
use inspire_pir::pir::{setup, save_shards_binary, EncodedDatabase, ServerCrs};

/// Number of buckets for sparse index (2^18 = 256K)
const NUM_BUCKETS: usize = 262_144;

#[derive(Parser)]
#[command(name = "inspire-setup")]
#[command(about = "Preprocess database for InsPIRe PIR")]
#[command(version)]
struct Args {
    /// Path to plinko-extractor output directory (containing database.bin)
    #[arg(long)]
    data_dir: PathBuf,

    /// Output directory for preprocessed data
    #[arg(long, default_value = "inspire_data")]
    output_dir: PathBuf,

    /// Ring dimension (1024, 2048, or 4096)
    #[arg(long, default_value = "2048")]
    ring_dim: usize,

    /// Random seed for deterministic key generation (optional)
    #[arg(long)]
    seed: Option<u64>,

    /// Save shards as binary files for memory-mapped loading
    #[arg(long)]
    binary_output: bool,

    /// Generate bucket index for sparse client lookups
    #[arg(long, default_value = "true")]
    bucket_index: bool,
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("InsPIRe PIR Setup");
    info!("Data directory: {}", args.data_dir.display());
    info!("Output directory: {}", args.output_dir.display());
    info!("Ring dimension: {}", args.ring_dim);

    let params = match args.ring_dim {
        1024 => {
            let mut p = InspireParams::secure_128_d2048();
            p.ring_dim = 1024;
            p
        }
        2048 => InspireParams::secure_128_d2048(),
        4096 => InspireParams::secure_128_d4096(),
        _ => {
            return Err(eyre::eyre!(
                "Invalid ring dimension: {}. Must be 1024, 2048, or 4096",
                args.ring_dim
            ));
        }
    };

    params
        .validate()
        .map_err(|e| eyre::eyre!("Invalid parameters: {}", e))?;

    let total_start = Instant::now();

    info!("Loading database from plinko-extractor...");
    let load_start = Instant::now();

    let eth_db = EthereumStateDb::open(&args.data_dir)
        .with_context(|| format!("Failed to open database at {}", args.data_dir.display()))?;

    let entry_count = eth_db.entry_count();
    let entry_size = eth_db.entry_size();
    let db_size_mb = (entry_count as f64 * entry_size as f64) / (1024.0 * 1024.0);

    info!(
        "Loaded database: {} entries ({:.2} MB)",
        entry_count, db_size_mb
    );
    info!("Load time: {:.2?}", load_start.elapsed());

    // Build bucket index while iterating storage mapping
    let bucket_counts = if args.bucket_index {
        info!("Building bucket index from storage mapping...");
        let bucket_start = Instant::now();
        let counts = build_bucket_index(eth_db.storage_map());
        info!(
            "Bucket index built: {} buckets in {:.2?}",
            NUM_BUCKETS,
            bucket_start.elapsed()
        );
        Some(counts)
    } else {
        None
    };

    info!("Reading database entries...");
    let pb = ProgressBar::new(entry_count);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"),
    );

    let mut database = Vec::with_capacity(entry_count as usize * entry_size);
    for idx in 0..entry_count {
        let entry = eth_db.read_entry(idx)?;
        database.extend_from_slice(&entry);
        if idx % 10000 == 0 {
            pb.set_position(idx);
        }
    }
    pb.finish_with_message("Done");

    info!("Generating CRS and encoding database...");
    let setup_start = Instant::now();

    let seed = args.seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });
    let mut sampler = GaussianSampler::with_seed(params.sigma, seed);

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?,
    );
    pb.set_message("Running PIR setup...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let (crs, encoded_db, secret_key) = setup(&params, &database, entry_size, &mut sampler)
        .with_context(|| "Failed to run PIR setup")?;

    pb.finish_with_message("Setup complete");

    info!("Setup time: {:.2?}", setup_start.elapsed());
    info!("Number of shards: {}", encoded_db.shards.len());

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {}", args.output_dir.display()))?;

    info!("Saving CRS...");
    let save_start = Instant::now();

    let crs_path = args.output_dir.join("crs.json");
    let crs_file = File::create(&crs_path)
        .with_context(|| format!("Failed to create CRS file: {}", crs_path.display()))?;
    let mut writer = BufWriter::new(crs_file);
    serde_json::to_writer(&mut writer, &crs)
        .with_context(|| "Failed to serialize CRS")?;
    writer.flush()?;

    let crs_size = fs::metadata(&crs_path)?.len();
    info!("CRS saved: {:.2} MB", crs_size as f64 / (1024.0 * 1024.0));

    info!("Saving secret key (keep this secure!)...");
    let sk_path = args.output_dir.join("secret_key.json");
    let sk_file = File::create(&sk_path)
        .with_context(|| format!("Failed to create secret key file: {}", sk_path.display()))?;
    let mut writer = BufWriter::new(sk_file);
    serde_json::to_writer(&mut writer, &secret_key)
        .with_context(|| "Failed to serialize secret key")?;
    writer.flush()?;

    let sk_size = fs::metadata(&sk_path)?.len();
    info!("Secret key saved: {:.2} KB", sk_size as f64 / 1024.0);

    info!("Saving encoded database...");
    let db_path = args.output_dir.join("encoded_db.json");
    let db_file = File::create(&db_path)
        .with_context(|| format!("Failed to create database file: {}", db_path.display()))?;
    let mut writer = BufWriter::new(db_file);
    serde_json::to_writer(&mut writer, &encoded_db)
        .with_context(|| "Failed to serialize encoded database")?;
    writer.flush()?;

    let db_size = fs::metadata(&db_path)?.len();
    info!(
        "Encoded database saved: {:.2} MB",
        db_size as f64 / (1024.0 * 1024.0)
    );

    info!("Save time: {:.2?}", save_start.elapsed());

    if args.binary_output {
        info!("Saving shards as binary files for mmap...");
        let shards_dir = args.output_dir.join("shards");
        save_shards_binary(&encoded_db.shards, &shards_dir)
            .with_context(|| "Failed to save binary shards")?;
        info!("Binary shards saved to {}", shards_dir.display());
    }

    // Save bucket index if generated
    if let Some(ref counts) = bucket_counts {
        save_bucket_index(&args.output_dir, counts)?;
    }

    save_metadata(&args.output_dir, &params, &crs, &encoded_db, entry_count)?;

    let total_time = total_start.elapsed();
    info!("Total preprocessing time: {:.2?}", total_time);

    println!();
    println!("=== Setup Complete ===");
    println!("Output directory: {}", args.output_dir.display());
    println!("Database entries: {}", entry_count);
    println!("Shards: {}", encoded_db.shards.len());
    println!("Ring dimension: {}", params.ring_dim);
    println!("CRS size: {:.2} MB", crs_size as f64 / (1024.0 * 1024.0));
    println!(
        "Encoded DB size: {:.2} MB",
        db_size as f64 / (1024.0 * 1024.0)
    );
    println!("Total time: {:.2?}", total_time);

    Ok(())
}

fn save_metadata(
    output_dir: &PathBuf,
    params: &InspireParams,
    _crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    entry_count: u64,
) -> Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Metadata {
        version: String,
        ring_dim: usize,
        modulus: String,
        plaintext_modulus: u64,
        gadget_base: u64,
        gadget_len: usize,
        entry_count: u64,
        shard_count: usize,
        entries_per_shard: u64,
    }

    let metadata = Metadata {
        version: "1.0.0".to_string(),
        ring_dim: params.ring_dim,
        modulus: params.q.to_string(),
        plaintext_modulus: params.p,
        gadget_base: params.gadget_base,
        gadget_len: params.gadget_len,
        entry_count,
        shard_count: encoded_db.shards.len(),
        entries_per_shard: encoded_db.config.entries_per_shard(),
    };

    let meta_path = output_dir.join("metadata.json");
    let meta_file = File::create(&meta_path)?;
    serde_json::to_writer_pretty(meta_file, &metadata)?;

    info!("Metadata saved to {}", meta_path.display());
    Ok(())
}

/// Build bucket index from storage mapping
///
/// Computes keccak256(address || slot) for each entry and counts per bucket.
fn build_bucket_index(storage_map: &inspire_pir::ethereum_db::StorageMapping) -> Vec<u32> {
    let mut bucket_counts = vec![0u32; NUM_BUCKETS];

    for (address, slot, _index) in storage_map.iter() {
        let bucket_id = compute_bucket_id(&address, &slot);
        bucket_counts[bucket_id] += 1;
    }

    bucket_counts
}

/// Compute bucket ID from address and slot using keccak256
fn compute_bucket_id(address: &[u8; 20], slot: &[u8; 32]) -> usize {
    let mut hasher = Keccak::v256();
    hasher.update(address);
    hasher.update(slot);

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    // Take first 18 bits as bucket ID
    let bucket_id = ((hash[0] as usize) << 10) | ((hash[1] as usize) << 2) | ((hash[2] as usize) >> 6);
    bucket_id & (NUM_BUCKETS - 1)
}

/// Save bucket index to output directory
fn save_bucket_index(output_dir: &PathBuf, counts: &[u32]) -> Result<()> {
    // Save uncompressed
    let index_path = output_dir.join("bucket-index.bin");
    let mut file = BufWriter::new(File::create(&index_path)?);
    for &count in counts {
        file.write_all(&(count as u16).to_le_bytes())?;
    }
    file.flush()?;

    let uncompressed_size = counts.len() * 2;
    info!(
        "Bucket index saved: {} ({} KB)",
        index_path.display(),
        uncompressed_size / 1024
    );

    // Save compressed
    let compressed_path = output_dir.join("bucket-index.bin.zst");
    let raw_data: Vec<u8> = counts
        .iter()
        .flat_map(|&c| (c as u16).to_le_bytes())
        .collect();
    let compressed = zstd::encode_all(&raw_data[..], 19)?;
    std::fs::write(&compressed_path, &compressed)?;

    info!(
        "Compressed bucket index: {} ({} KB, {:.1}%)",
        compressed_path.display(),
        compressed.len() / 1024,
        compressed.len() as f64 / uncompressed_size as f64 * 100.0
    );

    Ok(())
}
