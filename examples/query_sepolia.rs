//! Query real Sepolia data using InsPIRe PIR
//!
//! Run with: cargo run --release --example query_sepolia

use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

use inspire::math::GaussianSampler;
use inspire::pir::{extract, query, respond, EncodedDatabase, ServerCrs};
use inspire::rlwe::RlweSecretKey;

fn main() -> eyre::Result<()> {
    let pir_dir = std::path::Path::new("sepolia-test/pir");

    println!("Loading CRS...");
    let start = Instant::now();
    let crs: ServerCrs =
        serde_json::from_reader(BufReader::new(File::open(pir_dir.join("crs.json"))?))?;
    println!("  Loaded in {:?}", start.elapsed());

    println!("Loading encoded database...");
    let start = Instant::now();
    let encoded_db: EncodedDatabase =
        serde_json::from_reader(BufReader::new(File::open(pir_dir.join("encoded_db.json"))?))?;
    println!("  Loaded in {:?}", start.elapsed());

    println!("Loading secret key...");
    let secret_key: RlweSecretKey =
        serde_json::from_reader(BufReader::new(File::open(pir_dir.join("secret_key.json"))?))?;

    let mut sampler = GaussianSampler::new(crs.params.sigma);

    println!("\n=== PIR Query Test ===");
    println!(
        "Database: {} entries across {} shards",
        encoded_db.config.total_entries,
        encoded_db.shards.len()
    );
    println!("Ring dimension: {}", crs.params.ring_dim);
    println!();

    // Query entry 0 (first account's first word - nonce)
    let test_indices = [0, 1, 2, 100, 500, 1000, 10000, 30000];

    for target_idx in test_indices {
        if target_idx >= encoded_db.config.total_entries {
            continue;
        }

        println!("Querying index {}...", target_idx);

        // Generate query
        let query_start = Instant::now();
        let (state, client_query) = query(
            &crs,
            target_idx,
            &encoded_db.config,
            &secret_key,
            &mut sampler,
        )?;
        let query_time = query_start.elapsed();

        // Server responds
        let respond_start = Instant::now();
        let response = respond(&crs, &encoded_db, &client_query)?;
        let respond_time = respond_start.elapsed();

        // Extract result
        let extract_start = Instant::now();
        let result = extract(&crs, &state, &response, 32)?;
        let extract_time = extract_start.elapsed();

        println!(
            "  Query: {:?}, Respond: {:?}, Extract: {:?}",
            query_time, respond_time, extract_time
        );
        println!("  Result (hex): {}", hex::encode(&result));

        // Interpret if this is an account (first 3 words)
        if target_idx < 30000 && target_idx % 3 == 0 {
            // First word of account - nonce
            let nonce_bytes = &result[0..8];
            let nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());
            println!("  Interpreted as nonce: {}", nonce);
        }
        println!();
    }

    Ok(())
}
