//! Benchmark comparing InsPIRe protocol variants
//!
//! Run with: cargo run --example benchmark_variants --release

use inspire::math::GaussianSampler;
use inspire::params::{InspireParams, SecurityLevel};
use inspire::pir::{extract, query, respond, setup};
use std::time::Instant;

fn main() {
    println!("=== InsPIRe Variant Benchmark ===\n");

    let configs = [
        ("d=256 (test)", test_params_d256()),
        ("d=2048 (production)", InspireParams::secure_128_d2048()),
    ];

    for (name, params) in configs {
        println!("--- {} ---", name);
        benchmark_config(&params);
        println!();
    }
}

fn test_params_d256() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        crt_moduli: vec![1152921504606830593],
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn benchmark_config(params: &InspireParams) {
    let entry_size = 32;
    let num_entries = params.ring_dim;
    let mut database = vec![0u8; num_entries * entry_size];
    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i * 17 + j * 13) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);

    let setup_start = Instant::now();
    let (crs, encoded_db, rlwe_sk) = setup(params, &database, entry_size, &mut sampler).unwrap();
    let setup_time = setup_start.elapsed();

    let target_idx = params.ring_dim / 2;

    let query_start = Instant::now();
    let (state, client_query) = query(
        &crs,
        target_idx as u64,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();
    let query_time = query_start.elapsed();

    let respond_start = Instant::now();
    let response = respond(&crs, &encoded_db, &client_query).unwrap();
    let respond_time = respond_start.elapsed();

    let extract_start = Instant::now();
    let result = extract(&crs, &state, &response, entry_size).unwrap();
    let extract_time = extract_start.elapsed();

    let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
    let correct = result == expected;

    let query_bytes = bincode::serialize(&client_query).unwrap().len();
    let response_bytes = response.to_binary().unwrap().len();

    println!(
        "Entries: {} x {} bytes = {} KB total",
        num_entries,
        entry_size,
        (num_entries * entry_size) / 1024
    );
    println!();
    println!("Communication:");
    println!(
        "  Query size:    {:>8} bytes ({:.1} KB)",
        query_bytes,
        query_bytes as f64 / 1024.0
    );
    println!(
        "  Response size: {:>8} bytes ({:.1} KB)",
        response_bytes,
        response_bytes as f64 / 1024.0
    );
    println!(
        "  Total:         {:>8} bytes ({:.1} KB)",
        query_bytes + response_bytes,
        (query_bytes + response_bytes) as f64 / 1024.0
    );
    println!();
    println!("Timing:");
    println!("  Setup:   {:>8.2} ms", setup_time.as_secs_f64() * 1000.0);
    println!("  Query:   {:>8.2} ms", query_time.as_secs_f64() * 1000.0);
    println!("  Respond: {:>8.2} ms", respond_time.as_secs_f64() * 1000.0);
    println!("  Extract: {:>8.2} ms", extract_time.as_secs_f64() * 1000.0);
    println!();
    println!("Correctness: {}", if correct { "[OK]" } else { "[FAIL]" });
}
