//! Benchmark seed expansion query size reduction
//!
//! Compares serialized sizes of ClientQuery vs SeededClientQuery

use inspire_pir::math::GaussianSampler;
use inspire_pir::params::InspireParams;
use inspire_pir::pir::{query, query_seeded, setup};

fn main() -> eyre::Result<()> {
    println!("Seed Expansion Benchmark");
    println!("========================\n");

    // Test with different ring dimensions
    let configs = [
        (
            "d=256 (test)",
            InspireParams {
                ring_dim: 256,
                q: 1152921504606830593,
                crt_moduli: vec![1152921504606830593],
                p: 65536,
                sigma: 6.4,
                gadget_base: 1 << 20,
                gadget_len: 3,
                security_level: inspire_pir::params::SecurityLevel::Bits128,
            },
        ),
        ("d=2048 (production)", InspireParams::secure_128_d2048()),
    ];

    for (name, params) in configs {
        println!("Configuration: {}", name);
        println!("  Ring dimension: {}", params.ring_dim);
        println!("  Gadget length: {}", params.gadget_len);

        let mut sampler = GaussianSampler::new(params.sigma);

        // Create a small test database
        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler)?;

        // Generate both query types
        let target_index = 42u64;
        let (_, regular_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )?;
        let (_, seeded_query) = query_seeded(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )?;

        // Serialize and measure sizes
        let regular_json = serde_json::to_vec(&regular_query)?;
        let seeded_json = serde_json::to_vec(&seeded_query)?;

        let regular_size = regular_json.len();
        let seeded_size = seeded_json.len();
        let reduction = 100.0 * (1.0 - (seeded_size as f64 / regular_size as f64));

        println!(
            "  Regular query size: {} bytes ({:.1} KB)",
            regular_size,
            regular_size as f64 / 1024.0
        );
        println!(
            "  Seeded query size:  {} bytes ({:.1} KB)",
            seeded_size,
            seeded_size as f64 / 1024.0
        );
        println!("  Reduction: {:.1}%", reduction);

        // Verify seeded query can be expanded and produces same structure
        let expanded = seeded_query.expand();
        assert_eq!(expanded.shard_id, regular_query.shard_id);
        assert_eq!(
            expanded.rgsw_ciphertext.rows.len(),
            regular_query.rgsw_ciphertext.rows.len()
        );
        println!("  [OK] Seeded query expands correctly\n");
    }

    // Summary
    println!("Summary");
    println!("-------");
    println!("Seed expansion stores 32-byte seeds instead of full polynomials.");
    println!("For d=2048, each polynomial is 2048 * 8 = 16384 bytes.");
    println!("RGSW has 2*gadget_len = 6 rows, each with one 'a' polynomial.");
    println!("Expected savings: 6 * (16384 - 32) = ~96 KB for d=2048.");

    Ok(())
}
