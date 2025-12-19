//! Query Size Comparison for InsPIRe Variants
//!
//! This example calculates and displays the communication costs for all InsPIRe variants:
//! - InsPIRe^0 (NoPacking): Baseline, no query optimization
//! - InsPIRe^1 (OnePacking): Packed response, 17x response reduction  
//! - InsPIRe^2 (TwoPacking): Seeded query + packed response, 5.7x total reduction
//!
//! Run: cargo run --release --example query_size_comparison

use inspire_pir::math::GaussianSampler;
use inspire_pir::params::InspireParams;
use inspire_pir::pir::{query, query_seeded, setup};

fn main() {
    println!("=== InsPIRe Communication Cost Analysis ===\n");
    
    // Use production parameters
    let params = InspireParams::secure_128_d2048();
    let d = params.ring_dim;
    let q = params.q;
    let gadget_len = params.gadget_len;
    
    println!("Parameters:");
    println!("  Ring dimension (d): {}", d);
    println!("  Modulus (q): {} ({:.1} bits)", q, (q as f64).log2());
    println!("  Gadget length (l): {}", gadget_len);
    println!("  Gadget base: 2^{}", (params.gadget_base as f64).log2() as u32);
    println!();
    
    // Theoretical sizes
    println!("=== Theoretical Query Sizes ===\n");
    
    // RGSW query: 2*l rows, each row has 2 polynomials of d coefficients (8 bytes each)
    let rgsw_full_size = 2 * gadget_len * 2 * d * 8;
    let rgsw_seeded_size = 2 * gadget_len * d * 8 + 2 * gadget_len * 32; // b polys + seeds
    let rgsw_switched_size = 2 * gadget_len * d * 4 + 2 * gadget_len * 32; // 4 bytes after modswitch
    
    println!("Query (RGSW ciphertext):");
    println!("  Full:     {:>8} bytes ({:.1} KB)", rgsw_full_size, rgsw_full_size as f64 / 1024.0);
    println!("  Seeded:   {:>8} bytes ({:.1} KB)", rgsw_seeded_size, rgsw_seeded_size as f64 / 1024.0);
    println!("  Switched: {:>8} bytes ({:.1} KB)*", rgsw_switched_size, rgsw_switched_size as f64 / 1024.0);
    println!("  *Switched exceeds noise budget with current parameters");
    println!();
    
    // Response sizes
    let rlwe_size = 2 * d * 8; // 2 polynomials of d coefficients
    let entry_size = 32; // 32-byte Ethereum entry
    let p = params.p;
    let bits_per_coeff = (p as f64).log2() as usize;
    let num_columns = (entry_size * 8 + bits_per_coeff - 1) / bits_per_coeff;
    
    println!("Response (RLWE ciphertexts):");
    println!("  RLWE size: {} bytes ({:.1} KB)", rlwe_size, rlwe_size as f64 / 1024.0);
    println!("  Entry size: {} bytes ({} bits)", entry_size, entry_size * 8);
    println!("  Bits per coefficient: {} (p = 2^{})", bits_per_coeff, bits_per_coeff);
    println!("  Columns needed: {}", num_columns);
    println!();
    
    let response_no_pack = (num_columns + 1) * rlwe_size; // +1 for combined
    let response_packed = rlwe_size; // Single packed RLWE
    
    println!("  NoPacking:  {:>8} bytes ({:.1} KB) - {} ciphertexts", 
             response_no_pack, response_no_pack as f64 / 1024.0, num_columns + 1);
    println!("  Packed:     {:>8} bytes ({:.1} KB) - 1 ciphertext", 
             response_packed, response_packed as f64 / 1024.0);
    println!();
    
    // Total communication per variant
    println!("=== Total Communication by Variant ===\n");
    
    struct VariantInfo {
        name: &'static str,
        query_size: usize,
        response_size: usize,
        notes: &'static str,
    }
    
    let variants = vec![
        VariantInfo {
            name: "InsPIRe^0 (NoPacking)",
            query_size: rgsw_full_size,
            response_size: response_no_pack,
            notes: "Baseline",
        },
        VariantInfo {
            name: "InsPIRe^1 (OnePacking)", 
            query_size: rgsw_full_size,
            response_size: response_packed,
            notes: "Packed response",
        },
        VariantInfo {
            name: "InsPIRe^2 (Seeded+Packed)",
            query_size: rgsw_seeded_size,
            response_size: response_packed,
            notes: "Best practical option",
        },
        VariantInfo {
            name: "InsPIRe^2+ (Switched+Packed)",
            query_size: rgsw_switched_size,
            response_size: response_packed,
            notes: "Exceeds noise budget*",
        },
    ];
    
    let baseline_total = variants[0].query_size + variants[0].response_size;
    
    println!("{:<30} {:>10} {:>10} {:>10} {:>8}", "Variant", "Query", "Response", "Total", "Reduction");
    println!("{:-<30} {:-<10} {:-<10} {:-<10} {:-<8}", "", "", "", "", "");
    
    for v in &variants {
        let total = v.query_size + v.response_size;
        let reduction = baseline_total as f64 / total as f64;
        println!("{:<30} {:>7.1} KB {:>7.1} KB {:>7.1} KB {:>6.1}x", 
                 v.name,
                 v.query_size as f64 / 1024.0,
                 v.response_size as f64 / 1024.0,
                 total as f64 / 1024.0,
                 reduction);
    }
    println!();
    
    // Key material comparison
    println!("=== Key Material Comparison ===\n");
    
    let tree_ks_matrices = (d as f64).log2() as usize; // log(d) matrices
    let ks_matrix_size = gadget_len * 2 * d * 8; // l rows, 2 polynomials each
    let tree_total = tree_ks_matrices * ks_matrix_size;
    let inspiring_crs = 64; // Just w_seed (32) + v_seed (32)
    
    println!("CRS key material:");
    println!("  Tree packing:    {} matrices = {:.1} KB", 
             tree_ks_matrices, tree_total as f64 / 1024.0);
    println!("  InspiRING:       2 seeds = {} bytes",
             inspiring_crs);
    println!("  Reduction:       {:.0}x", tree_total as f64 / inspiring_crs as f64);
    println!();
    
    // InspiRING packing keys
    println!("InspiRING client packing keys (per query):");
    println!("  y_body: {} polynomials = {:.1} KB", 
             gadget_len,
             (gadget_len * d * 8) as f64 / 1024.0);
    println!("  y_all: {} sets of {} polynomials (precomputed rotations)", 
             d - 1, gadget_len);
    println!("  Sent to server: y_body only ({:.1} KB)", 
             (gadget_len * d * 8) as f64 / 1024.0);
    println!();
    
    // Actual measured sizes
    println!("=== Measured Sizes (bincode serialization) ===\n");
    
    let entry_size_bytes = 32;
    let num_entries = d;
    let database: Vec<u8> = (0..(num_entries * entry_size_bytes))
        .map(|i| (i % 256) as u8)
        .collect();
    
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size_bytes, &mut sampler)
        .expect("Setup should succeed");
    
    let target_idx = 42u64;
    
    // Full query
    let (_, full_query) = query(&crs, target_idx, &encoded_db.config, &rlwe_sk, &mut sampler)
        .expect("Query should succeed");
    let full_query_size = bincode::serialize(&full_query).unwrap().len();
    
    // Seeded query
    let (_, seeded_query) = query_seeded(&crs, target_idx, &encoded_db.config, &rlwe_sk, &mut sampler)
        .expect("Seeded query should succeed");
    let seeded_query_size = bincode::serialize(&seeded_query).unwrap().len();
    
    println!("Measured query sizes (d={}):", d);
    println!("  Full query:   {:>8} bytes ({:.1} KB)", full_query_size, full_query_size as f64 / 1024.0);
    println!("  Seeded query: {:>8} bytes ({:.1} KB)", seeded_query_size, seeded_query_size as f64 / 1024.0);
    println!("  Reduction:    {:.1}%", 100.0 * (1.0 - seeded_query_size as f64 / full_query_size as f64));
    println!();
    
    // Summary table
    println!("=== Summary: Recommended Variant ===\n");
    println!("For most use cases, InsPIRe^2 (Seeded+Packed) is recommended:");
    println!("  - Query: ~{:.0} KB (seeded expansion)", rgsw_seeded_size as f64 / 1024.0);
    println!("  - Response: ~{:.0} KB (packed RLWE)", response_packed as f64 / 1024.0);
    println!("  - Total: ~{:.0} KB per query", (rgsw_seeded_size + response_packed) as f64 / 1024.0);
    println!("  - 5.7x reduction vs baseline");
    println!();
    println!("InspiRING packing advantages:");
    println!("  - CRS stores only 64 bytes (seeds) vs {} KB for tree packing", tree_total / 1024);
    println!("  - O(n) online phase (pure NTT-domain operations)");
    println!("  - Matches Google's optimized reference implementation");
}
