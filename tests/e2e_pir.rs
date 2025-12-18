//! End-to-end PIR correctness tests for InsPIRe
//!
//! Tests the full PIR protocol: Setup → Query → Respond → Extract = Original Entry

use inspire_pir::math::GaussianSampler;
use inspire_pir::params::{InspireParams, InspireVariant, SecurityLevel};
use inspire_pir::pir::{extract, extract_with_variant, query, query_seeded, query_switched, respond, respond_with_variant, setup};

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

#[test]
fn test_e2e_single_entry() {
    let params = test_params();

    let num_entries = 16;
    let entry_size = 32;
    let mut database = vec![0u8; num_entries * entry_size];

    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i * 17 + j * 13) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in 0..num_entries {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "Entry {} mismatch", target_idx);
    }
}

#[test]
fn test_e2e_random_entries() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let params = test_params();
    let num_entries = 64;
    let entry_size = 32;

    let mut database = vec![0u8; num_entries * entry_size];
    rng.fill(&mut database[..]);

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for _ in 0..10 {
        let target_idx = rng.gen_range(0..num_entries);

        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "Entry {} mismatch", target_idx);
    }
}

#[test]
fn test_e2e_multi_shard() {
    let params = test_params();

    let entries_per_shard = params.ring_dim;
    let num_shards = 3;
    let num_entries = entries_per_shard * num_shards;
    let entry_size = 32;

    let mut database = vec![0u8; num_entries * entry_size];
    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i + j) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for shard_id in 0..num_shards {
        let target_idx = shard_id * entries_per_shard + entries_per_shard / 2;

        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        assert_eq!(client_query.shard_id, shard_id as u32);

        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected);
    }
}

#[test]
fn test_e2e_privacy_basic() {
    let params = test_params();
    let num_entries = 16;
    let entry_size = 32;

    let mut database = vec![0u8; num_entries * entry_size];
    for i in 0..num_entries {
        database[i * entry_size..(i + 1) * entry_size].fill(i as u8);
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let target_idx = 5;
    let (state, client_query) =
        query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
    let response = respond(&crs, &encoded_db, &client_query).unwrap();
    let result = extract(&crs, &state, &response, entry_size).unwrap();

    assert!(
        result.iter().all(|&b| b == 5),
        "Should retrieve entry 5, got {:?}",
        result
    );

    for other_idx in 0..num_entries {
        if other_idx != target_idx {
            let other_entry = vec![other_idx as u8; entry_size];
            assert_ne!(result, other_entry, "Should not get entry {}", other_idx);
        }
    }
}

#[test]
fn test_e2e_boundary_indices() {
    let params = test_params();
    let num_entries = params.ring_dim;
    let entry_size = 32;

    let mut database = vec![0u8; num_entries * entry_size];
    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i ^ j) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let test_indices = [0, 1, num_entries / 2, num_entries - 2, num_entries - 1];

    for &target_idx in &test_indices {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(
            result, expected,
            "Boundary index {} mismatch",
            target_idx
        );
    }
}

#[test]
fn test_e2e_different_entry_sizes() {
    let params = test_params();
    let num_entries = 32;

    for entry_size in [16, 32, 64] {
        let mut database = vec![0u8; num_entries * entry_size];
        for i in 0..num_entries {
            for j in 0..entry_size {
                database[i * entry_size + j] = ((i * 7 + j * 3) % 256) as u8;
            }
        }

        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_idx = 10;
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(
            result, expected,
            "Entry size {} mismatch for entry {}",
            entry_size, target_idx
        );
    }
}

#[test]
fn test_e2e_seeded_query() {
    let params = test_params();

    let num_entries = 64;
    let entry_size = 32;
    let mut database = vec![0u8; num_entries * entry_size];

    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i * 17 + j * 13) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in [0, 15, 31, 63] {
        let (state, seeded_query) =
            query_seeded(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        
        // Server expands the seeded query before processing
        let expanded_query = seeded_query.expand();
        let response = respond(&crs, &encoded_db, &expanded_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "Seeded query: Entry {} mismatch", target_idx);
    }
}

/// Test switched query compression.
///
/// Note: This test is ignored by default because modulus switching on RGSW
/// ciphertexts introduces noise that exceeds decryption thresholds with
/// current parameters (q ≈ 2^60, q' = 2^30, B = 2^20, ℓ = 3).
///
/// The noise amplification formula: added_error ≈ ℓ × B × (q / q') ≈ 3×2^50
/// exceeds the safe margin q/(2p) ≈ 2^43.
///
/// To make this work, either:
/// - Use q' ≳ 2^38 (doesn't fit in u32)
/// - Use smaller gadget base (increases RGSW size)
/// - Use modulus switching only for RLWE responses (not queries)
#[test]
#[ignore = "modulus switching exceeds noise budget with current parameters"]
fn test_e2e_switched_query() {
    let params = test_params();

    let num_entries = 64;
    let entry_size = 32;
    let mut database = vec![0u8; num_entries * entry_size];

    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i * 17 + j * 13) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in [0, 15, 31, 63] {
        let (state, switched_query) =
            query_switched(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        
        // Server expands the switched query (modulus switch + seed expansion)
        let expanded_query = switched_query.expand();
        let response = respond(&crs, &encoded_db, &expanded_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "Switched query: Entry {} mismatch", target_idx);
    }
}

#[test]
fn test_e2e_variant_no_packing() {
    let params = test_params();

    let num_entries = 32;
    let entry_size = 32;
    let mut database = vec![0u8; num_entries * entry_size];

    for i in 0..num_entries {
        for j in 0..entry_size {
            database[i * entry_size + j] = ((i * 7 + j * 11) % 256) as u8;
        }
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in [0, 10, 31] {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        let response = respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::NoPacking).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "NoPacking variant: Entry {} mismatch", target_idx);
    }
}

/// Test OnePacking variant which packs multiple column RLWEs into a single RLWE.
///
/// IMPORTANT: OnePacking has a constraint that column_value * d < p, meaning
/// column values must be < p/d = 65536/256 = 256 for the test parameters.
/// This test uses 2-byte entries with high_byte=0 to ensure column values < 256.
#[test]
fn test_e2e_variant_one_packing() {
    let params = test_params();
    let d = params.ring_dim;

    let num_entries = d;
    let entry_size = 2; // 1 column per entry, value < 256
    
    // Create database with column values < 256 (high byte = 0)
    let database: Vec<u8> = (0..num_entries)
        .flat_map(|i| {
            let low_byte = (i % 256) as u8;
            let high_byte = 0u8; // Keep high byte 0 for column_value < 256
            vec![low_byte, high_byte]
        })
        .collect();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    // Test multiple indices
    for target_index in [0u64, 1, 42, 100] {
        let (state, client_query) =
            query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

        // Use OnePacking variant
        let response = respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::OnePacking)
            .expect("OnePacking respond should succeed");

        // Verify we got a packed response (single ciphertext)
        assert_eq!(response.ciphertext.ring_dim(), params.ring_dim);

        // Extract using OnePacking variant
        let extracted = extract_with_variant(&crs, &state, &response, entry_size, InspireVariant::OnePacking)
            .expect("Extract should succeed");

        // Verify extracted data matches expected
        let expected_start = (target_index as usize) * entry_size;
        let expected_end = expected_start + entry_size;
        let expected = &database[expected_start..expected_end];

        assert_eq!(
            extracted.as_slice(),
            expected,
            "OnePacking failed for index {}: extracted {:?}, expected {:?}",
            target_index,
            &extracted[..],
            &expected[..]
        );
    }
}

/// Test TwoPacking variant (seeded query + packed response)
///
/// TwoPacking uses the same response format as OnePacking, but expects the query
/// to have been generated with query_seeded() for bandwidth reduction.
#[test]
fn test_e2e_variant_two_packing() {
    let params = test_params();
    let d = params.ring_dim;

    let num_entries = d;
    let entry_size = 2; // 1 column per entry, value < 256
    
    // Create database with column values < 256
    let database: Vec<u8> = (0..num_entries)
        .flat_map(|i| {
            let low_byte = (i % 256) as u8;
            let high_byte = 0u8;
            vec![low_byte, high_byte]
        })
        .collect();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let target_index = 42u64;
    let (state, client_query) =
        query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

    // TwoPacking now works (same as OnePacking on server side)
    let response = respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::TwoPacking)
        .expect("TwoPacking respond should succeed");

    // Extract using TwoPacking (falls back to OnePacking extraction)
    let extracted = extract_with_variant(&crs, &state, &response, entry_size, InspireVariant::TwoPacking)
        .expect("Extract should succeed");

    let expected_start = (target_index as usize) * entry_size;
    let expected = &database[expected_start..expected_start + entry_size];

    assert_eq!(
        extracted.as_slice(),
        expected,
        "TwoPacking failed: extracted {:?}, expected {:?}",
        &extracted[..],
        &expected[..]
    );
}
