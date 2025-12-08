//! End-to-end PIR correctness tests for InsPIRe
//!
//! Tests the full PIR protocol: Setup → Query → Respond → Extract = Original Entry

use inspire_pir::math::GaussianSampler;
use inspire_pir::params::{InspireParams, SecurityLevel};
use inspire_pir::pir::{extract, query, respond, setup};

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        p: 65536,
        sigma: 3.2,
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
    let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in 0..num_entries {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
    let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for _ in 0..10 {
        let target_idx = rng.gen_range(0..num_entries);

        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
    let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for shard_id in 0..num_shards {
        let target_idx = shard_id * entries_per_shard + entries_per_shard / 2;

        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
    let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let target_idx = 5;
    let (state, client_query) =
        query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
    let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let test_indices = [0, 1, num_entries / 2, num_entries - 2, num_entries - 1];

    for &target_idx in &test_indices {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
        let (crs, encoded_db) = setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_idx = 10;
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &mut sampler).unwrap();
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
