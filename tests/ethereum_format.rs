//! Integration tests for Ethereum-style data formats
//!
//! Tests PIR with Ethereum account and storage entry structures.

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

fn hex_to_bytes_32(hex: &str) -> [u8; 32] {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            break;
        }
        let s = std::str::from_utf8(chunk).unwrap();
        bytes[i] = u8::from_str_radix(s, 16).unwrap();
    }
    bytes
}

#[test]
fn test_account_entry_format() {
    let params = test_params();
    let entry_size = 32;

    let nonce = hex_to_bytes_32("0x0000000000000000000000000000000000000000000000000000000000000042");
    let balance = hex_to_bytes_32("0x00000000000000000000000000000000000000000000000de0b6b3a7640000");
    let codehash = hex_to_bytes_32("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    let mut database = Vec::new();
    database.extend_from_slice(&nonce);
    database.extend_from_slice(&balance);
    database.extend_from_slice(&codehash);

    let num_entries = 3;

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in 0..num_entries {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
        assert_eq!(result, expected, "Account field {} mismatch", target_idx);
    }
}

#[test]
fn test_storage_entry_format() {
    let params = test_params();
    let entry_size = 32;
    let num_entries = 16;

    let mut database = vec![0u8; num_entries * entry_size];
    for i in 0..num_entries {
        let storage_value = hex_to_bytes_32(&format!(
            "0x000000000000000000000000000000000000000000000000000000000000{:04x}",
            i * 100
        ));
        database[i * entry_size..(i + 1) * entry_size].copy_from_slice(&storage_value);
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let target_idx = 7;
    let (state, client_query) =
        query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
    let response = respond(&crs, &encoded_db, &client_query).unwrap();
    let result = extract(&crs, &state, &response, entry_size).unwrap();

    let expected = &database[target_idx * entry_size..(target_idx + 1) * entry_size];
    assert_eq!(result, expected, "Storage entry {} mismatch", target_idx);
}

#[test]
fn test_consecutive_account_words() {
    let params = test_params();
    let entry_size = 32;

    let account_fields = [
        hex_to_bytes_32("0x0000000000000000000000000000000000000000000000000000000000000001"),
        hex_to_bytes_32("0x0000000000000000000000000000000000000000000000001bc16d674ec80000"),
        hex_to_bytes_32("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
    ];

    let mut database = Vec::new();
    for field in &account_fields {
        database.extend_from_slice(field);
    }

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let mut retrieved_fields = Vec::new();
    for idx in 0..3 {
        let (state, client_query) =
            query(&crs, idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();
        retrieved_fields.push(result);
    }

    for (idx, (retrieved, original)) in retrieved_fields.iter().zip(account_fields.iter()).enumerate() {
        assert_eq!(
            retrieved.as_slice(),
            original,
            "Consecutive word {} mismatch",
            idx
        );
    }
}

#[test]
fn test_realistic_ethereum_values() {
    let params = test_params();
    let entry_size = 32;

    let realistic_values = [
        hex_to_bytes_32("0x0000000000000000000000000000000000000000000000000000000000000000"),
        hex_to_bytes_32("0x0000000000000000000000000000000000000000000000056bc75e2d63100000"),
        hex_to_bytes_32("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        hex_to_bytes_32("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
        hex_to_bytes_32("0x0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4"),
        hex_to_bytes_32("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex_to_bytes_32("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        hex_to_bytes_32("0x0000000000000000000000000000000000000000000000000000000000000001"),
    ];

    let mut database = Vec::new();
    for value in &realistic_values {
        database.extend_from_slice(value);
    }

    let num_entries = realistic_values.len();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    for target_idx in 0..num_entries {
        let (state, client_query) =
            query(&crs, target_idx as u64, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
        let response = respond(&crs, &encoded_db, &client_query).unwrap();
        let result = extract(&crs, &state, &response, entry_size).unwrap();

        assert_eq!(
            result.as_slice(),
            &realistic_values[target_idx],
            "Realistic value {} mismatch",
            target_idx
        );
    }
}
