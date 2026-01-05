//! Generate test data files for manual CLI testing
//!
//! Run with: cargo run --example generate_test_data
//!
//! Creates:
//! - testdata/database.bin: 1024 entries of 32 bytes each
//! - testdata/account-mapping.bin: 10 test accounts
//! - testdata/storage-mapping.bin: 20 test storage slots

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use byteorder::{LittleEndian, WriteBytesExt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let testdata_dir = Path::new("testdata");
    std::fs::create_dir_all(testdata_dir)?;

    // Generate database with 1024 entries of 32 bytes each
    generate_database(testdata_dir)?;

    // Generate account mapping (10 accounts)
    generate_account_mapping(testdata_dir)?;

    // Generate storage mapping (20 slots)
    generate_storage_mapping(testdata_dir)?;

    println!("Test data generated in testdata/");
    println!();
    println!("To run PIR setup:");
    println!("  cargo run --release --bin inspire-setup -- \\");
    println!("    --database testdata/database.bin \\");
    println!("    --entry-size 32 \\");
    println!("    --output-dir testdata/pir");
    println!();
    println!("To query by index:");
    println!("  cargo run --release --bin inspire-client -- \\");
    println!("    --server http://localhost:3000 \\");
    println!("    --secret-key testdata/pir/secret_key.json \\");
    println!("    index 42");

    Ok(())
}

fn generate_database(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = dir.join("database.bin");
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    let num_entries = 1024;
    let entry_size = 32;

    for i in 0..num_entries {
        // Generate deterministic 32-byte entries
        // Pattern: first 8 bytes = index, rest = index-based pattern
        let mut entry = [0u8; 32];

        // First 8 bytes: little-endian index
        entry[0..8].copy_from_slice(&(i as u64).to_le_bytes());

        // Remaining bytes: pattern based on index
        for j in 8..entry_size {
            entry[j] = ((i * 17 + j * 13) % 256) as u8;
        }

        writer.write_all(&entry)?;
    }

    writer.flush()?;
    println!(
        "Created {} ({} entries x {} bytes)",
        path.display(),
        num_entries,
        entry_size
    );

    Ok(())
}

fn generate_account_mapping(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = dir.join("account-mapping.bin");
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    // 10 test accounts at known indices
    let accounts: Vec<([u8; 20], u64)> = vec![
        // Vitalik's address (example)
        (
            hex_to_address("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            0,
        ),
        // Some test addresses
        (
            hex_to_address("0000000000000000000000000000000000000001"),
            10,
        ),
        (
            hex_to_address("0000000000000000000000000000000000000002"),
            20,
        ),
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            100,
        ),
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            200,
        ),
        (
            hex_to_address("3333333333333333333333333333333333333333"),
            300,
        ),
        (
            hex_to_address("4444444444444444444444444444444444444444"),
            400,
        ),
        (
            hex_to_address("5555555555555555555555555555555555555555"),
            500,
        ),
        (
            hex_to_address("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            777,
        ),
        (
            hex_to_address("cafebabecafebabecafebabecafebabecafebabe"),
            999,
        ),
    ];

    for (address, index) in &accounts {
        writer.write_all(address)?;
        writer.write_u64::<LittleEndian>(*index)?;
    }

    writer.flush()?;
    println!("Created {} ({} accounts)", path.display(), accounts.len());

    Ok(())
}

fn generate_storage_mapping(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = dir.join("storage-mapping.bin");
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    // 20 test storage slots
    let slots: Vec<([u8; 20], [u8; 32], u64)> = vec![
        // Contract 1: slots 0-4
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            100,
        ),
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000001"),
            101,
        ),
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000002"),
            102,
        ),
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000003"),
            103,
        ),
        (
            hex_to_address("1111111111111111111111111111111111111111"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000004"),
            104,
        ),
        // Contract 2: slots 0-4
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            200,
        ),
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000001"),
            201,
        ),
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000002"),
            202,
        ),
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000003"),
            203,
        ),
        (
            hex_to_address("2222222222222222222222222222222222222222"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000004"),
            204,
        ),
        // Contract 3: various slots
        (
            hex_to_address("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            777,
        ),
        (
            hex_to_address("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            hex_to_slot("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            778,
        ),
        // Some mapping slots (keccak256 style)
        (
            hex_to_address("cafebabecafebabecafebabecafebabecafebabe"),
            hex_to_slot("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
            900,
        ),
        (
            hex_to_address("cafebabecafebabecafebabecafebabecafebabe"),
            hex_to_slot("b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"),
            901,
        ),
        (
            hex_to_address("cafebabecafebabecafebabecafebabecafebabe"),
            hex_to_slot("405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"),
            902,
        ),
        // Additional entries
        (
            hex_to_address("3333333333333333333333333333333333333333"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            300,
        ),
        (
            hex_to_address("4444444444444444444444444444444444444444"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            400,
        ),
        (
            hex_to_address("5555555555555555555555555555555555555555"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            500,
        ),
        (
            hex_to_address("6666666666666666666666666666666666666666"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            600,
        ),
        (
            hex_to_address("7777777777777777777777777777777777777777"),
            hex_to_slot("0000000000000000000000000000000000000000000000000000000000000000"),
            700,
        ),
    ];

    for (address, slot, index) in &slots {
        writer.write_all(address)?;
        writer.write_all(slot)?;
        writer.write_u64::<LittleEndian>(*index)?;
    }

    writer.flush()?;
    println!("Created {} ({} slots)", path.display(), slots.len());

    Ok(())
}

fn hex_to_address(hex: &str) -> [u8; 20] {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let mut bytes = [0u8; 20];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= 20 {
            break;
        }
        let s = std::str::from_utf8(chunk).unwrap();
        bytes[i] = u8::from_str_radix(s, 16).unwrap();
    }
    bytes
}

fn hex_to_slot(hex: &str) -> [u8; 32] {
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
