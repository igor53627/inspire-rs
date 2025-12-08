![CI](https://github.com/igor53627/inspire-rs/actions/workflows/ci.yml/badge.svg)

# inspire-rs

**InsPIRe: Communication-Efficient PIR with Server-side Preprocessing**

A Rust implementation of the InsPIRe PIR (Private Information Retrieval) protocol, designed for private queries over large databases like Ethereum state (~73 GB, 2.4 billion entries).

## Overview

InsPIRe achieves state-of-the-art communication efficiency for single-server PIR through:

- **InspiRING Ring Packing**: Novel LWE→RLWE transformation using only 2 key-switching matrices (vs logarithmic in prior work)
- **Homomorphic Polynomial Evaluation**: Reduced response size via encrypted polynomial evaluation
- **CRS Model**: Server-side preprocessing for amortized efficiency

## Features

- 128-bit security (validated via lattice-estimator)
- Support for 32-byte entries (Ethereum state format)
- Database sharding for large datasets
- CLI binaries for server/client/setup
- Integration with [plinko-extractor](https://github.com/pse-team/plinko-extractor) format

## Usage

### Setup (Server-side preprocessing)

```bash
cargo run --release --bin inspire-setup -- \
  --database path/to/database.bin \
  --entry-size 32 \
  --output-dir ./pir-data
```

### Server

```bash
cargo run --release --bin inspire-server -- \
  --crs ./pir-data/crs.json \
  --database ./pir-data/encoded.json \
  --port 3000
```

### Client

```bash
cargo run --release --bin inspire-client -- \
  --crs ./pir-data/crs.json \
  --index 12345 \
  --server http://localhost:3000
```

## Protocol

1. **Setup(D)**: Server encodes database as polynomials, generates CRS
2. **Query(idx)**: Client encrypts target index as RGSW ciphertext
3. **Respond(D', qry)**: Server performs homomorphic rotation
4. **Extract(st, resp)**: Client decrypts RLWE response

The key insight: storing value `y_k` at coefficient `k` of polynomial `h(X)`, then multiplying by `X^{-k}` (the inverse monomial) rotates `y_k` to coefficient 0.

## Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Ring dimension d | 2048 | Power of two |
| Ciphertext modulus q | 2^60 - 2^14 + 1 | NTT-friendly |
| Plaintext modulus p | 2^16 | For 32-byte entries |
| Error σ | 3.2 | Discrete Gaussian |
| Key-switching matrices | 2 | K_g, K_h only |

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## Quick Start with Test Data

Generate test data files:

```bash
cargo run --example generate_test_data
```

This creates:
- `testdata/database.bin` - 1024 entries of 32 bytes
- `testdata/account-mapping.bin` - 10 test accounts
- `testdata/storage-mapping.bin` - 20 test storage slots

Run PIR setup:

```bash
cargo run --release --bin inspire-setup -- \
  --database testdata/database.bin \
  --entry-size 32 \
  --output-dir testdata/pir
```

## Documentation

- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) - Architecture details
- [docs/COMMUNICATION_COSTS.md](docs/COMMUNICATION_COSTS.md) - Bandwidth analysis
- [docs/PIR_COMPARISON.md](docs/PIR_COMPARISON.md) - Scheme comparison

## License

MIT OR Apache-2.0

## References

- [InsPIRe Paper](https://eprint.iacr.org/2024/XXX) - Original protocol specification
