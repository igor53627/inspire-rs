![CI](https://github.com/igor53627/inspire-rs/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/inspire.svg)](https://crates.io/crates/inspire)
[![Docs](https://docs.rs/inspire/badge.svg)](https://docs.rs/inspire)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/igor53627/inspire-rs)
[![Interactive Visualization](https://img.shields.io/badge/Demo-Protocol%20Visualization-blue)](https://igor53627.github.io/inspire-rs/protocol-visualization.html)

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
  --data-dir path/to/plinko-output \
  --output-dir ./inspire_data \
  --ring-dim 2048 \
  --binary-output  # optional: also write binary shards for mmap
```

### Server

```bash
cargo run --release --bin inspire-server -- \
  --data-dir ./inspire_data \
  --bind 0.0.0.0:3000 \
  --mmap  # optional: use memory-mapped shards
```

### Client

```bash
# Query by raw index
cargo run --release --bin inspire-client -- \
  --server http://localhost:3000 \
  --secret-key inspire_data/secret_key.json \
  Index --index 12345

# Query account by address
cargo run --release --bin inspire-client -- \
  --server http://localhost:3000 \
  --secret-key inspire_data/secret_key.json \
  --account-mapping inspire_data/account-mapping.bin \
  Account --address 0x...
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
| Ciphertext modulus q | CRT moduli [268369921, 249561089] (q ≈ 2^56) | NTT-friendly per-modulus |
| Plaintext modulus p | 2^16 | For 32-byte entries |
| Error σ | 6.4 | Discrete Gaussian |
| Key-switching matrices | 2 | K_g, K_h only (InspiRING) |

### InspiRING Key Material Comparison (Conceptual)

| Approach | KS Matrices | Conceptual Storage |
|----------|-------------|-------------------|
| Tree Packing | log(d) = 11 | 1056 KB |
| InspiRING (2-matrix) | 2 (seeds only) | 64 bytes |
| **Reduction** | **5.5x** | **16,000x** |

**Note**: The conceptual 64-byte figure refers only to InspiRING packing-key seeds. The actual `ServerCrs` in this implementation is ~40-50 MB (d=2048), dominated by `crs_a_vectors` (d×d coefficients ≈ 33 MB) and offline precomputation. The HTTP server defaults to **InspiRING** when clients send packing keys; tree packing is opt-in via `packing_mode=tree`. Default parameters now use CRT moduli (two residues per coefficient); single-modulus params remain for switched-query experiments.

## Building

```bash
cargo build --release
```

### WebAssembly (WASM) Builds

The library supports building for `wasm32-unknown-unknown` targets (browsers) by disabling server-specific features:

```toml
# In your Cargo.toml
[dependencies]
inspire = { version = "0.1", default-features = false }
```

Build with wasm-pack:

```bash
wasm-pack build --target web -- --no-default-features
```

#### WASM Caveats

1. **Parallelism (rayon)**: The library uses `rayon` for parallel computation. On WASM:
   - Requires wasm threads (nightly + `-Z build-std` + `+atomics,+bulk-memory`)
   - Integrate with `wasm-bindgen-rayon` for thread pool initialization
   - Without threads, operations run sequentially on the main thread

2. **Random number generation**: The `rand` crate requires `getrandom` JS support:
   ```toml
   [dependencies]
   getrandom = { version = "0.2", features = ["js"] }
   ```

3. **Feature availability**: With `default-features = false`:
   - [OK] Core PIR: setup, query, respond, extract
   - [X] Server features: mmap, ethereum_db, HTTP endpoints
   - [X] CLI features: binary executables

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

## Communication Costs

InsPIRe offers 3 protocol variants with different bandwidth/computation tradeoffs:

| Variant | Query | Response | Total | Reduction |
|---------|-------|----------|-------|-----------|
| **InsPIRe^0** (NoPacking) | 192 KB | 545 KB | **737 KB** | baseline |
| **InsPIRe^1** (OnePacking) | 192 KB | 32 KB | **224 KB** | 3.3x |
| **InsPIRe^2** (Seeded+Packed) | 96 KB | 32 KB | **128 KB** | 5.7x |

**Production recommendation**: use **InsPIRe^2 (TwoPacking)** — seeded query + packed response.

These costs are **independent of database size**—the same whether querying 1 MB or 73 GB.

**Note**: The table reflects serialized sizes in single-modulus mode (crt_moduli length 1). With CRT enabled (default), ciphertexts store two residues per coefficient and sizes increase roughly proportionally.

> **Why constant sizes?** This is a privacy requirement. If sizes varied with target index or database, traffic analysis could reveal what's being queried. See [docs/COMMUNICATION_COSTS.md](docs/COMMUNICATION_COSTS.md#why-pir-sizes-are-constant) for the formulas.

### Protocol Variants

```rust
use inspire::{query, query_seeded, respond_one_packing, respond_seeded_packed};
use inspire::params::InspireVariant;

// InsPIRe^0: Simple, no packing
let response = respond(&crs, &db, &query)?;

// InsPIRe^1: Packed response (17x response reduction)
let response = respond_one_packing(&crs, &db, &query)?;

// InsPIRe^2: Seeded query + packed response (5.7x total reduction)
let (state, seeded_query) = query_seeded(&crs, index, &config, &sk, &mut sampler)?;
let response = respond_seeded_packed(&crs, &db, &seeded_query)?;

// Extract with variant-specific extraction
let entry = extract_with_variant(&crs, &state, &response, entry_size, InspireVariant::TwoPacking)?;
```

## Performance

Benchmarked on AMD/Intel x64 server with d=2048, 128-bit security:

### Server Response Time

| Database Size | Shards | Respond Time |
|---------------|--------|--------------|
| 256K entries (8 MB) | 128 | 3.8 ms |
| 512K entries (16 MB) | 256 | 3.1 ms |
| 1M entries (32 MB) | 512 | 3.3 ms |

### End-to-End Latency

| Phase | Time |
|-------|------|
| Client: Query generation (seeded) | ~4 ms |
| Server: Expand + Respond | ~3-4 ms |
| Client: Extract result | ~5 ms |
| **Total round-trip** | **~12 ms** |

### Packing Performance

The implementation supports two packing approaches:

| Approach | Used By | Complexity | Notes |
|----------|---------|------------|-------|
| Tree packing | `respond_one_packing()` | O(log d) key-switches | Opt-in via `packing_mode=tree` |
| InspiRING 2-matrix | `respond_inspiring()` | O(γ × ℓ × n) online | Default for networked API (requires packing keys) |

**Tree packing** (via `automorph_pack`) is available as an explicit fallback. Set `packing_mode=tree` and use `extract_with_variant(..., InspireVariant::OnePacking)` to unpack. This uses log(d) Galois key-switching matrices stored in the CRS.

**InspiRING 2-matrix** packing is implemented in `inspiring2` module with optimizations matching Google's reference:
- NTT-domain automorphisms via precomputed permutation tables
- Fused multiply-accumulate in NTT domain
- Pre-cached bold_t in NTT form for zero-conversion online phase

**HTTP API note:** Query JSON includes `packing_mode` (`\"inspiring\"` or `\"tree\"`, default `\"inspiring\"`). If `packing_mode=\"inspiring\"` and `inspiring_packing_keys` are missing, the server returns `400` with a descriptive error. Use `packing_mode=\"tree\"` to opt in to tree packing (both in-memory and mmap modes support InspiRING when keys are present).

Run benchmarks: `cargo bench --bench packing`

Run query size analysis: `cargo run --release --example query_size_comparison`

## Documentation

- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) - Architecture details
- [docs/COMMUNICATION_COSTS.md](docs/COMMUNICATION_COSTS.md) - Bandwidth analysis
- [docs/protocol-visualization.html](docs/protocol-visualization.html) - Interactive D3 visualization of protocol and costs

## License

MIT OR Apache-2.0

## References

- [InsPIRe Paper](https://eprint.iacr.org/2025/1352) - Original protocol specification (IEEE S&P 2025)
