# InsPIRe Implementation for Ethereum State PIR

## Overview

This document outlines the implementation of InsPIRe PIR protocol in Rust for private queries over the Ethereum state database (~73 GB, 2.4 billion entries).

## Key Design Decisions

### 1. Parameter Selection (128-bit Security)

Based on the InsPIRe paper's validated parameters:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Ring dimension d | 2048 | Power of two, balances security/performance |
| Ciphertext modulus q | CRT moduli [268369921, 249561089] (q ≈ 2^56) | NTT-friendly per-modulus |
| Plaintext modulus p | 2^16 | Packs 32-byte entries across coefficients |
| Error σ | 6.4 | Discrete Gaussian parameter |
| Gadget base z | 2^20 | For key-switching decomposition |
| Key-switching matrices | 2 | K_g, K_h (vs logarithmic in prior work) |

**Note**: Single-modulus params remain available for modulus-switching experiments; default secure_128 params use CRT.

### 2. Database Sharding

The 73 GB Ethereum state is sharded into ~1 GB chunks:

- **Entries per shard**: ~33M (2^25)
- **Total shards**: ~72
- **Index decomposition**: `global_idx → (shard_id, local_idx)`

### 3. Architecture

```
inspire-pir/
├── src/
│   ├── lib.rs                 # Public API
│   ├── params.rs              # Parameter sets
│   ├── modulus_switch.rs      # Modulus switching (experimental)
│   ├── math/
│   │   ├── crt.rs             # CRT helpers (compose/decompose)
│   │   ├── mod_q.rs           # Modular arithmetic Z_q
│   │   ├── modular.rs         # Montgomery reduction
│   │   ├── ntt.rs             # Number-Theoretic Transform
│   │   ├── poly.rs            # Polynomials over R_q
│   │   ├── gaussian.rs        # Error sampling
│   │   ├── sampler.rs         # Sampler traits
│   │   └── sampling.rs        # Uniform/ternary sampling
│   ├── lwe/
│   │   ├── types.rs           # LWE ciphertext, secret key
│   │   └── enc.rs             # LWE encryption/decryption
│   ├── rlwe/
│   │   ├── types.rs           # RLWE ciphertext, keys
│   │   ├── enc.rs             # RLWE operations
│   │   └── galois.rs          # τ_g automorphisms
│   ├── rgsw/
│   │   ├── types.rs           # RGSW encryption
│   │   └── external_product.rs
│   ├── ks/
│   │   ├── setup.rs           # KS.Setup
│   │   └── switch.rs          # KS.Switch
│   ├── inspiring/
│   │   ├── transform.rs       # Transform, TransformPartial
│   │   ├── collapse.rs        # Collapse, CollapseHalf
│   │   ├── collapse_one.rs    # CollapseOne
│   │   ├── pack.rs            # Pack, PartialPack
│   │   ├── inspiring2.rs      # Canonical 2-matrix InspiRING API
│   │   ├── automorph_pack.rs  # Tree packing via automorphisms
│   │   ├── simple_pack.rs     # Simple LWE packing
│   │   └── types.rs           # Packing types
│   ├── pir/
│   │   ├── setup.rs           # InsPIRe.Setup
│   │   ├── query.rs           # InsPIRe.Query
│   │   ├── respond.rs         # InsPIRe.Respond (parallel by default)
│   │   ├── extract.rs         # InsPIRe.Extract
│   │   ├── encode_db.rs       # EncodeDB, Interpolate
│   │   ├── eval_poly.rs       # Homomorphic polynomial evaluation
│   │   ├── mmap.rs            # Memory-mapped database support
│   │   └── error.rs           # PIR error types
│   ├── ethereum_db/
│   │   ├── mapping.rs         # Parse account/storage mappings
│   │   └── adapter.rs         # Convert to InsPIRe shards
│   └── bin/
│       ├── server.rs          # PIR server
│       ├── client.rs          # PIR client
│       └── setup.rs           # Database preprocessing
```

## Core Algorithms

### InspiRING Ring Packing

Transforms d LWE ciphertexts into a single RLWE ciphertext using only 2 key-switching matrices:

1. **Transform**: `(a, b) ∈ Z_q^d × Z_q → (â, b̃) ∈ R_q^d × R_q`
   - Embed LWE vectors into ring elements
   - Precompute rotation patterns via τ_g automorphisms

2. **Collapse**: Reduce aggregated ciphertexts using K_g, K_h
   - Uses RGSW external product and key-switching
   - CollapseHalf, CollapseOne for dimensional reduction

3. **Pack/PartialPack**: Orchestrate the full pipeline

### InsPIRe PIR Protocol

1. **Setup(D)**: Server-side preprocessing
   - Generate CRS: automorphism key-switching matrices (`k_g`, `k_h`), tree-packing Galois keys, CRS `a`-vectors, and InspiRING packing precomputation
   - EncodeDB: Convert database to polynomial representation (encoding + interpolation internally)

2. **Query(idx)**: Client generates query
   - Decompose: `idx → (shard_id, local_idx)`
   - Generate LWE ciphertexts for first PIR layer
   - Combine with CRS fixed parts

3. **Respond(D', qry)**: Server computes response
   - InspiRING packing (LWE → RLWE)
   - Homomorphic polynomial evaluation
   - Output RLWE ciphertext(s)

4. **Extract(st, resp)**: Client decrypts
   - Decrypt RLWE response
   - Map coefficients to 32-byte entry

## Performance Estimates

### Server Preprocessing (One-time per snapshot)

| Component | Time | Storage |
|-----------|------|---------|
| CRS/Key material | seconds-minutes | ~40-50 MB (d=2048) |
| DB encoding (73 GB) | 1-2 hours | ~73 GB |
| Total | ~2 hours | ~120 GB |

Note: CRS size is dominated by `crs_a_vectors` (d×d coefficients ≈ 33 MB for d=2048) and InspiRING offline precomputation.

### Online Query

Based on paper benchmarks for 1 GB database:

| Metric | InsPIRe | YPIR (comparison) |
|--------|---------|-------------------|
| Query size | 236-504 KB | 802-858 KB |
| Response size | Included above | Similar |
| Server time | 120-650 ms | 140-600 ms |
| Throughput | 1.5-8.7 GB/s | 1.7-7.4 GB/s |

### Parallel Response Performance

The `respond()` function uses `rayon` for parallel column processing. Benchmarks on Apple M-series (ring_dim=256):

| Columns | Sequential | Parallel | Speedup |
|---------|-----------|----------|---------|
| 1 | 917 µs | 939 µs | ~1x |
| 2 | 1.83 ms | 365 µs | **5.0x** |
| 4 | 3.63 ms | 626 µs | **5.8x** |
| 8 | 7.31 ms | 1.02 ms | **7.2x** |

Run benchmarks with: `cargo bench --bench respond`

The parallel implementation is the default. A sequential version (`respond_sequential`) is available for comparison and debugging.

### Memory-Mapped Database Mode

For large databases (73GB Ethereum state), use memory-mapped mode to avoid loading everything into RAM:

**Setup (generate binary shards):**
```bash
cargo run --release --bin inspire-setup -- \
  --data-dir ./plinko-data \
  --output-dir ./inspire_data \
  --binary-output
```

**Server (use mmap mode):**
```bash
cargo run --release --bin inspire-server -- \
  --data-dir ./inspire_data \
  --mmap
```

Benefits:
- Shards loaded on-demand from disk
- Minimal startup memory footprint
- OS page cache handles hot shard caching
- Suitable for databases larger than available RAM

## Ethereum Database Integration

### Data Format (from plinko-extractor)

- **database.bin**: Flat binary, 32-byte words
  - Accounts: 3 words (nonce, balance, bytecode_hash) = 96 bytes
  - Storage: 1 word (value) = 32 bytes
- **account-mapping.bin**: Address(20 bytes) + Index(8 bytes LE)
- **storage-mapping.bin**: Address(20 bytes) + SlotKey(32 bytes) + Index(8 bytes LE)

### Client Flow

1. Wallet needs `(address, maybe_slot)`
2. Lookup index via mapping (local or remote)
3. Client generates query: `query(&crs, idx, ...)` or `query_seeded(...)` → PIR query
4. Send to server HTTP endpoint → server calls `respond(&crs, &db, &query)`
5. Client extracts: `extract(&crs, &state, &response, entry_size)` → 32-byte value

CLI usage:
```bash
# Query by raw index
inspire-client --server http://localhost:3000 Index --index 12345

# Query account by address
inspire-client --server http://localhost:3000 Account --address 0x...
```

## Dependencies

Core (no external FHE library needed):
- `rand`, `rand_chacha`: Randomness
- `rayon`: Parallelism for NTT/preprocessing
- `memmap2`: Memory-mapped database access
- `axum`, `tokio`: Server API

## Security Considerations

- Parameters validated via lattice-estimator for 128-bit security
- CRS model: random CRS components and key-switching matrices are fixed at `setup`; the RLWE secret key is generated once and reused across queries
- No client-specific server state (supports anonymity)
- Circular security assumption (standard for lattice FHE)
- Secret keys separated from CRS (`ServerCrs` contains only public parameters and precomputation, no secret key)
- `#[serde(skip)]` on secret key fields prevents accidental serialization

## Implementation Phases

1. **Phase 1**: Math primitives (NTT, polynomial arithmetic, Gaussian sampling)
2. **Phase 2**: Lattice crypto (LWE, RLWE, key-switching)
3. **Phase 3**: InspiRING ring packing
4. **Phase 4**: PIR protocol
5. **Phase 5**: Ethereum DB integration
6. **Phase 6**: Server/client binaries, benchmarks

## References

- [InsPIRe Paper](docs/inspire_paper.json) - Full protocol specification
- [Plinko Extractor](../plinko-extractor/) - Database format
- [lattice-estimator](https://github.com/malb/lattice-estimator) - Security validation
