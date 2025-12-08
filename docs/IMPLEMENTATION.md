# InsPIRe Implementation for Ethereum State PIR

## Overview

This document outlines the implementation of InsPIRe PIR protocol in Rust for private queries over the Ethereum state database (~73 GB, 2.4 billion entries).

## Key Design Decisions

### 1. Parameter Selection (128-bit Security)

Based on the InsPIRe paper's validated parameters:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Ring dimension d | 2048 | Power of two, balances security/performance |
| Ciphertext modulus q | 2^60 - 2^14 + 1 | NTT-friendly: q ≡ 1 (mod 4096) |
| Plaintext modulus p | 2^16 | Packs 32-byte entries across coefficients |
| Error σ | 3.2 | Discrete Gaussian parameter |
| Gadget base z | 2^20 | For key-switching decomposition |
| Key-switching matrices | 2 | K_g, K_h (vs logarithmic in prior work) |

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
│   ├── math/
│   │   ├── mod_q.rs           # Modular arithmetic Z_q
│   │   ├── ntt.rs             # Number-Theoretic Transform
│   │   ├── poly.rs            # Polynomials over R_q
│   │   └── gaussian.rs        # Error sampling
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
│   │   └── pack.rs            # Pack, PartialPack
│   ├── pir/
│   │   ├── setup.rs           # InsPIRe.Setup
│   │   ├── query.rs           # InsPIRe.Query
│   │   ├── respond.rs         # InsPIRe.Respond (parallel by default)
│   │   ├── extract.rs         # InsPIRe.Extract
│   │   ├── encode_db.rs       # EncodeDB, Interpolate
│   │   ├── eval_poly.rs       # Homomorphic polynomial evaluation
│   │   └── mmap.rs            # Memory-mapped database support
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
   - Generate CRS (K_g, K_h, Galois keys)
   - EncodeDB: Convert database to polynomial representation
   - Interpolate: Cooley-Tukey for polynomial coefficients
   - GenFixedQueryParts: Precompute CRS-dependent values

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
| CRS/Key material | seconds-minutes | <10 MB |
| DB encoding (73 GB) | 1-2 hours | ~73 GB |
| Total | ~2 hours | ~150 GB |

### Online Query

Based on paper benchmarks for 1 GB database:

| Metric | InsPIRe | YPIR (comparison) |
|--------|---------|-------------------|
| Query size | 236-504 KB | 802-858 KB |
| Response size | Included above | Similar |
| Server time | 120-650 ms | 140-600 ms |
| Throughput | 1.5-8.7 GB/s | 1.7-7.4 GB/s |

## Ethereum Database Integration

### Data Format (from plinko-extractor)

- **database.bin**: Flat binary, 32-byte words
  - Accounts: 3 words (nonce, balance, bytecode_hash)
  - Storage: 1 word (value)
- **account-mapping.bin**: Address(20) + Index(4)
- **storage-mapping.bin**: Address(20) + SlotKey(32) + Index(4)

### Client Flow

1. Wallet needs `(address, maybe_slot)`
2. Lookup index via mapping (local or remote)
3. `InspireClient::query(idx)` → PIR query
4. Send to server → `InspireServer::respond()`
5. `InspireClient::extract()` → 32-byte value

## Dependencies

Core (no external FHE library needed):
- `rand`, `rand_chacha`: Randomness
- `rayon`: Parallelism for NTT/preprocessing
- `memmap2`: Memory-mapped database access
- `axum`, `tokio`: Server API

## Security Considerations

- Parameters validated via lattice-estimator for 128-bit security
- CRS model: random components fixed but secret keys re-sampled per query
- No client-specific server state (supports anonymity)
- Circular security assumption (standard for lattice FHE)
- Secret keys separated from CRS (ServerCrs contains only public params)
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
