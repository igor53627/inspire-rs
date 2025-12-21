# InsPIRe Implementation Comparison Report

**inspire-rs vs Google Reference Implementation**

| | inspire-rs | Google InsPIRe |
|---|---|---|
| Repository | [igor53627/inspire-rs](https://github.com/igor53627/inspire-rs) | [google/private-membership](https://github.com/google/private-membership/tree/main/research/InsPIRe) |
| Purpose | Production PIR library | Research evaluation harness |
| HE Stack | Self-contained | Built on spiral-rs |

---

## 1. Architecture Overview

### inspire-rs

```
lib.rs
├── params          # InspireParams, SecurityLevel
├── modulus_switch  # Modulus switching (experimental)
├── math            # Poly, NTT, samplers
├── lwe             # LWE primitives
├── rlwe            # RlweSecretKey, RlweCiphertext
├── rgsw            # RgswCiphertext, external_product
├── ks              # Key-switching
├── inspiring       # InspiRING packing (inspiring2, automorph_pack, etc.)
├── pir             # setup/query/respond/extract API
│   ├── encode_db
│   ├── mmap
│   ├── error
│   └── ...
└── ethereum_db     # Ethereum integration
```

**Design Philosophy**: Standalone library with production-oriented APIs, sharding, mmap support, and service binaries (inspire-server, inspire-client, inspire-setup).

### Google InsPIRe

```
lib.rs
├── scheme          # SimplePIR, DoublePIR, InsPIRe orchestration
├── client/server   # Protocol endpoints
├── packing         # InspiRING + CDKS packing variants
├── params          # Auto-tuned parameter selection
├── kernel          # AVX-512 optimized operations
├── noise_analysis  # Security/correctness analysis
├── measurement     # Benchmarking infrastructure
└── (spiral-rs)     # External HE library dependency
```

**Design Philosophy**: Research artifact for comparative evaluation of multiple PIR protocol variants with heavy benchmarking focus.

---

## 2. Protocol Variants

| Variant | inspire-rs | Google |
|---------|------------|--------|
| SimplePIR | [X] | [OK] |
| DoublePIR | [X] | [OK] |
| InsPIRe (full) | [OK] | [OK] |
| InsPIRe^0 (NoPacking) | [OK] | [OK] |
| InsPIRe^1 (OnePacking) | [OK] | [OK] |
| InsPIRe^2 (Seeded+Packed) | [OK] | [OK] |
| InsPIRe^2+ (ModSwitch+Packed) | [OK]* | [OK] |
| Sqrt-N layout | [OK] | (via nu_1/nu_2) |

*InsPIRe^2+ is experimental and may exceed noise budget with default parameters.

**inspire-rs** implements the InsPIRe protocol with multiple variants:
- InsPIRe^0: `respond()` - no packing
- InsPIRe^1: `respond_one_packing()` - tree-packed response (uses `automorph_pack`)
- InsPIRe^2: `query_seeded()` + `respond_seeded_packed()` - seeded + packed
- InsPIRe^2+: `query_switched()` + `respond_switched_packed()` - experimental

---

## 3. Cryptographic Parameters

| Parameter | inspire-rs | Google |
|-----------|------------|--------|
| Ring dimension (d) | 2048 (configurable) | 2048 (fixed) |
| Modulus (q) | Single ~2^60 prime | CRT: [268369921, 249561089] |
| Noise (sigma) | 6.4 | 6.4 |
| Gadget base | 2^20 | ~2^19-2^20 |
| Gadget digits | 3 | 3 (t_gsw), varies for t_exp_* |
| Plaintext modulus (p) | 65536 | Scenario-dependent (2^14-2^16) |

### Key Difference: Modulus Strategy

- **inspire-rs**: Single large prime modulus - simpler implementation, no CRT complexity
- **Google**: CRT with two moduli - enables modulus switching optimizations but adds complexity

---

## 4. Database Handling

| Feature | inspire-rs | Google |
|---------|------------|--------|
| Sharding | [OK] Native ShardConfig/ShardData | [X] Monolithic |
| Persistence | [OK] Binary shard files | [X] In-memory only |
| Memory-mapping | [OK] MmapDatabase | [X] Not supported |
| Ethereum integration | [OK] ethereum_db module | [X] Generic only |
| Multi-layer DB | [X] Single layer | [OK] For DoublePIR/InsPIRe |

### inspire-rs Database Flow

```
Raw bytes → encode_database() → ShardData[] → save_shards_binary()
                                     ↓
                              MmapDatabase.open() → respond_mmap()
```

### Google Database Flow

```
Raw bytes → YServer::new() → in-memory matrices
                  ↓
          Multi-layer DBs for DoublePIR/InsPIRe variants
```

---

## 5. Performance Optimizations

| Optimization | inspire-rs | Google |
|--------------|------------|--------|
| SIMD (AVX-512) | [X] Portable Rust | [OK] Full AVX-512 |
| Parallelism | [OK] Rayon | Single-threaded |
| Seeded ciphertexts | [OK] SeededRgsw/Rlwe | [X] Not exposed |
| Modulus switching | [OK] SwitchedSeeded* | [OK] q2_bits |
| Memory-mapped I/O | [OK] | [X] |
| Aligned memory | Standard | AlignedMemory64 |

### Performance Trade-off

- **Google**: Maximum single-core throughput on AVX-512 hardware
- **inspire-rs**: Portability + multi-core parallelism via Rayon

---

## 6. InspiRING Packing

| Aspect | inspire-rs | Google |
|--------|------------|--------|
| Key-switch matrices | 2 (InspiRING) / log(d) (tree) | 2 (but configurable) |
| Multi-gamma support | [X] | [OK] (gamma_0, gamma_1, gamma_2) |
| Packing variants | Tree packing (default), InspiRING | NoPacking, CDKS, InspiRING |
| API exposure | Internal module + respond variants | Full packing pipeline |

Google's InspiRING is deeply integrated with multi-layer PIR (DoublePIR, InsPIRe variants), using multiple gamma parameters for staged packing.

**inspire-rs** implements both packing approaches:
- **Tree packing** (`automorph_pack`): Used by `respond_one_packing()` and the HTTP server. Uses log(d) Galois key-switching matrices stored in `galois_keys`.
- **InspiRING 2-matrix** (`inspiring2`): Available via `respond_inspiring()` for local experiments. Requires `ClientPackingKeys` which are not currently transmitted over the network API.

---

## 7. API Comparison

> **Note**: The examples below show simplified signatures for clarity.
> Actual functions include additional parameters (`shard_config`, `rlwe_sk`, `sampler`, `entry_size`).
> See the [module documentation](../src/pir/mod.rs) for full signatures.

### inspire-rs (Production-oriented)

```rust
// Setup
let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler);

// Query
let (state, query) = query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler);
// or seeded (50% smaller)
let (state, seeded_query) = query_seeded(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler);

// Response
let response = respond(&crs, &encoded_db, &query);
// or memory-mapped
let response = respond_mmap(&crs, &mmap_db, &query);

// Extract
let result = extract(&crs, &state, &response, entry_size);
```

### Google (Evaluation-oriented)

```rust
let protocol_type = ProtocolType::InsPIRe;
let (params, (db_rows, db_cols, item_bits)) = 
    params_for_scenario_medium_payload(N, item_size, gammas, perf_factor);

let server = YServer::new(&params, db, protocol_type);
let offline = server.perform_offline_precomputation_medium_payload(&gammas);

// Complex multi-step protocol with Measurement tracking
run_ypir_batched(&params, protocol_type, &mut measurement);
```

---

## 8. Features Unique to Each

### inspire-rs Only

| Feature | Description |
|---------|-------------|
| **Service binaries** | inspire-server, inspire-client, inspire-setup with Axum/Tokio |
| **Seeded compression** | SeededRlweCiphertext, SeededRgswCiphertext (~50% reduction) |
| **Modulus switching** | SwitchedSeededRgsw (experimental, exceeds noise budget with default params) |
| **Mmap support** | Memory-mapped database for large datasets |
| **Sharding** | Native multi-shard database support |
| **Ethereum DB** | Built-in Ethereum state integration |

### Google Only

| Feature | Description |
|---------|-------------|
| **Protocol variants** | SimplePIR, DoublePIR, InsPIRe^0, InsPIRe^2 |
| **CRT moduli** | Two-modulus CRT representation |
| **AVX-512 kernels** | Highly optimized SIMD operations |
| **Auto-tuning** | params_for_scenario_* with noise analysis |
| **Packing variants** | NoPacking, CDKS, InspiRING as options |
| **Measurement harness** | Structured benchmarking infrastructure |

---

## 9. Security Considerations

| Aspect | inspire-rs | Google |
|--------|------------|--------|
| Target security | 128-bit | 128-bit |
| Noise analysis | External (lattice-estimator) | Built-in noise_analysis module |
| Parameter validation | Manual via InspireParams | Auto-tuned per scenario |
| Correctness bounds | Implicit | Explicit subgaussian analysis |

Both implementations target 128-bit security. Google includes built-in noise analysis; inspire-rs validates parameters externally via lattice-estimator.

---

## 10. When to Use Which

### Use inspire-rs when:

- Building a **production PIR service**
- Need **sharding and mmap** for large databases
- Want **portable code** (no AVX-512 dependency)
- Integrating with **Ethereum state**
- Need **seeded ciphertext compression**
- Want a **simpler, auditable codebase**

### Use Google's implementation when:

- **Benchmarking** different PIR protocol variants
- Need **maximum per-core performance** on AVX-512
- Exploring **parameter trade-offs** with auto-tuning
- **Research** comparing SimplePIR/DoublePIR/InsPIRe
- Need **built-in noise analysis**

---

## 11. Potential Enhancements for inspire-rs

Based on this comparison, potential future enhancements:

1. **Add noise analysis module** - Built-in security/correctness verification
2. **CRT support (optional)** - Two-modulus representation for wider parameter space
3. **AVX-512 backend (feature flag)** - Optional high-performance path
4. **Parameter auto-tuning** - Scenario-based parameter selection
5. **SimplePIR variant** - For comparison/simpler use cases

Note: Seed expansion was implemented in December 2024, achieving 50% query size reduction (192 KB -> 98 KB).
Modulus switching is also available but exceeds noise budget with default parameters due to error amplification in external product.

---

## 12. Summary

| Dimension | inspire-rs | Google |
|-----------|------------|--------|
| **Focus** | Production deployment | Research evaluation |
| **Complexity** | Lower | Higher |
| **Portability** | High | AVX-512 dependent |
| **Protocol scope** | InsPIRe only | Multiple variants |
| **DB handling** | Sharded + mmap | In-memory |
| **API style** | Library | Evaluation harness |
| **Performance** | Multi-core Rayon | Single-core AVX-512 |

**inspire-rs** is a focused, production-ready implementation of the InsPIRe protocol with practical features (sharding, mmap, Ethereum integration). **Google's implementation** is a comprehensive research artifact for exploring the full PIR design space with maximum per-core performance.

---

*Report generated: December 2024*
*Comparison based on: google/private-membership @ main/research/InsPIRe*
