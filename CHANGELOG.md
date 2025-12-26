# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **STATE_FORMAT support**: `inspire-setup` now reads new `state.bin` format instead of plinko-extractor format (Issue #32)
  - Single `state.bin` file with 64-byte header + 84-byte entries (address + slot + value)
  - Removed support for legacy `database.bin`, `account-mapping.bin`, `storage-mapping.bin` files
  - Added `StateHeader`, `StorageEntry` types to `ethereum_db` module
  - PIR entries remain 32 bytes (value only); address+slot used for bucket indexing
  - Updated `inspire-client` to use `state.bin` for storage slot lookups
  - Removed `AccountMapping`, `StorageMapping` and related functions
- **Default packing algorithm**: `respond_with_variant` for OnePacking/TwoPacking now uses InspiRING when `inspiring_packing_keys` is present in the query (~35x faster online), falling back to tree packing otherwise
- **HTTP server**: Uses InspiRING for in-memory databases when packing keys are available
- **Documentation**: Fixed performance claims ("226x faster" -> "~35x faster") and clarified CRS size comparison in protocol-visualization.html

### Fixed

- **protocol-visualization.html**: Fixed incorrect claims per issue #31
  - Key Privacy Property: Now correctly states query size depends on N (via N/t indicator) and response depends on entry size
  - Query structures: InsPIRe_0 and InsPIRe^(2) now correctly show LWE indicator vectors (no RGSW); only InsPIRe uses RGSW ciphertext
  - Variant naming: Aligned with paper notation (InsPIRe_0, InsPIRe^(2), InsPIRe, InsPIRe+)
  - Key material: Added separate "Upload Keys" chart showing packing keys (86 KB) per Theorem 12; Protocol Flow now shows "Upload: Keys + Query" breakdown matching paper's Figure 2/3

### Added

- **WASM Support**: Enable building for `wasm32-unknown-unknown` targets (browsers)
  - `server` feature flag: gates axum, tokio, memmap2, reqwest dependencies
  - `cli` feature flag: gates clap, eyre, tracing-subscriber, indicatif dependencies
  - Stable `PirError` type that works across all feature configurations
  - `pir_err!` macro for portable error creation
  - Server-only modules (`mmap`, `ethereum_db`) gated behind `server` feature
  - Binaries have `required-features` to prevent build failures with `--no-default-features`
  - Documentation for WASM build caveats (rayon threads, getrandom JS)

### Changed

- **InspiRING 2-Matrix Packing Algorithm**: Canonical port of Google's reference implementation
  - `inspiring2` module faithfully implementing Google's `packing.rs` algorithm
  - Uses only 2 key-switching matrices (K_g, K_h) instead of log(d)=11 matrices
  - **New canonical API** (matching Google's structure):
    - `PackParams` - packing parameters with correct generator formula `gen = 2n/gamma + 1`
    - `PrecompInsPIR` - offline precomputation (a_hat, bold_t, bold_t_bar, bold_t_hat)
    - `OfflinePackingKeys` - server-side key generation with w_all rotations
    - `ClientPackingKeys` - client-side key generation with y_all rotations
    - `packing_offline()` - R[i] inner products with g^(n-i), 1/gamma scaling, automorphisms, backward recursion
    - `packing_online()` - y_all x bold_t multiplication
    - `packing_online_fully_ntt()` - fully NTT-optimized online phase (O(n) per multiply)
    - `full_packing_offline()` - parallel dual recursion for gamma=n
    - `generate_rotations()` - generate y_all from y_body
  - **Google-matching performance optimizations**:
    - NTT-domain automorphisms via precomputed permutation tables: O(n) vs O(n log n)
    - `automorph_tables` stored in `PackParams` for all odd automorphism indices
    - `apply_automorphism_ntt()` and `apply_automorphism_ntt_double()` for O(n) NTT-domain automorphisms
    - `mod_inv_poly_ntt` for fast scalar multiply in NTT domain
    - Fused multiply-accumulate using `mul_acc_ntt_domain()` in Poly
    - Pre-cached `bold_t_ntt` in PrecompInsPIR for zero-conversion online phase
    - Shared `NttContext` passed through key generation functions
    - All rotation generation uses NTT-domain automorphisms
  - **Legacy API** (compatibility layer):
    - `GeneratorPowers` - precomputed g^i mod 2d table
    - `RotatedKsMatrix` - pre-rotated K_g by automorphisms
    - `precompute_inspiring()`, `pack_inspiring_legacy()`, `pack_inspiring_partial()`, `pack_inspiring_full()`
  - Performance: **35x faster** online packing (115μs vs ~4ms for d=2048, 16 LWEs)
  - CRS key material: **16,000x smaller** (64 bytes seeds vs 1056 KB for d=2048)
  - Updated docs/protocol-visualization.html with algorithm comparison toggle
  - **Protocol Flow section now variant-aware**: Toggle between ^0, ^1, ^2, ^2+ to see different query/response flows
  - Each variant shows accurate sizes and processing steps (e.g., InspiRING packing for ^1+)
  - New benchmark groups: `ntt_automorphism_d2048`, `production_inspiring2_d2048`
  - New example: `cargo run --release --example query_size_comparison`
  - References: https://github.com/google/private-membership/tree/main/research/InsPIRe

- **InsPIRe^1 (OnePacking) implementation**: Automorphism-based tree packing for response compression
  - `pack_lwes()` packs multiple LWE ciphertexts into single RLWE using Galois automorphisms
  - `respond_one_packing()` for packed server responses (17x response size reduction)
  - `extract_packed()` for extracting columns from packed response
  - Response size: 545 KB -> 32 KB (17x smaller)
  - Total roundtrip: 737 KB -> 224 KB (3.3x reduction)

- **InsPIRe^2 (TwoPacking) implementation**: Seeded query + packed response
  - `respond_seeded()` and `respond_seeded_packed()` for seeded query handling
  - `respond_switched()` and `respond_switched_packed()` for maximum compression
  - Query size: 192 KB -> 96 KB (seeded) or 48 KB (switched)
  - Total roundtrip with ^2: 128 KB (5.7x reduction from ^0)
  - Total roundtrip with ^2+: 80 KB (9.2x reduction from ^0)

- Automorphism key infrastructure for tree packing:
  - `generate_automorph_keys()` creates log(d) key-switching matrices
  - `galois_keys` field in `ServerCrs` for automorphism operations
  - `homomorphic_automorph()` for applying automorphisms with key-switching
  - `YConstants` for tree packing y-values at each level

- `InspireVariant` enum for protocol variant selection (NoPacking, OnePacking, TwoPacking)
- `respond_with_variant()` and `extract_with_variant()` functions for explicit variant selection
- `RlweCiphertext::sample_extract_coeff0()` for RLWE → LWE sample extraction
- InspiRING packing infrastructure:
  - `LweSecretKey::from_rlwe()` to derive LWE key from RLWE key coefficients
  - `generate_packing_ks_matrix()` for LWE→RLWE key-switching matrix setup
  - `packing_k_g` and `packing_k_h` fields in `ServerCrs` for packing keys
  - `pack_rlwe_coeffs()` helper for RLWE coefficient packing
  - `invert_sample_extract()` to convert LWE a-vector back to RLWE polynomial form
  - `prep_pack_lwes()` to prepare LWEs for tree packing
- Benchmark example: `cargo run --example benchmark_variants --release`
- New e2e tests: `test_e2e_variant_no_packing`, `test_variant_packing_unimplemented`
- Modulus switching module for ciphertext compression
  - `modulus_switch` module with `SwitchedPoly`, `SwitchedSeededRlweCiphertext`, `SwitchedSeededRgswCiphertext`
  - `SwitchedClientQuery` type for maximum compression
  - `query_switched()` function combining seeding + modulus switching
  - **Note**: With default parameters, modulus switching on RGSW queries exceeds noise budget
    due to error amplification in external product. Use `query_seeded()` for production.
- Seed expansion for ~50% query size reduction
  - `SeededRlweCiphertext`, `SeededRgswCiphertext` types
  - `SeededClientQuery` for network transmission
  - `query_seeded()` function for generating compact queries
  - `Poly::from_seed()` for deterministic polynomial generation
  - Query size reduced from 192 KB to 98 KB (50% reduction)
- Benchmark example: `cargo run --example benchmark_seed_expansion`
- Implementation comparison report: docs/IMPLEMENTATION_COMPARISON.md

### Changed

- Noise parameter sigma updated from 3.2 to 6.4 to match InsPIRe paper (Issue #13)
- Updated COMMUNICATION_COSTS.md to clarify O(d) communication (not O(sqrt(N)))
- Updated protocol-visualization.html with new query sizes and "Switched + Seeded" format
- Removed PIR_COMPARISON.md (focus on InsPIRe only)

## [0.1.0] - 2024-12-08

### Added

- Initial InsPIRe PIR implementation based on the paper
- 128-bit security level with optimized parameters
- 32-byte database entry support
- Database sharding for large datasets
- CLI binaries: `inspire-server`, `inspire-client`, `inspire-setup`
- Ethereum database integration example

### Security

- `ServerCrs`/`ClientState` separation to prevent secret key exposure
- `#[serde(skip)]` on secret keys to prevent accidental serialization
