# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
