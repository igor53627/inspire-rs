# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Modulus switching for additional ~50% query size reduction (75% total)
  - `modulus_switch` module with `SwitchedPoly`, `SwitchedSeededRlweCiphertext`, `SwitchedSeededRgswCiphertext`
  - `SwitchedClientQuery` type for maximum compression
  - `query_switched()` function combining seeding + modulus switching
  - Query size reduced from 192 KB to 48 KB (75% reduction)
- Seed expansion for ~50% query size reduction
  - `SeededRlweCiphertext`, `SeededRgswCiphertext` types
  - `SeededClientQuery` for network transmission
  - `query_seeded()` function for generating compact queries
  - `Poly::from_seed()` for deterministic polynomial generation
- Benchmark example: `cargo run --example benchmark_seed_expansion`
- Implementation comparison report: docs/IMPLEMENTATION_COMPARISON.md

### Changed

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
