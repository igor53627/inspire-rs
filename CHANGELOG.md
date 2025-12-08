# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
