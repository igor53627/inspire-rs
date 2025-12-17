# PIR Scheme Comparison

## Overview

This document compares various Private Information Retrieval (PIR) schemes relevant to Ethereum state queries.

## Scheme Categories

### 1. Server-Stored Client-Specific Keys
| Scheme | Query Size | Response Size | Server Storage | Notes |
|--------|------------|---------------|----------------|-------|
| XPIR | Large | Large | Per-client keys | High computation |
| OnionPIR | Medium | Medium | Per-client keys | |
| Spiral | Small | Small | Per-client keys | Good for few queries |
| Respire | Very small | Very small | Per-client keys | Best communication |

**Drawback**: Server must store MB-scale keys per client; doesn't scale to large user bases.

### 2. Client-Stored Database Hints
| Scheme | Query Size | Hint Size | Throughput | Notes |
|--------|------------|-----------|------------|-------|
| SimplePIR | ~1 KB | ~1 GB | 10+ GB/s | Highest throughput |
| DoublePIR | ~1 KB | ~100 MB | 5+ GB/s | |
| FrodoPIR | ~1 KB | ~100 MB | Good | |
| Piano | ~1 KB | Stream DB | Good | Streams entire DB |
| Plinko | ~1 KB | ~200 MB | Good | iPRF-based, updatable |
| **Dummy Subsets** | 34-47 KB | ~30 MB | Very fast | 2-server or 1-server variants |

**Drawback**: Client must download/store large hints; hints need updating with DB changes.

### 3. No Offline Communication (CRS Model)
| Scheme | Query Size | Response Size | Throughput | Communication Complexity |
|--------|------------|---------------|------------|-------------------------|
| HintlessPIR | 2.2 MB | Included | 1.37 GB/s | O(√N) |
| YPIR | 858 KB | Included | 7.4 GB/s | O(√N) |
| **InsPIRe** | 236-504 KB | Included | 1.5-8.7 GB/s | O(√N) |
| **VIA** (2025) | 690 KB | Included | 3.1 GB/s | **O(log N)** |

**Best for**: Single queries, cold start, user anonymity, large user bases.

## Detailed Comparisons

### InsPIRe vs YPIR vs HintlessPIR

For 1 GB database with 64-byte entries:

| Metric | InsPIRe | YPIR | HintlessPIR |
|--------|---------|------|-------------|
| Total communication | 172-347 KB | 802 KB | 2,236 KB |
| Server time | 320-1100 ms | 600 ms | 750 ms |
| Throughput | 0.9-3.2 GB/s | 1.7 GB/s | 1.4 GB/s |
| Key material | 84 KB | 420 KB | 360 KB |
| Offline preprocessing | Yes | Yes | Yes |

**InsPIRe advantages**:
- 50% less communication than YPIR
- 5× smaller keys than YPIR
- 67-90% less communication than HintlessPIR

### VIA Protocol (2025 - State of the Art)

| Database Size | VIA Communication | YPIR Communication | Improvement |
|---------------|-------------------|-------------------|-------------|
| 1 GB | ~400 KB | 802 KB | 2× |
| 4 GB | ~500 KB | 1.2 MB | 2.4× |
| 32 GB | 690 KB | 2.5 MB | 3.7× |

**VIA key features**:
- O(log N) communication complexity (vs O(√N) for InsPIRe/YPIR)
- Single server, no offline communication
- DMux-CMux framework + LWE-to-RLWE conversion
- Throughput: 3.11 GB/s for 32 GB database

### VIA-C (With Offline Communication)

| Metric | VIA-C | Respire | SimplePIR |
|--------|-------|---------|-----------|
| Query size | 0.66 KB | 58 KB | ~1 KB |
| Response size | 1.4 KB | 2.0 KB | ~1 KB |
| Offline comm | 14.8 MB | 14.8 MB | ~1 GB |
| Throughput | 1.4 GB/s | 0.6 GB/s | 10+ GB/s |

**VIA-C**: 28.5× less online communication than Respire.

## TreePIR Variants

### TreePIR for Merkle Proofs (2022)

Specialized for tree-shaped databases (Merkle trees):

| Metric | TreePIR | Probabilistic Batch Codes |
|--------|---------|---------------------------|
| Storage overhead | **0%** | 3× |
| Communication | 1.5-2× better | Baseline |
| Computation | 1.5-2× better | Baseline |
| Setup time | 8-160× faster | Baseline |
| Indexing | O(polylog) | O(N) |

**Best for**: Certificate transparency, blockchain Merkle proofs, DynamoDB.

### TreePIR from DDH (CRYPTO 2023)

General-purpose PIR with polylogarithmic communication:

| Metric | TreePIR (DDH) | Lattice-based PIR |
|--------|---------------|-------------------|
| Servers required | **2** | 1 |
| Communication | **O(polylog N)** | O(√N) or O(log N) |
| Assumption | DDH | RLWE/LWE |
| Amortized time | Sublinear | Linear |

**Trade-off**: Requires two non-colluding servers.

### Dummy Subsets (CCS 2024)

Stateful PIR using dummy subsets to eliminate leakage. Available in 2-server and 1-server variants.

**Key idea**: Client stores partition-based hints; queries include dummy indices to hide the real target.

| Database | Variant | Client Storage | Offline Comm | Online Comm | Online Compute |
|----------|---------|----------------|--------------|-------------|----------------|
| 32 MB (2^20 × 32B) | 2-server | 3.8 MB | 3.8 MB | 2.3 KB | 0.12 ms |
| 512 MB (2^24 × 32B) | 2-server | 15 MB | 15 MB | 8.6 KB | 0.54 ms |
| 8 GB (2^28 × 32B) | 2-server | 60 MB | 60 MB | 34 KB | 2.7 ms |
| 8 GB (2^28 × 32B) | 1-server | 60 MB | Stream DB | 47 KB (amort.) | 4.5 ms |

**Comparison with other stateful schemes (8 GB database)**:

| Scheme | Online Comm | Online Compute | Client Storage | Servers |
|--------|-------------|----------------|----------------|---------|
| **Dummy Subsets** | 34 KB | 2.7 ms | 60 MB | 2 |
| **Dummy Subsets** | 47 KB | 4.5 ms | 60 MB | 1 |
| TreePIR | 263 KB | 20 ms | 12 MB | 2 |
| Checklist | 0.6 KB | 1.9 ms | 1.1 GB | 2 |
| Spiral (stateless) | 30 KB | 30,000+ ms | Per-client | 1 |
| SimplePIR | ~1 KB | ~750 ms | ~1 GB hint | 1 |
| Piano | 50 KB | 14 ms | 60 MB | 1 |

**Advantages**:
- 7.7× less communication than TreePIR
- 18× faster computation than TreePIR
- 18× less client storage than Checklist
- 100-1000× faster than Spiral for large databases
- 9-14× less communication than SimplePIR online
- Standard PIR correctness (unlike Piano's probabilistic guarantee)

**Drawbacks**:
- Single-server variant requires streaming entire DB in offline phase
- Higher online communication than schemes with larger hints (Checklist, SimplePIR)
- O(√N) communication complexity (not polylog)

## Compression and Optimization Techniques

### Query Compression

| Technique | Compression | Notes |
|-----------|-------------|-------|
| CRS model | ~2× | Random components shared |
| Seed expansion | ~10× | Send 32-byte seed |
| Modulus switching | ~1.5× | Smaller q for transmission |

### Batching

| Technique | Per-Query Cost | Notes |
|-----------|----------------|-------|
| No batching | 350 KB | Baseline |
| Shared CRS | 250 KB | CRS amortized |
| Packed (same shard) | **0.4 KB** | Up to d/2 queries per ciphertext |

### Why Compression (Brotli/gzip) Doesn't Help

Cryptographic ciphertexts are pseudorandom by design:

| Data Type | Entropy | Compression |
|-----------|---------|-------------|
| LWE/RLWE ciphertexts | ~8 bits/byte | 0-2% |
| Key-switching matrices | ~8 bits/byte | 0-2% |
| Random bytes | ~8 bits/byte | 0% |

## Ethereum State: Scheme Selection Guide

| Use Case | Best Scheme | Communication | Notes |
|----------|-------------|---------------|-------|
| Single query, cold start | InsPIRe / VIA | 300-700 KB | No setup needed |
| Many queries, same client | Plinko | ~1 KB/query | After 200 MB hint download |
| Many queries, fast compute | Dummy Subsets | 34-47 KB/query | After ~60 MB hint, 2.7-4.5 ms/query |
| Merkle proof retrieval | TreePIR (Merkle) | O(log N) | Optimized for tree structure |
| Maximum privacy | TreePIR (DDH) | O(polylog N) | Requires 2 servers |
| Highest throughput | SimplePIR | ~1 KB | Requires ~1 GB hint |
| 2-server trusted setup | Dummy Subsets | 34 KB/query | Lowest computation if 2 servers OK |

## Wallet Open Scenario

User opens wallet with 10 tokens, 3 NFTs, ETH balance (14 queries, 512 bytes actual data):

| Scheme | Total Transfer | Per-Query | Privacy |
|--------|----------------|-----------|---------|
| Direct RPC | 2 KB | 0.14 KB | None |
| InsPIRe (batched) | 2-4 MB | 140-280 KB | Full |
| VIA (batched) | 1-2 MB | 70-140 KB | Full |
| Plinko (after hint) | 14 KB | 1 KB | Full |
| Dummy Subsets (after hint) | 480-660 KB | 34-47 KB | Full |

## Summary Table

| Scheme | Servers | Offline Comm | Online Comm | Throughput | Assumption |
|--------|---------|--------------|-------------|------------|------------|
| SimplePIR | 1 | ~1 GB hint | ~1 KB | 10+ GB/s | LWE |
| Plinko | 1 | ~200 MB hint | ~1 KB | Good | PRF |
| HintlessPIR | 1 | None | 2.2 MB | 1.4 GB/s | RLWE |
| YPIR | 1 | None | 858 KB | 7.4 GB/s | RLWE |
| **InsPIRe** | 1 | None | 236-504 KB | 1.5-8.7 GB/s | RLWE |
| **VIA** | 1 | None | 690 KB (32GB) | 3.1 GB/s | LWE/RLWE |
| TreePIR (DDH) | 2 | Sublinear | O(polylog N) | Sublinear | DDH |
| Spiral | 1 | Per-client keys | Small | Good | RLWE |
| **Dummy Subsets** | 1-2 | ~30-60 MB hint | 34-47 KB | Very fast | DPF/PRF |

## References

- InsPIRe: [docs/inspire_paper.json](inspire_paper.json)
- VIA: [ePrint 2025/2074](https://eprint.iacr.org/2025/2074)
- TreePIR (Merkle): [arXiv:2205.05211](https://arxiv.org/abs/2205.05211)
- TreePIR (DDH): [CRYPTO 2023](https://eprint.iacr.org/2023/204)
- YPIR: [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/menon)
- Plinko: [ePrint 2024/318](https://eprint.iacr.org/2024/318)
- Dummy Subsets: [ePrint 2023/1072](https://eprint.iacr.org/2023/1072) (CCS 2024)
