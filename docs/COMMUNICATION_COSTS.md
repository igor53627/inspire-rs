# InsPIRe Communication Cost Analysis

## Overview

This document analyzes the communication costs of InsPIRe PIR for Ethereum state queries, including compression opportunities and batching strategies.

## CRS (Common Reference String) Overhead

The CRS is shared once and reused across queries:

| Component | Size (d=2048) | Purpose |
|-----------|---------------|---------|
| Key-switching matrices (K_g, K_h) | 60-84 KB | Ring packing |
| RGSW gadget encryptions | ~10-20 KB | Polynomial evaluation |
| Galois keys | ~10-20 KB | Automorphisms τ_g |
| **Total CRS** | **~100-130 KB** | |

Comparison with other schemes:
- InspiRING (d=2048): 84 KB
- CDKS: 462 KB (5.5× larger)
- HintlessPIR: 360 KB (4.3× larger)

## Per-Query Communication

With CRS already shared:

| Part | Size | Notes |
|------|------|-------|
| Query (client→server) | ~200-300 KB | RLWE `b` values |
| Response (server→client) | ~100-200 KB | Packed RLWE ciphertext(s) |
| **Total per-query** | **~300-500 KB** | |

Comparison:
- InsPIRe: 300-500 KB
- YPIR: 858 KB
- HintlessPIR: 2.2 MB

## Compression Analysis

### Why Brotli/gzip Won't Help

LWE/RLWE ciphertexts are cryptographically pseudorandom (indistinguishable from uniform random by design):

| Data Type | Entropy | Compression |
|-----------|---------|-------------|
| Random bytes | ~8 bits/byte | ~0% reduction |
| CRS (key material) | ~8 bits/byte | ~0-2% reduction |
| Query ciphertexts | ~8 bits/byte | ~0-2% reduction |

### Alternatives for Smaller Communication

1. **Seed expansion**: Send 32-byte seed, server regenerates randomness
2. **Smaller ring dimension**: d=1024 → 60 KB keys (vs 84 KB for d=2048)
3. **Modulus switching**: Use smaller q for transmitted ciphertexts
4. **Hybrid approach**: First query uses full CRS, subsequent queries only send delta

## Hybrid Approach: Multi-Request Costs

### Communication Over Multiple Requests

| Requests | Naive (full each time) | Hybrid (CRS once) | Savings |
|----------|------------------------|-------------------|---------|
| 1 | 500 KB | 500 KB | 0% |
| 5 | 2.5 MB | 1.9 MB | 24% |
| 10 | 5.0 MB | 3.6 MB | 28% |
| 20 | 10.0 MB | 7.1 MB | 29% |

### With Seed Compression (Aggressive)

| Requests | Hybrid + Seed | Per-query |
|----------|---------------|-----------|
| 1 | ~300 KB | 300 KB |
| 10 | ~1.5 MB | ~150 KB |
| 20 | ~2.8 MB | ~140 KB |

At 20+ requests: **~140 KB/query** steady-state.

## Batched Queries

### Simple Batching (Shared CRS)

| Queries | Separate | Batched |
|---------|----------|---------|
| 10 | 3.5 MB | 2.6 MB |
| 20 | 7.0 MB | 5.1 MB |

### Packed Batching (Same RLWE Ciphertext)

When querying indices in the same shard, multiple queries pack into one RLWE ciphertext:

| Batch Size | Communication | Per-Query Cost |
|------------|---------------|----------------|
| 1 | ~350 KB | 350 KB |
| d/2 = 1024 | ~400 KB | **~0.4 KB** |

Ring dimension d=2048 allows up to ~1000 queries per ciphertext (same shard).

### Batching Trade-offs

| Approach | Latency | Throughput | Use Case |
|----------|---------|------------|----------|
| Individual | Low | Low | Interactive |
| Batched | Higher | Much higher | Background sync, prefetch |

## Real-World Example: Wallet Open

### Scenario: User opens wallet with 10 tokens, 3 NFTs, ETH balance

#### Data Requirements

| Asset Type | Count | Query Type | DB Lookups |
|------------|-------|------------|------------|
| ETH balance | 1 | Account | 1 (returns 96B) |
| ERC-20 tokens | 10 | Storage | 10 (each 32B) |
| NFTs (ERC-721) | 3 | Storage | 3 (each 32B) |
| **Total** | | | **14 queries** |

Actual payload needed: 96 + 13×32 = **512 bytes**

#### Communication Estimates

| Scenario | Upload | Download | Total |
|----------|--------|----------|-------|
| Naive (no batching) | 14 × 250 KB | 14 × 150 KB | **5.6 MB** |
| Shared CRS | 100 KB + 14 × 200 KB | 14 × 150 KB | **5.0 MB** |
| Shard batching (~10 shards) | 100 KB + 10 × 200 KB | 10 × 150 KB | **3.6 MB** |
| Packed batching (optimistic) | 100 KB + 5 × 250 KB | 5 × 150 KB | **2.1 MB** |

#### Realistic Expectations

- **First wallet open**: ~3-4 MB total
- **Subsequent refreshes** (CRS cached): ~2.5-3.5 MB
- **PIR overhead**: ~5000-7000× vs raw data (512 bytes)

### Comparison to Alternatives

| Method | Data Transferred | Privacy | Client Storage |
|--------|------------------|---------|----------------|
| Direct RPC | ~2 KB | None | None |
| InsPIRe PIR | ~3-4 MB | Full | ~100 KB (CRS) |
| Plinko (hints) | ~200 MB upfront, then ~1 KB/query | Full | ~200 MB |

## Optimization Strategies for Ethereum Wallets

### 1. Prefetch Common Data
- Cache CRS on app install (~100 KB)
- Background-fetch token balances during idle time

### 2. Batch by Access Pattern
- Queue all lookups before sending
- Group by shard when possible

### 3. Incremental Updates
- Subscribe to block updates
- Only re-query changed state (via state diffs)

### 4. Hybrid Privacy Tiers
- Use PIR for sensitive queries (balances, specific NFTs)
- Use public RPC for non-sensitive metadata (token names, decimals)

## Summary

| Metric | Value |
|--------|-------|
| CRS size (one-time) | ~100 KB |
| Per-query (after CRS) | ~250-400 KB |
| Wallet open (14 queries) | ~3-4 MB |
| PIR overhead vs raw | ~5000-7000× |
| Batching benefit | Up to 10× reduction |

InsPIRe provides **full query privacy** at the cost of ~3-4 MB per wallet session, which is acceptable for most mobile/desktop scenarios but may be challenging for very constrained environments.
