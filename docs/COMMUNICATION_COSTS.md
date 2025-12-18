# InsPIRe Communication Cost Analysis

## Overview

This document analyzes the communication costs of InsPIRe PIR for Ethereum state queries.

**Important**: InsPIRe communication is **O(d)** where d is the ring dimension, not O(√N). The costs below are essentially independent of database size.

## Measured Communication (d=2048)

Benchmarked with 128-bit security parameters:

| Component | Full (Binary) | Seeded (Binary) | Seeded (JSON) |
|-----------|---------------|-----------------|---------------|
| Query (client→server) | 192 KB | **96 KB** | 230 KB |
| Response (server→client) | 544 KB | 544 KB | 1,296 KB |
| **Total per-query** | **736 KB** | **640 KB** | **1,526 KB** |

Optimizations:
- **Seed expansion**: 50% query reduction (seeds replace `a` polynomials)
- **Binary (bincode)**: ~60% reduction vs JSON (no text overhead)

Note: Modulus switching would reduce query to 48 KB, but exceeds noise budget with current parameters. See [Modulus Switching Tradeoffs](#modulus-switching-tradeoffs).

## CRS (Common Reference String) Overhead

The CRS is shared once and reused across queries:

| Component | Size (d=2048) | Purpose |
|-----------|---------------|---------|
| Key-switching matrices (K_g, K_h) | 60-84 KB | Ring packing |
| RGSW gadget encryptions | ~10-20 KB | Polynomial evaluation |
| Galois keys | ~10-20 KB | Automorphisms τ_g |
| **Total CRS** | **~100-130 KB** | |

## Why PIR Sizes Are Constant

A common question: why do different database sizes produce identical query and response sizes?

**This is a fundamental privacy requirement.** If sizes varied with the target index or database, an observer could infer what's being queried just from traffic analysis.

### Query Size Formula

The query is an RGSW ciphertext encrypting `X^(-k)` (the inverse monomial for target index k):

```
Query Size = 2ℓ × 2 × d × 8 bytes

Where:
  ℓ = gadget length (3)
  d = ring dimension (2048)
  8 = bytes per coefficient (64-bit integers)

Calculation: 2 × 3 × 2 × 2048 × 8 = 196,608 bytes ≈ 192 KB
With JSON overhead: ~458 KB
With seed expansion: ~230 KB (seeds replace half the polynomials)
```

**What affects query size:**
| Factor | Effect |
|--------|--------|
| Ring dimension (d) | Linear scaling |
| Gadget length (ℓ) | Linear scaling |
| Coefficient size | Linear scaling |

**What does NOT affect query size:**
| Factor | Why Not |
|--------|---------|
| Database size | Index k only changes polynomial coefficients, not structure |
| Target index | Same RGSW structure regardless of which entry |
| Number of shards | Shard ID is metadata, not ciphertext size |

### Response Size Formula

The response contains RLWE ciphertexts for each column of the entry:

```
Response Size = num_ciphertexts × 2 × d × 8 bytes

Where:
  num_ciphertexts = ceil(entry_bits / log₂(p)) + 1
                  = ceil(256 / 16) + 1 = 17  (for 32-byte entries)
  d = ring dimension (2048)
  8 = bytes per coefficient

Calculation: 17 × 2 × 2048 × 8 = 557,056 bytes ≈ 544 KB (binary)
With JSON overhead: ~1,296 KB
```

**What affects response size:**
| Factor | Effect |
|--------|--------|
| Entry size | More columns → more ciphertexts |
| Ring dimension (d) | Linear scaling |
| Plaintext modulus (p) | Higher p → fewer columns needed |

**What does NOT affect response size:**
| Factor | Why Not |
|--------|---------|
| Database size | Same entry format regardless of DB size |
| Which entry retrieved | Ciphertext structure is identical |
| Number of entries | Server processes one shard, returns same format |

### Database Size Effect

| Database Size | Shards | Query Size (seeded) | Response Size | Server Time |
|---------------|--------|---------------------|---------------|-------------|
| 1K entries | 1 | 96 KB | 544 KB | ~1 ms |
| 64K entries | 32 | 96 KB | 544 KB | ~1.5 ms |
| 1M entries | 512 | 96 KB | 544 KB | ~3 ms |
| 100M entries | 50K | 96 KB | 544 KB | ~3 ms |

**The only thing that changes is server computation time** (selecting and processing the correct shard).

### Visual Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHY PIR SIZES ARE CONSTANT                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  QUERY (~230 KB)                                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  RGSW(X^(-k))                                           │   │
│  │  ├── 6 RLWE rows (2ℓ where ℓ=3)                        │   │
│  │  │   └── Each row: 2 polynomials × 2048 coeffs × 8B    │   │
│  │  └── Structure fixed by (d, ℓ), not by k or DB size    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  RESPONSE (~544 KB)                                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  17 × RLWE ciphertexts (for 32-byte entry)              │   │
│  │  ├── 1 combined + 16 column ciphertexts                 │   │
│  │  │   └── Each: 2 polynomials × 2048 coeffs × 8B = 32KB │   │
│  │  └── Structure fixed by (d, entry_size), not DB size   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  DATABASE SIZE only affects:                                    │
│  ├── Number of shards (more entries = more shards)             │
│  ├── Server computation (which shard to process)               │
│  └── NOT bandwidth (privacy would leak otherwise!)              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Measured Performance

Benchmarked on AMD/Intel x64 server:

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

## Modulus Switching Tradeoffs

Modulus switching reduces coefficient size from 8 bytes to 4 bytes by rescaling from q to q':

```
c' = round(c × q' / q)
```

### The Problem: Noise Amplification in External Product

For RGSW queries used in external product, the rounding error is amplified:

```
added_error ≈ ℓ × B × (q / q')

Where:
  ℓ = gadget digits (3)
  B = gadget base (2^20)
  q / q' = modulus ratio (2^30 for q=2^60, q'=2^30)

Current: 3 × 2^20 × 2^30 = 3×2^50 ≈ 3.4×10^15
Allowed: q / (2p) = 2^60 / 2^17 = 2^43 ≈ 8.8×10^12

Result: Error exceeds threshold by ~128×, causing decryption failures.
```

### Can We Fix It?

To make q'=2^30 work, we need: `ℓ × B < 2^13 ≈ 8192`

| Gadget Base (B) | Digits (ℓ) | B^ℓ ≥ q? | ℓ × B | Works? |
|-----------------|------------|----------|-------|--------|
| 2^20 (current)  | 3          | ✓        | 3×2^20 | ✗ |
| 2^10            | 6          | ✓        | 6144   | ✓ |
| 2^8             | 8          | ✓        | 2048   | ✓ |

### The Tradeoff: It's a Wash

RGSW ciphertext has **2ℓ rows**. Changing parameters:

| Config | Rows | Seeded Size | + Modulus Switch | Net Size |
|--------|------|-------------|------------------|----------|
| ℓ=3, B=2^20 (current) | 6 | 98 KB | ✗ (broken) | 98 KB |
| ℓ=6, B=2^10 | 12 | 196 KB | ✓ (50% off) | 98 KB |
| ℓ=8, B=2^8 | 16 | 261 KB | ✓ (50% off) | 130 KB |

**Conclusion**: Doubling ℓ to enable modulus switching results in the same or worse final size. Seeded-only compression (98 KB) is the practical optimum for current security parameters.

### When Modulus Switching Does Help

- **RLWE responses** (no external product amplification)
- **Different parameter regimes** (smaller gadget base already chosen for other reasons)
- **Lower security levels** (smaller q allows smaller q' ratio)

## Why Generic Compression Won't Help

LWE/RLWE ciphertexts are cryptographically pseudorandom (indistinguishable from uniform random by design):

| Data Type | Entropy | Compression |
|-----------|---------|-------------|
| Random bytes | ~8 bits/byte | ~0% reduction |
| CRS (key material) | ~8 bits/byte | ~0-2% reduction |
| Query ciphertexts | ~8 bits/byte | ~0-2% reduction |

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

#### Communication (Measured)

| Scenario | Upload | Download | Total |
|----------|--------|----------|-------|
| 14 queries (standard) | 14 × 458 KB = 6.4 MB | 14 × 1,296 KB = 18.1 MB | **24.5 MB** |
| 14 queries (seeded) | 14 × 230 KB = 3.2 MB | 14 × 1,296 KB = 18.1 MB | **21.3 MB** |

#### Realistic Expectations

- **Per query**: ~1.5 MB (seeded)
- **Wallet open (14 queries)**: ~21 MB total
- **PIR overhead vs raw**: ~40,000× (512 bytes → 21 MB)

## Optimization Strategies

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

| Metric | Binary | JSON |
|--------|--------|------|
| Query size (seeded) | 96 KB | 230 KB |
| Response size | 544 KB | 1,296 KB |
| Per-query total | 640 KB | 1,526 KB |
| Server respond time | ~3-4 ms | ~3-4 ms |
| End-to-end latency | ~12 ms | ~12 ms |
| Wallet open (14 queries) | ~9 MB | ~21 MB |

InsPIRe provides **full query privacy** with ~640 KB per query (binary) and ~12ms latency. The bandwidth overhead is significant but acceptable for privacy-critical applications on modern networks.

## Interactive Visualization

For an interactive visualization of these costs with animated protocol flow, parameter sliders, and size breakdowns, see [protocol-visualization.html](protocol-visualization.html).
