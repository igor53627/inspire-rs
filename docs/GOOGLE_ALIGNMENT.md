# Google InsPIRe Alignment Notes

This document summarizes how inspire-rs parameters map to the Google
InsPIRe reference implementation and highlights known incompatibilities.
It is intended as a practical guide for cross-checking experiments.

## Parameter Mapping (High-Level)

| Concept | Google InsPIRe (research/InsPIRe) | inspire-rs |
|--------|----------------------------------|-----------|
| Ring dimension | `d` | `ring_dim` |
| Ciphertext modulus | CRT moduli list | single modulus `q` |
| Plaintext modulus | `p` | `p` |
| Gadget base | `B` | `gadget_base` |
| Gadget length | `l_gsw` | `gadget_len` |
| Switched modulus | `q'` | `DEFAULT_SWITCHED_Q` (or custom) |

## Key Differences / Incompatibilities

1. **CRT vs single modulus**
   - Google uses multiple CRT moduli for NTT and switching; inspire-rs uses a
     single 64-bit modulus. This changes noise behavior and available q'.

2. **Switched query safety**
   - In inspire-rs, switched queries must satisfy a noise bound:
     `base * len <= q' / (2 * p * safety_factor)`.
   - `query_switched()` auto-selects a smaller gadget base (larger `len`) to
     meet this bound. If a switched query is constructed with the CRS gadget
     (`gadget_len=3`), correctness is not guaranteed at `q' = 2^30`.

3. **Size expectations**
   - With the safe gadget selection, switched query sizes are typically
     ~95–115 KB (for `d=2048`), which may be larger than seeded queries.

4. **Multi-layer / gamma parameters**
   - Google’s full implementation supports multi-layer PIR (DoublePIR, InsPIRe
     variants with multiple gamma parameters). inspire-rs currently targets a
     single-layer database representation.

## Practical Guidance

- **Use `query_switched()`** when testing switched queries. Manual modulus
  switching with the CRS gadget base will likely exceed the noise budget.
- If you need a smaller switched query size, increase `q'` (requires custom
  serialization) or accept a larger gadget length.

