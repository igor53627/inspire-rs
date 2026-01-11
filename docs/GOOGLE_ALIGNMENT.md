# Google InsPIRe Alignment Notes

This document summarizes how inspire-rs aligns with the Google InsPIRe
reference implementation (research/InsPIRe) and highlights known
incompatibilities. It is intended as a practical guide for cross-checking
experiments and scoping alignment work.

## Parameter Mapping (High-Level)

| Concept | Google InsPIRe (research/InsPIRe) | inspire-rs |
|--------|----------------------------------|-----------|
| Ring dimension | `d` / `poly_len` | `ring_dim` |
| Ciphertext modulus | CRT moduli list | single modulus `q` |
| Plaintext modulus | `p` | `p` |
| Gadget base | `B` | `gadget_base` |
| Gadget length | `l_gsw` | `gadget_len` |
| Switched modulus | `q'` | `DEFAULT_SWITCHED_Q` (or custom) |

## What we can align

- **Ring dimension**: both default to 2048.
- **Noise width (sigma)**: both default to ~6.4.
- **High-level protocol shape**: seeded queries, optional modulus switching,
  InspiRING packing for InsPIRe^2.
- **Evaluation methodology**: compare sizes/latency using similar workloads.

## What is not directly comparable

- **Modulus structure**:
  - Google (Spiral): CRT moduli `[268369921, 249561089]` (~2×28-bit primes).
  - inspire-rs: single NTT-friendly prime `q = 2^60 - 2^14 + 1`.
- **Param selection pipeline**:
  - Google derives params via Spiral-specific routines with `q2_bits = 28`,
    `t_exp_left = 3`, and `p = 2^15` or `2^16`.
  - inspire-rs uses fixed “secure_128” parameters (ring_dim=2048, p=65537).
- **Switched-query noise model**:
  - inspire-rs must choose a smaller gadget base (larger `l`) to keep
    modulus-switching noise within bounds.
  - Using CRS gadget (l=3, base 2^20) for switched queries is invalid.

## Current inspire-rs defaults (reference)

- ring_dim: 2048
- q: 2^60 - 2^14 + 1
- p: 65537
- sigma: 6.4
- gadget_base: 2^20
- gadget_len: 3
- switched_q: 2^30 (auto-selects smaller gadget base for correctness)

## Google InsPIRe defaults (reference)

From `research/InsPIRe/src/params.rs`:

- poly_len: 2048
- moduli: [268369921, 249561089]
- noise_width: 6.4
- q2_bits: 28
- t_exp_left: 3
- p: 2^15 or 2^16 (depends on scenario)

## Alignment gaps to track

1. **Document parameter mapping** between Spiral/CRT and single-modulus NTT.
2. **Switched correctness guard**: reject unsafe gadget params server-side.
3. **Evaluation parity**: match workloads + report comparable metrics.
4. **Clarify variants**: InsPIRe^2 vs InsPIRe^2+ terminology across repos.

## Practical Guidance

- Use `query_switched()` when testing switched queries. Manual modulus
  switching with the CRS gadget base will likely exceed the noise budget.
- If you need a smaller switched query size, increase `q'` (requires custom
  serialization) or accept a larger gadget length.
