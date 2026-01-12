//! Key-switching module
//!
//! This module implements key-switching for RLWE ciphertexts, which transforms
//! a ciphertext valid under secret key s to one valid under secret key s'.
//!
//! # Overview
//!
//! Key-switching is essential for:
//! - The InsPIRe packing algorithm (LWE → RLWE)
//! - Automorphism operations on RLWE ciphertexts
//! - Bootstrapping procedures
//!
//! # Key-Switching Matrix
//!
//! A key-switching matrix K from s to s' consists of ℓ RLWE ciphertexts:
//! ```text
//! K = [RLWE_{s'}(s·z^0), RLWE_{s'}(s·z^1), ..., RLWE_{s'}(s·z^(ℓ-1))]
//! ```
//!
//! # Algorithm
//!
//! To switch (a, b) from key s to key s':
//! 1. Decompose a using gadget: g⁻¹(a) = [a₀, a₁, ..., a_{ℓ-1}]
//! 2. Compute: (a', b') = (0, b) + Σᵢ aᵢ · K[i]
//!
//! # Example
//!
//! ```ignore
//! use inspire::ks::{KeySwitchingMatrix, generate_ks_matrix, key_switch};
//! use inspire::rgsw::GadgetVector;
//!
//! let gadget = GadgetVector::new(1 << 20, 3, q);
//! let ks_matrix = generate_ks_matrix(&from_key, &to_key, &gadget, &mut sampler, &ctx);
//! let switched_ct = key_switch(&ct, &ks_matrix, &ctx);
//! ```

mod setup;
mod switch;

pub use setup::{
    generate_automorphism_ks_matrix, generate_ks_matrix, generate_packing_ks_matrix,
    KeySwitchingMatrix,
};
pub use switch::key_switch;
