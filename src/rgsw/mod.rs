//! RGSW (Ring-GSW) encryption module
//!
//! This module implements RGSW encryption, which enables homomorphic
//! multiplication of RLWE ciphertexts via the external product operation.
//!
//! # Overview
//!
//! RGSW is based on the GSW (Gentry-Sahai-Waters) scheme over polynomial rings.
//! An RGSW ciphertext encrypting message m is a 2ℓ × 2 matrix where:
//! - Each row is an RLWE ciphertext
//! - The gadget vector g = [1, z, z², ..., z^(ℓ-1)]^T allows decomposition
//!
//! # External Product
//!
//! The key operation is RLWE(m₀) ⊡ RGSW(m₁) → RLWE(m₀·m₁), which enables:
//! - Homomorphic multiplication by encrypted constants
//! - Selection operations in PIR queries
//!
//! # Example
//!
//! ```ignore
//! use inspire_pir::rgsw::{RgswCiphertext, GadgetVector, external_product};
//! use inspire_pir::rlwe::RlweCiphertext;
//!
//! let gadget = GadgetVector::new(1 << 20, 3, q);
//! let rgsw_ct = RgswCiphertext::encrypt(...);
//! let result = external_product(&rlwe_ct, &rgsw_ct, &ctx);
//! ```

mod types;
mod external_product;

pub use types::{GadgetVector, RgswCiphertext};
pub use external_product::{external_product, gadget_decompose, gadget_reconstruct};
