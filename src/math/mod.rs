//! Mathematical primitives for InsPIRe PIR.
//!
//! This module provides the core mathematical operations required for
//! lattice-based cryptography in the InsPIRe protocol:
//!
//! - **Modular arithmetic** over Z_q using Montgomery reduction
//! - **Number-Theoretic Transform (NTT)** for fast polynomial multiplication
//! - **Polynomial operations** over R_q = Z_q[X]/(X^d + 1)
//! - **Discrete Gaussian sampling** for error term generation
//!
//! # Overview
//!
//! The InsPIRe protocol operates over the polynomial ring R_q = Z_q[X]/(X^d + 1),
//! where d is typically 2048 or 4096 and q is an NTT-friendly prime (~2^60).
//! All cryptographic operations (encryption, key switching, homomorphic operations)
//! are built on these mathematical primitives.
//!
//! # Example
//!
//! ```
//! use inspire_pir::math::{Poly, NttContext};
//!
//! // Create a polynomial and convert to NTT domain
//! let ctx = NttContext::with_default_q(256);
//! let mut poly = Poly::random(256, ctx.modulus());
//! poly.to_ntt(&ctx);
//! ```

pub mod gaussian;
pub mod crt;
pub mod mod_q;
pub mod modular;
pub mod ntt;
pub mod poly;
pub mod sampler;
pub mod sampling;

pub use gaussian::GaussianSampler;
pub use crt::{crt_compose_2, crt_decompose_2, crt_modulus, mod_inverse};
pub use mod_q::DEFAULT_Q;
pub use modular::ModQ;
pub use ntt::NttContext;
pub use poly::Poly;
