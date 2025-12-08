//! Math primitives for InsPIRe PIR
//!
//! This module provides the core mathematical operations:
//! - Modular arithmetic over Z_q
//! - Number-Theoretic Transform (NTT) for fast polynomial multiplication
//! - Polynomial operations over R_q = Z_q[X]/(X^d + 1)
//! - Discrete Gaussian sampling

pub mod mod_q;
pub mod modular;
pub mod ntt;
pub mod poly;
pub mod gaussian;
pub mod sampler;
pub mod sampling;

pub use mod_q::DEFAULT_Q;
pub use modular::ModQ;
pub use ntt::NttContext;
pub use poly::Poly;
pub use gaussian::GaussianSampler;
