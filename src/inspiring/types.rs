//! Intermediate types for the InspiRING packing algorithm.
//!
//! Provides intermediate representations used during the LWE-to-RLWE
//! packing process.

use crate::math::Poly;
use serde::{Deserialize, Serialize};

/// Intermediate ciphertext representation during packing.
///
/// Holds a vector of polynomials (â) and a single polynomial (b̃) during
/// the InspiRING transform and collapse stages.
///
/// # Fields
///
/// * `a_polys` - Vector of polynomials â ∈ R_q^k
/// * `b_poly` - Single polynomial b̃ ∈ R_q
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediateCiphertext {
    /// Vector of polynomials â ∈ R_q^k.
    pub a_polys: Vec<Poly>,
    /// Single polynomial b̃ ∈ R_q.
    pub b_poly: Poly,
}

impl IntermediateCiphertext {
    /// Create a new intermediate ciphertext
    pub fn new(a_polys: Vec<Poly>, b_poly: Poly) -> Self {
        Self { a_polys, b_poly }
    }

    /// Get the dimension (number of a polynomials)
    pub fn dimension(&self) -> usize {
        self.a_polys.len()
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.b_poly.dimension()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.b_poly.modulus()
    }
}

/// Aggregated ciphertext: result of combining multiple intermediate ciphertexts
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedCiphertext {
    /// Vector of polynomials â_agg ∈ R_q^k
    pub a_polys: Vec<Poly>,
    /// Single polynomial b̃_agg ∈ R_q
    pub b_poly: Poly,
}

impl AggregatedCiphertext {
    /// Create a new aggregated ciphertext
    pub fn new(a_polys: Vec<Poly>, b_poly: Poly) -> Self {
        Self { a_polys, b_poly }
    }

    /// Get the dimension (number of a polynomials)
    pub fn dimension(&self) -> usize {
        self.a_polys.len()
    }

    /// Get the ring dimension
    pub fn ring_dim(&self) -> usize {
        self.b_poly.dimension()
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.b_poly.modulus()
    }

    /// Convert to intermediate ciphertext (for collapse operations)
    pub fn to_intermediate(&self) -> IntermediateCiphertext {
        IntermediateCiphertext {
            a_polys: self.a_polys.clone(),
            b_poly: self.b_poly.clone(),
        }
    }
}
