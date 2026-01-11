//! CRT (Chinese Remainder Theorem) helpers.
//!
//! Ported and adapted from Google InsPIRe reference code
//! (private-membership/research/InsPIRe, commit 89f04516c4b8b48b8e65e50d25b37256e04096ad)
//! under the Apache-2.0 license.

/// Compute a modular inverse using extended Euclidean algorithm.
///
/// Returns `x` such that `(a * x) % modulus == 1`.
pub fn mod_inverse(a: u64, modulus: u64) -> u64 {
    let mut t: i128 = 0;
    let mut new_t: i128 = 1;
    let mut r: i128 = modulus as i128;
    let mut new_r: i128 = a as i128;

    while new_r != 0 {
        let quotient = r / new_r;
        let tmp_t = t - quotient * new_t;
        t = new_t;
        new_t = tmp_t;

        let tmp_r = r - quotient * new_r;
        r = new_r;
        new_r = tmp_r;
    }

    if r != 1 {
        panic!("mod_inverse: value is not invertible");
    }

    if t < 0 {
        t += modulus as i128;
    }
    t as u64
}

/// Compose two CRT residues into a value modulo q0 * q1.
///
/// Formula:
///   x = a0 + q0 * ((a1 - a0) * q0^{-1} mod q1)
pub fn crt_compose_2(a0: u64, a1: u64, q0: u64, q1: u64, q0_inv_mod_q1: u64) -> u64 {
    let a0_mod_q1 = a0 % q1;
    let diff = if a1 >= a0_mod_q1 {
        a1 - a0_mod_q1
    } else {
        (a1 + q1) - a0_mod_q1
    };
    let t = ((diff as u128 * q0_inv_mod_q1 as u128) % q1 as u128) as u64;
    a0 + q0 * t
}

/// Split a value into two CRT residues.
#[inline]
pub fn crt_decompose_2(value: u64, q0: u64, q1: u64) -> (u64, u64) {
    (value % q0, value % q1)
}

/// Compute the product of moduli (composite modulus).
pub fn crt_modulus(moduli: &[u64]) -> u64 {
    moduli
        .iter()
        .copied()
        .fold(1u64, |acc, m| acc.saturating_mul(m))
}
