//! Galois automorphisms for RLWE
//!
//! Galois automorphisms τ_g: R → R are ring automorphisms defined by
//! τ_g(X) = X^g for g ∈ Z_{2d}^*.
//!
//! For R = Z[X]/(X^d + 1), the Galois group is isomorphic to Z_d/2 × Z_2.

use crate::math::Poly;

use super::types::RlweCiphertext;

/// Apply Galois automorphism τ_g to a polynomial
///
/// τ_g(p(X)) = p(X^g) mod (X^d + 1)
///
/// For X^d + 1, we have X^d = -1, so:
/// - X^i maps to X^(g·i mod 2d) with sign flip if (g·i / d) is odd
///
/// # Arguments
/// * `poly` - Input polynomial
/// * `g` - Galois element (must be odd and coprime to 2d)
pub fn apply_automorphism(poly: &Poly, g: usize) -> Poly {
    let d = poly.dimension();
    let q = poly.modulus();
    let two_d = 2 * d;

    let mut result_coeffs = vec![0u64; d];

    for i in 0..d {
        let coeff = poly.coeff(i);
        if coeff == 0 {
            continue;
        }

        // Compute new index: g·i mod 2d
        let new_idx = (g * i) % two_d;

        // Determine sign and actual index
        let (actual_idx, negate) = if new_idx < d {
            (new_idx, false)
        } else {
            (new_idx - d, true)
        };

        // Add coefficient with appropriate sign
        if negate {
            // Subtract (add negative)
            result_coeffs[actual_idx] = mod_sub(result_coeffs[actual_idx], coeff, q);
        } else {
            result_coeffs[actual_idx] = mod_add(result_coeffs[actual_idx], coeff, q);
        }
    }

    Poly::from_coeffs_moduli(result_coeffs, poly.moduli())
}

/// Apply automorphism to RLWE ciphertext
///
/// τ_g((a, b)) = (τ_g(a), τ_g(b))
///
/// Note: After applying an automorphism, the ciphertext is encrypted under
/// τ_g(s) instead of s. Key-switching is required to get a valid ciphertext
/// under the original key.
pub fn automorphism_ciphertext(ct: &RlweCiphertext, g: usize) -> RlweCiphertext {
    RlweCiphertext {
        a: apply_automorphism(&ct.a, g),
        b: apply_automorphism(&ct.b, g),
    }
}

/// Get the two generators for the Galois group (Z/2dZ)^*
///
/// For d a power of 2, (Z/2dZ)^* ≅ Z_{d/2} × Z_2
/// - Generator g1 generates the cyclic subgroup of order d/2
/// - Generator g2 = 2d - 1 generates the subgroup of order 2
///
/// For d = 2048:
/// - g1 = 3 (primitive root)
/// - g2 = 4095 = 2d - 1
pub fn galois_generators(d: usize) -> (usize, usize) {
    debug_assert!(d.is_power_of_two(), "d must be a power of 2");
    debug_assert!(d >= 4, "d must be at least 4");

    // g1 = 3 is a generator for the cyclic part (works for all power-of-2 d)
    let g1 = 3;

    // g2 = 2d - 1 is the "negation" automorphism: τ_{-1}(X) = X^{-1} = -X^{d-1}
    let g2 = 2 * d - 1;

    (g1, g2)
}

/// Compute the order of g in (Z/2dZ)^*
pub fn automorphism_order(g: usize, d: usize) -> usize {
    let two_d = 2 * d;
    let mut val = g % two_d;
    let mut order = 1;

    while val != 1 {
        val = (val * g) % two_d;
        order += 1;

        if order > two_d {
            panic!("g={} is not in (Z/{}Z)^*", g, two_d);
        }
    }

    order
}

/// Check if g is a valid Galois element (odd and coprime to 2d)
pub fn is_valid_galois_element(g: usize, d: usize) -> bool {
    g % 2 == 1 && g < 2 * d && gcd(g, 2 * d) == 1
}

/// Compute GCD using Euclidean algorithm
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular addition
#[inline]
fn mod_add(a: u64, b: u64, q: u64) -> u64 {
    let sum = a as u128 + b as u128;
    (sum % q as u128) as u64
}

/// Modular subtraction
#[inline]
fn mod_sub(a: u64, b: u64, q: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        q - b + a
    }
}

/// Compose two automorphisms: τ_{g1} ∘ τ_{g2} = τ_{g1·g2 mod 2d}
pub fn compose_automorphisms(g1: usize, g2: usize, d: usize) -> usize {
    (g1 * g2) % (2 * d)
}

/// Compute the inverse automorphism: τ_g^{-1} = τ_{g^{-1} mod 2d}
pub fn inverse_automorphism(g: usize, d: usize) -> usize {
    let two_d = 2 * d;
    mod_inverse(g, two_d).expect("g must be coprime to 2d")
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: usize, m: usize) -> Option<usize> {
    let (g, x, _) = extended_gcd(a as i64, m as i64);
    if g != 1 {
        None
    } else {
        Some(((x % m as i64 + m as i64) % m as i64) as usize)
    }
}

fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::InspireParams;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    #[test]
    fn test_automorphism_identity() {
        let params = test_params();
        let d = params.ring_dim;

        // τ_1 should be identity
        let coeffs: Vec<u64> = (0..d).map(|i| i as u64).collect();
        let poly = Poly::from_coeffs_moduli(coeffs.clone(), params.moduli());

        let result = apply_automorphism(&poly, 1);

        for i in 0..d {
            assert_eq!(result.coeff(i), coeffs[i], "Identity failed at {}", i);
        }
    }

    #[test]
    fn test_automorphism_composition() {
        let params = test_params();
        let d = params.ring_dim;

        // τ_g1 ∘ τ_g2 should equal τ_{g1·g2 mod 2d}
        let (g1, g2) = galois_generators(d);

        let coeffs: Vec<u64> = (0..d).map(|i| ((i * 17 + 5) as u64) % params.p).collect();
        let poly = Poly::from_coeffs_moduli(coeffs, params.moduli());

        // Apply τ_g1 then τ_g2
        let step1 = apply_automorphism(&poly, g1);
        let composed = apply_automorphism(&step1, g2);

        // Apply τ_{g1·g2}
        let g_combined = compose_automorphisms(g1, g2, d);
        let direct = apply_automorphism(&poly, g_combined);

        for i in 0..d {
            assert_eq!(
                composed.coeff(i),
                direct.coeff(i),
                "Composition failed at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_automorphism_inverse() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        let coeffs: Vec<u64> = (0..d).map(|i| ((i * 13 + 7) as u64) % params.p).collect();
        let poly = Poly::from_coeffs_moduli(coeffs.clone(), params.moduli());

        // Apply τ_g then τ_{g^{-1}} should give identity
        let g_inv = inverse_automorphism(g1, d);
        let forward = apply_automorphism(&poly, g1);
        let back = apply_automorphism(&forward, g_inv);

        for i in 0..d {
            assert_eq!(back.coeff(i), coeffs[i], "Inverse failed at {}", i);
        }
    }

    #[test]
    fn test_galois_generators() {
        let d = 2048;
        let (g1, g2) = galois_generators(d);

        assert_eq!(g1, 3);
        assert_eq!(g2, 4095);

        // Verify g1 has order d/2 = 1024
        let order_g1 = automorphism_order(g1, d);
        assert_eq!(order_g1, d / 2, "g1 should have order d/2");

        // Verify g2 has order 2
        let order_g2 = automorphism_order(g2, d);
        assert_eq!(order_g2, 2, "g2 should have order 2");
    }

    #[test]
    fn test_galois_generators_d4096() {
        let d = 4096;
        let (g1, g2) = galois_generators(d);

        assert_eq!(g1, 3);
        assert_eq!(g2, 8191);

        let order_g1 = automorphism_order(g1, d);
        assert_eq!(order_g1, d / 2);

        let order_g2 = automorphism_order(g2, d);
        assert_eq!(order_g2, 2);
    }

    #[test]
    fn test_negation_automorphism() {
        let params = test_params();
        let d = params.ring_dim;
        let (_, g2) = galois_generators(d);

        // τ_{2d-1}(X^i) = X^{(2d-1)·i mod 2d} = X^{-i mod 2d}
        // For i=1: X^{-1} ≡ -X^{d-1} (since X^d = -1)

        // Create polynomial p(X) = X
        let mut coeffs = vec![0u64; d];
        coeffs[1] = 1;
        let poly = Poly::from_coeffs_moduli(coeffs, params.moduli());

        let result = apply_automorphism(&poly, g2);

        // Expected: -X^{d-1}
        // Coefficient at d-1 should be q-1 (which is -1 mod q)
        assert_eq!(result.coeff(d - 1), params.q - 1);
        for i in 0..d {
            if i != d - 1 {
                assert_eq!(result.coeff(i), 0);
            }
        }
    }

    #[test]
    fn test_valid_galois_elements() {
        let d = 2048;

        // All odd numbers less than 2d coprime to 2d are valid
        assert!(is_valid_galois_element(1, d));
        assert!(is_valid_galois_element(3, d));
        assert!(is_valid_galois_element(5, d));
        assert!(is_valid_galois_element(4095, d)); // 2d - 1

        // Even numbers are not valid
        assert!(!is_valid_galois_element(2, d));
        assert!(!is_valid_galois_element(4, d));
    }

    #[test]
    fn test_automorphism_ciphertext() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        // Create a dummy ciphertext
        let a_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 3) % params.q).collect();
        let b_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 7 + 1) % params.q).collect();

        let a = Poly::from_coeffs_moduli(a_coeffs, params.moduli());
        let b = Poly::from_coeffs_moduli(b_coeffs, params.moduli());
        let ct = RlweCiphertext::from_parts(a.clone(), b.clone());

        // Apply automorphism to ciphertext
        let ct_auto = automorphism_ciphertext(&ct, g1);

        // Verify components are automorphed correctly
        let a_auto = apply_automorphism(&a, g1);
        let b_auto = apply_automorphism(&b, g1);

        for i in 0..d {
            assert_eq!(ct_auto.a.coeff(i), a_auto.coeff(i));
            assert_eq!(ct_auto.b.coeff(i), b_auto.coeff(i));
        }
    }

    #[test]
    fn test_automorphism_linearity() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        // τ_g(p1 + p2) = τ_g(p1) + τ_g(p2)
        let p1_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 11) % params.p).collect();
        let p2_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 13 + 3) % params.p).collect();

        let p1 = Poly::from_coeffs_moduli(p1_coeffs, params.moduli());
        let p2 = Poly::from_coeffs_moduli(p2_coeffs, params.moduli());

        let sum = &p1 + &p2;
        let auto_sum = apply_automorphism(&sum, g1);

        let auto_p1 = apply_automorphism(&p1, g1);
        let auto_p2 = apply_automorphism(&p2, g1);
        let sum_auto = &auto_p1 + &auto_p2;

        for i in 0..d {
            assert_eq!(
                auto_sum.coeff(i),
                sum_auto.coeff(i),
                "Linearity failed at {}",
                i
            );
        }
    }
}
