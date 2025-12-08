//! Modular arithmetic over Z_q
//!
//! Provides efficient modular operations using Montgomery reduction.

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// Default modulus q = 2^60 - 2^14 + 1 (NTT-friendly prime)
pub const DEFAULT_Q: u64 = 1152921504606830593;

/// Element of Z_q with Montgomery representation for fast multiplication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModQ {
    /// Value in Montgomery form: a * R mod q, where R = 2^64
    value: u64,
    /// The modulus q
    q: u64,
    /// -q^(-1) mod 2^64 for Montgomery reduction
    q_inv_neg: u64,
    /// R^2 mod q for converting to Montgomery form
    r_squared: u64,
}

impl ModQ {
    /// Create a new ModQ context for a given modulus
    /// The value is stored in Montgomery form
    pub fn new(value: u64, q: u64) -> Self {
        let q_inv_neg = Self::compute_q_inv_neg(q);
        let r_squared = Self::compute_r_squared(q);
        let mut result = Self {
            value: 0,
            q,
            q_inv_neg,
            r_squared,
        };
        result.value = result.to_montgomery(value);
        result
    }

    /// Create with default modulus
    pub fn with_default_q(value: u64) -> Self {
        Self::new(value, DEFAULT_Q)
    }

    /// Create zero element
    pub fn zero(q: u64) -> Self {
        Self::new(0, q)
    }

    /// Create one element
    pub fn one(q: u64) -> Self {
        Self::new(1, q)
    }

    /// Get the underlying value (converted from Montgomery form)
    pub fn value(&self) -> u64 {
        self.from_montgomery(self.value)
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.q
    }

    /// Compute -q^(-1) mod 2^64 using extended Euclidean algorithm
    fn compute_q_inv_neg(q: u64) -> u64 {
        let mut y: u64 = 1;
        for i in 1..64 {
            let yi = y.wrapping_mul(q) & (1u64 << i);
            y |= yi;
        }
        y.wrapping_neg()
    }

    /// Compute R^2 mod q where R = 2^64
    fn compute_r_squared(q: u64) -> u64 {
        let r_mod_q = (1u128 << 64) % (q as u128);
        ((r_mod_q * r_mod_q) % (q as u128)) as u64
    }

    /// Convert to Montgomery form: a -> a * R mod q
    fn to_montgomery(&self, a: u64) -> u64 {
        self.montgomery_mul(a, self.r_squared)
    }

    /// Convert from Montgomery form: a * R -> a
    fn from_montgomery(&self, a: u64) -> u64 {
        self.montgomery_mul(a, 1)
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod q
    fn montgomery_mul(&self, a: u64, b: u64) -> u64 {
        let ab = (a as u128) * (b as u128);
        let m = ((ab as u64).wrapping_mul(self.q_inv_neg)) as u128;
        let t = ((ab + m * (self.q as u128)) >> 64) as u64;
        if t >= self.q {
            t - self.q
        } else {
            t
        }
    }

    /// Modular exponentiation using square-and-multiply
    pub fn pow(&self, mut exp: u64) -> Self {
        let mut base = *self;
        let mut result = Self {
            value: self.to_montgomery(1),
            q: self.q,
            q_inv_neg: self.q_inv_neg,
            r_squared: self.r_squared,
        };

        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    /// Modular inverse using Fermat's little theorem: a^(-1) = a^(q-2) mod q
    pub fn inv(&self) -> Option<Self> {
        if self.value() == 0 {
            None
        } else {
            Some(self.pow(self.q - 2))
        }
    }

}

impl Add for ModQ {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.q, rhs.q, "Moduli must match");
        let sum = self.value + rhs.value;
        let value = if sum >= self.q { sum - self.q } else { sum };
        Self {
            value,
            q: self.q,
            q_inv_neg: self.q_inv_neg,
            r_squared: self.r_squared,
        }
    }
}

impl AddAssign for ModQ {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for ModQ {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.q, rhs.q, "Moduli must match");
        let value = if self.value >= rhs.value {
            self.value - rhs.value
        } else {
            self.q - rhs.value + self.value
        };
        Self {
            value,
            q: self.q,
            q_inv_neg: self.q_inv_neg,
            r_squared: self.r_squared,
        }
    }
}

impl SubAssign for ModQ {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for ModQ {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.q, rhs.q, "Moduli must match");
        let value = self.montgomery_mul(self.value, rhs.value);
        Self {
            value,
            q: self.q,
            q_inv_neg: self.q_inv_neg,
            r_squared: self.r_squared,
        }
    }
}

impl MulAssign for ModQ {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for ModQ {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let value = if self.value == 0 {
            0
        } else {
            self.q - self.value
        };
        Self {
            value,
            q: self.q,
            q_inv_neg: self.q_inv_neg,
            r_squared: self.r_squared,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: u64 = DEFAULT_Q;

    #[test]
    fn test_basic_operations() {
        let a = ModQ::new(100, Q);
        let b = ModQ::new(200, Q);

        assert_eq!((a + b).value(), 300);
        assert_eq!((b - a).value(), 100);
        assert_eq!((a * b).value(), 20000);
    }

    #[test]
    fn test_modular_reduction() {
        let a = ModQ::new(Q - 1, Q);
        let b = ModQ::new(2, Q);

        assert_eq!((a + b).value(), 1);
    }

    #[test]
    fn test_negation() {
        let a = ModQ::new(100, Q);
        let neg_a = -a;

        assert_eq!((a + neg_a).value(), 0);
        assert_eq!(neg_a.value(), Q - 100);
    }

    #[test]
    fn test_subtraction_underflow() {
        let a = ModQ::new(100, Q);
        let b = ModQ::new(200, Q);

        assert_eq!((a - b).value(), Q - 100);
    }

    #[test]
    fn test_multiplication_large() {
        let a = ModQ::new(1 << 30, Q);
        let b = ModQ::new(1 << 30, Q);
        let result = (a * b).value();

        let expected = ((1u128 << 60) % Q as u128) as u64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pow() {
        let base = ModQ::new(2, Q);
        let result = base.pow(10);
        assert_eq!(result.value(), 1024);
    }

    #[test]
    fn test_pow_large() {
        let base = ModQ::new(3, Q);
        let result = base.pow(Q - 1);
        assert_eq!(result.value(), 1); // Fermat's little theorem
    }

    #[test]
    fn test_inverse() {
        let a = ModQ::new(12345, Q);
        let a_inv = a.inv().unwrap();
        let product = (a * a_inv).value();
        assert_eq!(product, 1);
    }

    #[test]
    fn test_inverse_of_zero() {
        let zero = ModQ::new(0, Q);
        assert!(zero.inv().is_none());
    }

    #[test]
    fn test_zero_and_one() {
        let zero = ModQ::zero(Q);
        let one = ModQ::one(Q);

        assert_eq!(zero.value(), 0);
        assert_eq!(one.value(), 1);
        assert_eq!((zero + one).value(), 1);
    }

    #[test]
    fn test_montgomery_roundtrip() {
        for val in [0u64, 1, 2, 100, Q - 1, Q - 2, 1 << 30] {
            let m = ModQ::new(val, Q);
            assert_eq!(m.value(), val);
        }
    }

    #[test]
    fn test_associativity() {
        let a = ModQ::new(123456789, Q);
        let b = ModQ::new(987654321, Q);
        let c = ModQ::new(456789123, Q);

        assert_eq!(((a + b) + c).value(), (a + (b + c)).value());
        assert_eq!(((a * b) * c).value(), (a * (b * c)).value());
    }

    #[test]
    fn test_distributivity() {
        let a = ModQ::new(12345, Q);
        let b = ModQ::new(67890, Q);
        let c = ModQ::new(11111, Q);

        let left = (a * (b + c)).value();
        let right = (a * b + a * c).value();
        assert_eq!(left, right);
    }
}
