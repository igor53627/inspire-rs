//! Modular arithmetic operations.
//!
//! Provides stateless modular arithmetic functions over Z_q.
//! These are simpler alternatives to the Montgomery-based `ModQ` type
//! when performance is not critical.

/// Stateless modular arithmetic operations over Z_q.
///
/// Provides basic modular operations without Montgomery representation.
/// Use this for simple operations; use `mod_q::ModQ` for performance-critical code.
///
/// # Example
///
/// ```
/// use inspire::math::modular::ModQ;
///
/// let q = 1152921504606830593u64;
/// let sum = ModQ::add(100, 200, q);
/// assert_eq!(sum, 300);
/// ```
pub struct ModQ;

impl ModQ {
    /// Adds two values modulo q.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand
    /// * `b` - Second operand
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// `(a + b) mod q`
    #[inline]
    pub fn add(a: u64, b: u64, q: u64) -> u64 {
        let sum = (a as u128) + (b as u128);
        (sum % (q as u128)) as u64
    }

    /// Subtracts two values modulo q.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand (minuend)
    /// * `b` - Second operand (subtrahend)
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// `(a - b) mod q`
    #[inline]
    pub fn sub(a: u64, b: u64, q: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            q - (b - a)
        }
    }

    /// Multiplies two values modulo q.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand
    /// * `b` - Second operand
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// `(a * b) mod q`
    #[inline]
    pub fn mul(a: u64, b: u64, q: u64) -> u64 {
        let prod = (a as u128) * (b as u128);
        (prod % (q as u128)) as u64
    }

    /// Negates a value modulo q.
    ///
    /// # Arguments
    ///
    /// * `a` - The value to negate
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// `(-a) mod q = (q - a) mod q`
    #[inline]
    pub fn negate(a: u64, q: u64) -> u64 {
        if a == 0 {
            0
        } else {
            q - a
        }
    }

    /// Converts a signed integer to its representation in Z_q.
    ///
    /// Negative values are mapped to their positive equivalents modulo q.
    ///
    /// # Arguments
    ///
    /// * `val` - The signed value
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// The unsigned representation in [0, q).
    #[inline]
    pub fn from_signed(val: i64, q: u64) -> u64 {
        if val >= 0 {
            (val as u64) % q
        } else {
            let abs = (-val) as u64;
            q - (abs % q)
        }
    }

    /// Converts from Z_q to signed representation in [-q/2, q/2).
    ///
    /// Values in [0, q/2] remain positive; values in (q/2, q) become negative.
    ///
    /// # Arguments
    ///
    /// * `val` - The unsigned value in [0, q)
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// The signed representation in [-q/2, q/2).
    #[inline]
    pub fn to_signed(val: u64, q: u64) -> i64 {
        if val <= q / 2 {
            val as i64
        } else {
            -((q - val) as i64)
        }
    }

    /// Reduces a value modulo q.
    ///
    /// # Arguments
    ///
    /// * `a` - The value to reduce
    /// * `q` - The modulus
    ///
    /// # Returns
    ///
    /// `a mod q`
    #[inline]
    pub fn reduce(a: u64, q: u64) -> u64 {
        a % q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: u64 = 1152921504606830593;

    #[test]
    fn test_add() {
        assert_eq!(ModQ::add(5, 7, Q), 12);
        assert_eq!(ModQ::add(Q - 1, 2, Q), 1);
    }

    #[test]
    fn test_sub() {
        assert_eq!(ModQ::sub(10, 3, Q), 7);
        assert_eq!(ModQ::sub(3, 10, Q), Q - 7);
    }

    #[test]
    fn test_mul() {
        assert_eq!(ModQ::mul(5, 7, Q), 35);
    }

    #[test]
    fn test_negate() {
        assert_eq!(ModQ::negate(5, Q), Q - 5);
        assert_eq!(ModQ::negate(0, Q), 0);
    }

    #[test]
    fn test_from_signed() {
        assert_eq!(ModQ::from_signed(5, Q), 5);
        assert_eq!(ModQ::from_signed(-5, Q), Q - 5);
        assert_eq!(ModQ::from_signed(0, Q), 0);
    }

    #[test]
    fn test_to_signed() {
        assert_eq!(ModQ::to_signed(5, Q), 5);
        assert_eq!(ModQ::to_signed(Q - 5, Q), -5);
    }
}
