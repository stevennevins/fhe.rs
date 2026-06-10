// Same rationale as `native.rs`: NTT loops index into precomputed tables
// whose layout guarantees the indices are valid.
#![expect(
    clippy::indexing_slicing,
    reason = "twiddle table indices are validated by construction"
)]

use itertools::Itertools;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::iter::successors;

/// Number-Theoretic Transform operator for primes of up to 64 bits.
///
/// [`NttOperator`](crate::ntt::NttOperator) is limited to 62-bit moduli
/// because its lazy butterflies need headroom for values up to 4p in a u64.
/// This operator trades that speed for range: every modular operation goes
/// through u128 division, which is correct for any NTT-friendly prime
/// p < 2^64 — in particular the Goldilocks prime 2^64 - 2^32 + 1 used by
/// zk proof systems. It is meant for the plaintext side of BFV, where
/// encode/decode is not performance critical; ciphertext arithmetic must
/// keep using `NttOperator`.
///
/// Unlike `NttOperator`, this operator is *not* constant time: u128
/// division timing may depend on operand values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ntt64Operator {
    p: u64,
    size: usize,
    omegas: Box<[u64]>,
    zetas_inv: Box<[u64]>,
    size_inv: u64,
}

impl Ntt64Operator {
    /// Create an NTT operator for the prime modulus p and a specific size.
    ///
    /// Aborts if the size is not a power of 2 that is >= 8.
    /// Returns None if the modulus does not support the NTT for this size,
    /// i.e. if p is not prime or p != 1 (mod 2 * size).
    #[must_use]
    pub fn new(p: u64, size: usize) -> Option<Self> {
        if !super::supports_ntt(p, size) {
            return None;
        }

        let size_inv = inv_mod(size as u64, p)?;
        let omega = primitive_root(size, p)?;
        let omega_inv = inv_mod(omega, p)?;

        // Same bit-reversed twiddle layout as `NttOperator::new`, so the two
        // operators compute identical transforms for moduli both support.
        let powers = successors(Some(1u64), |n| Some(mul_mod(*n, omega, p)))
            .take(size)
            .collect_vec();
        let powers_inv = successors(Some(omega_inv), |n| Some(mul_mod(*n, omega_inv, p)))
            .take(size)
            .collect_vec();
        let (omegas, zetas_inv): (Vec<u64>, Vec<u64>) = (0..size)
            .map(|i| {
                let j = i.reverse_bits() >> (size.leading_zeros() + 1);
                (powers[j], powers_inv[j])
            })
            .unzip();

        Some(Self {
            p,
            size,
            omegas: omegas.into_boxed_slice(),
            zetas_inv: zetas_inv.into_boxed_slice(),
            size_inv,
        })
    }

    /// Returns the size handled by this operator.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Compute the forward negacyclic NTT in place. Inputs are reduced
    /// modulo p first, so values in [p, 2^64) are accepted.
    ///
    /// Aborts if a is not of the size handled by the operator.
    pub fn forward(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.size);
        a.iter_mut().for_each(|ai| *ai %= self.p);

        let mut l = self.size >> 1;
        let mut k = 1;
        while l > 0 {
            for chunk in a.chunks_exact_mut(2 * l) {
                let omega = self.omegas[k];
                k += 1;
                let (left, right) = chunk.split_at_mut(l);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let t = mul_mod(*y, omega, self.p);
                    *y = sub_mod(*x, t, self.p);
                    *x = add_mod(*x, t, self.p);
                }
            }
            l >>= 1;
        }
    }

    /// Compute the backward negacyclic NTT in place. Inputs are reduced
    /// modulo p first, so values in [p, 2^64) are accepted.
    ///
    /// Aborts if a is not of the size handled by the operator.
    pub fn backward(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.size);
        a.iter_mut().for_each(|ai| *ai %= self.p);

        let mut k = 0;
        let mut l = 1;
        while l < self.size {
            for chunk in a.chunks_exact_mut(2 * l) {
                let zeta_inv = self.zetas_inv[k];
                k += 1;
                let (left, right) = chunk.split_at_mut(l);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let t = sub_mod(*x, *y, self.p);
                    *x = add_mod(*x, *y, self.p);
                    *y = mul_mod(t, zeta_inv, self.p);
                }
            }
            l <<= 1;
        }

        a.iter_mut()
            .for_each(|ai| *ai = mul_mod(*ai, self.size_inv, self.p));
    }
}

const fn add_mod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 + b as u128) % p as u128) as u64
}

const fn sub_mod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 + p as u128 - b as u128) % p as u128) as u64
}

const fn mul_mod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

const fn pow_mod(mut base: u64, mut exp: u64, p: u64) -> u64 {
    base %= p;
    let mut result = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod(result, base, p);
        }
        base = mul_mod(base, base, p);
        exp >>= 1;
    }
    result
}

/// Inverse modulo a prime p, via Fermat's little theorem.
fn inv_mod(a: u64, p: u64) -> Option<u64> {
    if a.is_multiple_of(p) {
        None
    } else {
        Some(pow_mod(a, p - 2, p))
    }
}

/// Returns a 2n-th primitive root modulo the prime p.
///
/// Mirrors `NttOperator::primitive_root`, including the seeded RNG, so both
/// operators derive the same root for a given (p, n).
fn primitive_root(n: usize, p: u64) -> Option<u64> {
    debug_assert!(super::supports_ntt(p, n));

    let lambda = (p - 1) / (2 * n as u64);

    let mut rng: ChaCha8Rng = SeedableRng::seed_from_u64(0);
    for _ in 0..100 {
        let root = pow_mod(rng.random_range(0..p), lambda, p);
        if is_primitive_root(root, 2 * n as u64, p) {
            return Some(root);
        }
    }
    None
}

/// Returns whether a is an n-th primitive root of unity modulo p, where n is
/// a power of two.
fn is_primitive_root(a: u64, n: u64, p: u64) -> bool {
    (pow_mod(a, n, p) == 1) && (pow_mod(a, n / 2, p) != 1)
}

#[cfg(test)]
mod tests {
    use super::Ntt64Operator;
    use crate::ntt::supports_ntt;
    use rand::{Rng, rng};

    const GOLDILOCKS: u64 = 18446744069414584321; // 2^64 - 2^32 + 1

    #[test]
    fn constructor() {
        for size in [8, 32, 1024] {
            // Goldilocks: 2^32 | p - 1, so every practical size works.
            assert!(supports_ntt(GOLDILOCKS, size));
            assert!(Ntt64Operator::new(GOLDILOCKS, size).is_some());

            // 2^64 - 59 is prime but 16 does not divide p - 1: no NTT.
            assert!(Ntt64Operator::new(u64::MAX - 58, size).is_none());
            // 2^64 - 2^32 + 2 is even, hence not prime.
            assert!(Ntt64Operator::new(GOLDILOCKS + 1, size).is_none());
        }
    }

    #[test]
    fn bijection() {
        let mut rng = rng();
        for size in [8, 32, 1024] {
            let op = Ntt64Operator::new(GOLDILOCKS, size).unwrap();
            for _ in 0..10 {
                let a: Vec<u64> = (0..size).map(|_| rng.random_range(0..GOLDILOCKS)).collect();

                let mut b = a.clone();
                op.forward(&mut b);
                assert_ne!(a, b);
                op.backward(&mut b);
                assert_eq!(a, b);
            }
        }
    }

    // The tfhe-ntt backend may pick different twiddle factors, so this
    // comparison is only meaningful against the native operator.
    #[cfg(not(feature = "tfhe-ntt"))]
    #[test]
    fn matches_62bit_ntt_operator() {
        // For a modulus both operators support, the transforms must be
        // identical: this validates the u128 arithmetic against the
        // battle-tested 62-bit implementation.
        let mut rng = rng();
        let p = 4611686018326724609u64;
        let q = crate::zq::Modulus::new(p).unwrap();
        for size in [32, 1024] {
            let op_62 = crate::ntt::NttOperator::new(&q, size).unwrap();
            let op_64 = Ntt64Operator::new(p, size).unwrap();

            for _ in 0..10 {
                let a = q.random_vec(size, &mut rng);

                let mut b_62 = a.clone();
                let mut b_64 = a.clone();
                op_62.forward(&mut b_62);
                op_64.forward(&mut b_64);
                assert_eq!(b_62, b_64);

                op_62.backward(&mut b_62);
                op_64.backward(&mut b_64);
                assert_eq!(b_62, b_64);
                assert_eq!(a, b_62);
            }
        }
    }

    #[test]
    fn inputs_above_p_are_reduced() {
        let op = Ntt64Operator::new(GOLDILOCKS, 8).unwrap();

        let mut a = vec![u64::MAX; 8]; // = GOLDILOCKS + (2^32 - 2)
        let mut b = vec![u64::MAX - GOLDILOCKS; 8];
        op.backward(&mut a);
        op.backward(&mut b);
        assert_eq!(a, b);
    }
}
