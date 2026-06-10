//! Branch-free encrypted arithmetic over [`FheUint64`], mirroring fhEVM's
//! `FHESafeMath`.
//!
//! Confidential-token arithmetic must never branch on encrypted data: an
//! `if` that panics or reverts on underflow tells every observer whether
//! the underflow happened. Instead, [`try_add`] and [`try_sub`] always
//! complete and return an encrypted success bit plus a result that
//! *selects back to the original value* when the operation would leave the
//! safe domain — state-rollback semantics, with the taken branch invisible
//! in both the ciphertexts and the call trace.
//!
//! The success bit comes from the committee's interactive comparison
//! ([`Committee::compare_ge`]); the committee therefore learns the
//! outcome of each guard, as documented in the [`crate::gateway`] leakage
//! section.
//!
//! # Safe domain
//!
//! All operands and results must lie in `[0, MAX_SAFE_VALUE]`, with
//! [`MAX_SAFE_VALUE`] = 2^39 - 1. The bound keeps every comparison the
//! guards make (including on the sum `a + b < 2^40`) within the gateway's
//! [`crate::gateway::MAX_COMPARE_OPERAND`] operand bound. "Overflow" for
//! [`try_add`] means leaving this domain, not wrapping at 2^64: domain
//! overflow is detectable by one in-bound comparison, whereas a 2^64 wrap
//! could not be (the wrapped sum violates the comparison bound).
//!
//! Like the operand bound on `compare_ge` itself, this is a documented
//! caller precondition on *encrypted* values, so it cannot be checked:
//! out-of-domain inputs yield arbitrary success bits.
//!
//! # Noise lifecycle
//!
//! [`try_add`] and [`try_sub`] apply the success bit to their result in
//! the *unfactored* cmux form `bit * x + (1 - bit) * y`, the same shape a
//! TFHE/fhEVM cmux has: the guarded value itself passes through a
//! homomorphic multiplication, so every guarded update costs one
//! multiplicative level of the value it updates. An algebraically
//! factored rewrite (`y + bit * (x - y)`, which for these guards reduces
//! to `a ± bit * b` and never multiplies `a`) would grow `a`'s noise only
//! additively — but it would also change the lifecycle this kit is
//! specified around: a long-lived balance updated through these guards
//! consumes its multiplicative budget and **must** be periodically
//! recrypted by the committee ([`Committee::refresh`]), exactly as fhEVM
//! balances live under TFHE's bootstrap. The unfactored form is a
//! deliberate fidelity choice, not an oversight; `tests/gateway.rs` and
//! the token's no-refresh companion test pin the resulting lifecycle
//! down. [`select`] itself remains the factored one-multiplication
//! primitive.
//!
//! # Example
//!
//! ```rust
//! use fhe::gateway::Committee;
//! use fhe::typed::safe_math::try_sub;
//! use fhe::typed::{FheUint64, set_server_key};
//! use rand::rng;
//!
//! let mut rng = rng();
//! // Toy parameters so the example runs quickly; production code should
//! // use `FheUint64::default_parameters_128()`.
//! let params = FheUint64::parameters(16, &[60, 60, 60, 60])?;
//! let committee = Committee::new(3, &params, &mut rng)?;
//! set_server_key(committee.server_key());
//!
//! let a = committee.encrypt(5, &mut rng)?;
//! let b = committee.encrypt(6, &mut rng)?;
//!
//! // 5 - 6 underflows: the operation still completes, reports an
//! // encrypted failure, and rolls the result back to the original value.
//! let (success, result) = try_sub(&committee, &a, &b, &mut rng)?;
//! assert_eq!(committee.threshold_decrypt(&success, &mut rng)?, 0);
//! assert_eq!(committee.threshold_decrypt(&result, &mut rng)?, 5);
//! # Ok::<(), fhe::Error>(())
//! ```

use rand::{CryptoRng, RngCore};

use super::FheUint64;
use crate::Result;
use crate::gateway::Committee;

/// Inclusive upper bound of the safe domain: 2^39 - 1.
///
/// See the [module documentation](self).
pub const MAX_SAFE_VALUE: u64 = (1 << 39) - 1;

/// Branch-free select: returns an encryption of `x` if `bit` encrypts 1,
/// of `y` if `bit` encrypts 0, computed as `bit * (x - y) + y`.
///
/// Costs one homomorphic multiplication (the result is one multiplicative
/// level deeper than the inputs). `bit` must encrypt exactly 0 or 1 — any
/// other value yields an arbitrary blend of `x` and `y`.
///
/// # Panics
/// Panics if no server key is installed on this thread (see
/// [`crate::typed::set_server_key`]); this matches the `*` operator it is
/// built from.
#[must_use]
pub fn select(bit: &FheUint64, x: &FheUint64, y: &FheUint64) -> FheUint64 {
    &(bit * &(x - y)) + y
}

/// The guarded result in cmux form: `bit * x + (1 - bit) * y`.
///
/// Unlike [`select`], this is NOT algebraically factored: both `x` and `y`
/// pass through a homomorphic multiplication by the bit, exactly as in a
/// TFHE/fhEVM cmux. `try_add`/`try_sub` use it deliberately so that a
/// guarded update consumes one multiplicative level of the value it
/// guards — see the module-level "Noise lifecycle" section.
pub(crate) fn cmux<R: RngCore + CryptoRng>(
    committee: &Committee,
    bit: &FheUint64,
    x: &FheUint64,
    y: &FheUint64,
    rng: &mut R,
) -> Result<FheUint64> {
    let one = committee.encrypt(1, rng)?;
    let not_bit = &one - bit;
    Ok(&(bit * x) + &(&not_bit * y))
}

/// Branch-free checked addition: returns `(success, result)` where
/// `result` encrypts `a + b` and `success` encrypts 1 if the sum stays in
/// the safe domain, and `result` encrypts the original `a` and `success`
/// encrypts 0 otherwise.
///
/// Never panics on overflow and never reveals (outside the committee's
/// documented leakage) which branch was taken. The result is one
/// multiplicative level deeper than `a` (see the module-level "Noise
/// lifecycle" section).
pub fn try_add<R: RngCore + CryptoRng>(
    committee: &Committee,
    a: &FheUint64,
    b: &FheUint64,
    rng: &mut R,
) -> Result<(FheUint64, FheUint64)> {
    let sum = a + b;
    let max = committee.encrypt(MAX_SAFE_VALUE, rng)?;
    let success = committee.compare_ge(&max, &sum, rng)?;
    let result = cmux(committee, &success, &sum, a, rng)?;
    Ok((success, result))
}

/// Branch-free checked subtraction: returns `(success, result)` where
/// `result` encrypts `a - b` and `success` encrypts 1 if `a >= b`, and
/// `result` encrypts the original `a` and `success` encrypts 0 otherwise.
///
/// Never panics on underflow and never reveals (outside the committee's
/// documented leakage) which branch was taken. The result is one
/// multiplicative level deeper than `a` (see the module-level "Noise
/// lifecycle" section).
pub fn try_sub<R: RngCore + CryptoRng>(
    committee: &Committee,
    a: &FheUint64,
    b: &FheUint64,
    rng: &mut R,
) -> Result<(FheUint64, FheUint64)> {
    let success = committee.compare_ge(a, b, rng)?;
    let result = cmux(committee, &success, &(a - b), a, rng)?;
    Ok((success, result))
}
