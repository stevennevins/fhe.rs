//! Typed high-level API in the style of [tfhe-rs](https://docs.zama.ai/tfhe-rs).
//!
//! This module wraps the low-level BFV API ([`crate::bfv`]) in two typed
//! ciphertexts with different 64-bit plaintext semantics:
//!
//! - [`FheUint64`]: one `u64` per ciphertext with **wrapping integer
//!   semantics** (t = 2^64), matching Rust's `wrapping_*` ops and the
//!   message space of tfhe-rs' `FheUint64`.
//! - [`FheGoldilocks`]: `degree` SIMD slots per ciphertext with **field
//!   semantics** modulo the Goldilocks prime t = 2^64 - 2^32 + 1, the field
//!   used by the Plonky2/Plonky3 zk proof systems.
//!
//! # Choosing between them
//!
//! | | `FheUint64` | `FheGoldilocks` |
//! |---|---|---|
//! | Plaintext modulus t | 2^64 | 2^64 - 2^32 + 1 (prime) |
//! | Arithmetic | wrapping `u64` | field mod t |
//! | SIMD slots | none (t not NTT-friendly) | `degree` slots |
//! | Interop | tfhe-rs `FheUint64` message space | Plonky2/Plonky3 field |
//!
//! t = 2^64 admits no plaintext NTT (it is not prime, and no root of unity
//! of the right order exists), so a `FheUint64` ciphertext carries a single
//! value. The Goldilocks prime has 2^32 | t - 1, so a plaintext NTT exists
//! for every practical degree and one ciphertext batches `degree` field
//! elements — at degree 16384, a 16384x throughput advantage for slot-wise
//! workloads.
//!
//! Both moduli are ~2^64, so they pay the same noise-budget cost: roughly
//! 64 bits of every ciphertext-modulus level go to the message. The curated
//! [`FheUint64::default_parameters_128`] and
//! [`FheGoldilocks::default_parameters_128`] sets (degree 16384, 291-bit q)
//! both support multiplicative depth 2 at 128-bit security; deeper circuits
//! need a larger degree and ciphertext modulus, sized following the
//! <https://homomorphicencryption.org> standard tables.
//!
//! # `FheUint64` semantics
//!
//! [`FheUint64`]'s homomorphic arithmetic matches Rust's
//! wrapping `u64` semantics exactly: the plaintext modulus is fixed to
//! t = 2^64, so `+`, `-`, `*` and unary `-` on ciphertexts decrypt to
//! `wrapping_add`, `wrapping_sub`, `wrapping_mul` and `wrapping_neg` of the
//! underlying values.
//!
//! Multiplication needs key material (a relinearization key). Like tfhe-rs,
//! this module stores it in a thread-local [`ServerKey`] installed with
//! [`set_server_key`], so the `*` operator works without threading a key
//! through every call site.
//!
//! # Example
//!
//! ```rust
//! use fhe::typed::{FheUint64, ServerKey, set_server_key};
//! use rand::rng;
//!
//! let mut rng = rng();
//! // Toy parameters so the example runs quickly; production code should use
//! // `FheUint64::default_parameters_128()`.
//! let params = FheUint64::parameters(16, &[60, 60, 60, 60])?;
//! let sk = fhe::bfv::SecretKey::random(&params, &mut rng);
//! set_server_key(ServerKey::new(&sk, &mut rng)?);
//!
//! let a = FheUint64::encrypt(u64::MAX - 1, &sk, &mut rng)?;
//! let b = FheUint64::encrypt(7, &sk, &mut rng)?;
//!
//! let sum = &a + &b;
//! assert_eq!(sum.decrypt(&sk)?, (u64::MAX - 1).wrapping_add(7));
//!
//! let product = &a * &b;
//! assert_eq!(product.decrypt(&sk)?, (u64::MAX - 1).wrapping_mul(7));
//! # Ok::<(), fhe::Error>(())
//! ```
//!
//! # Intentional divergences from tfhe-rs
//!
//! - **No `ClientKey`/`CompactPublicKey` wrappers.** Encryption takes the
//!   existing [`SecretKey`] or [`PublicKey`] directly, plus an explicit RNG
//!   (tfhe-rs hides the RNG; this crate passes RNGs explicitly everywhere).
//! - **Fallible API.** `encrypt`/`decrypt` return [`crate::Result`] instead
//!   of panicking, matching this crate's `try_*` conventions. The arithmetic
//!   operators do panic on misuse (no server key installed, mismatched
//!   parameters), which matches both tfhe-rs and the underlying
//!   [`Ciphertext`] operators.
//! - **`ServerKey` holds only a relinearization key.** There is no
//!   bootstrapping in BFV, so unlike tfhe-rs the multiplicative depth is
//!   bounded by the parameters; see [`FheUint64::default_parameters_128`].

mod goldilocks;
pub use goldilocks::{FheGoldilocks, GOLDILOCKS_MODULUS};

use std::cell::RefCell;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use std::sync::Arc;

use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, FheParametrized,
    Serialize,
};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

use crate::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey,
    RelinearizationKey, SecretKey,
};
use crate::{Error, Result};

/// Key material the server needs to evaluate `*` on [`FheUint64`] values.
///
/// Mirrors the tfhe-rs `ServerKey`, but only contains a BFV relinearization
/// key since BFV has no bootstrapping.
pub struct ServerKey {
    rk: RelinearizationKey,
}

impl ServerKey {
    /// Generates a server key from the secret key.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey, rng: &mut R) -> Result<Self> {
        Ok(Self {
            rk: RelinearizationKey::new(sk, rng)?,
        })
    }

    /// Wraps an existing relinearization key, e.g. one generated
    /// collectively with [`crate::mbfv::RelinKeyGenerator`].
    #[must_use]
    pub fn from_relinearization_key(rk: RelinearizationKey) -> Self {
        Self { rk }
    }
}

impl FheParametrized for ServerKey {
    type Parameters = BfvParameters;
}

impl Serialize for ServerKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.rk.to_bytes()
    }
}

impl DeserializeParametrized for ServerKey {
    type Error = Error;

    /// Deserializes a server key, validating that the parameters have
    /// plaintext modulus t = 2^64.
    fn from_bytes(bytes: &[u8], par: &Arc<BfvParameters>) -> Result<Self> {
        check_parameters(par)?;
        Ok(Self {
            rk: RelinearizationKey::from_bytes(bytes, par)?,
        })
    }
}

thread_local! {
    static SERVER_KEY: RefCell<Option<Arc<ServerKey>>> = const { RefCell::new(None) };
}

/// Installs the server key used by the `*` operator on this thread.
///
/// Mirrors tfhe-rs' `set_server_key`. Each thread that multiplies
/// [`FheUint64`] or [`FheGoldilocks`] values must install a key.
pub fn set_server_key(key: ServerKey) {
    SERVER_KEY.with(|k| *k.borrow_mut() = Some(Arc::new(key)));
}

/// Removes the server key from this thread, if any.
pub fn unset_server_key() {
    SERVER_KEY.with(|k| *k.borrow_mut() = None);
}

fn with_server_key<T>(f: impl FnOnce(&ServerKey) -> T) -> T {
    SERVER_KEY.with(|k| {
        let k = k.borrow();
        assert!(
            k.is_some(),
            "no server key installed on this thread; call fhe::typed::set_server_key"
        );
        f(k.as_ref().unwrap())
    })
}

/// An encrypted `u64` with wrapping arithmetic, in the style of tfhe-rs'
/// `FheUint64`.
///
/// Wraps a BFV [`Ciphertext`] whose parameters have plaintext modulus
/// t = 2^64, so homomorphic operations match `u64` wrapping semantics. See
/// the [module documentation](self) for an example.
#[derive(Clone)]
pub struct FheUint64 {
    ct: Ciphertext,
}

/// t = 2^64 as a `BigUint`.
fn t_2_64() -> BigUint {
    BigUint::from(1u128 << 64)
}

/// Encodes `value` into coefficient 0 of a degree-n plaintext polynomial.
/// With both operands encoded this way, polynomial multiplication leaves the
/// product in coefficient 0.
fn encode(value: u64, par: &Arc<BfvParameters>) -> Result<Plaintext> {
    let mut v = vec![0u64; par.degree()];
    if let Some(first) = v.first_mut() {
        *first = value;
    }
    Plaintext::try_encode(v.as_slice(), Encoding::poly(), par)
}

fn check_parameters(par: &Arc<BfvParameters>) -> Result<()> {
    if *par.plaintext_big() != t_2_64() {
        return Err(Error::DefaultError(
            "FheUint64 requires parameters with plaintext modulus t = 2^64".to_string(),
        ));
    }
    Ok(())
}

impl FheUint64 {
    /// Encrypts `value` under the secret key.
    ///
    /// Fails if the key's parameters do not have plaintext modulus t = 2^64.
    pub fn encrypt<R: RngCore + CryptoRng>(
        value: u64,
        sk: &SecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        check_parameters(&sk.par)?;
        let pt = encode(value, &sk.par)?;
        Ok(Self {
            ct: sk.try_encrypt(&pt, rng)?,
        })
    }

    /// Encrypts `value` under the public key.
    ///
    /// Fails if the key's parameters do not have plaintext modulus t = 2^64.
    pub fn encrypt_with_public_key<R: RngCore + CryptoRng>(
        value: u64,
        pk: &PublicKey,
        rng: &mut R,
    ) -> Result<Self> {
        check_parameters(&pk.par)?;
        let pt = encode(value, &pk.par)?;
        Ok(Self {
            ct: pk.try_encrypt(&pt, rng)?,
        })
    }

    /// Decrypts to the underlying `u64`.
    pub fn decrypt(&self, sk: &SecretKey) -> Result<u64> {
        let pt = sk.try_decrypt(&self.ct)?;
        let v = Vec::<u64>::try_decode(&pt, Encoding::poly())?;
        v.first().copied().ok_or_else(|| {
            Error::DefaultError("decrypted plaintext has no coefficients".to_string())
        })
    }

    /// Builds t = 2^64 parameters with the given degree and ciphertext
    /// moduli sizes. Useful for tests and examples; production code should
    /// prefer [`FheUint64::default_parameters_128`].
    pub fn parameters(degree: usize, moduli_sizes: &[usize]) -> Result<Arc<BfvParameters>> {
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus_biguint(t_2_64())
            .set_moduli_sizes(moduli_sizes)
            .build_arc()
    }

    /// Curated parameters for `FheUint64` at 128 bits of security.
    ///
    /// Degree 16384 with a 291-bit ciphertext modulus (six explicit NTT
    /// primes from the same table as
    /// [`BfvParameters::default_parameters_128`]), well under the 438-bit
    /// bound of the <https://homomorphicencryption.org> standard for this
    /// degree. The existing `default_parameters_128` cannot be reused
    /// directly because it generates the plaintext modulus with
    /// `generate_prime`, which is capped below 2^62.
    ///
    /// Supports a multiplicative depth of at least 2 (verified empirically
    /// by `tests/typed_fheuint64.rs`), plus additions.
    pub fn default_parameters_128() -> Result<Arc<BfvParameters>> {
        BfvParametersBuilder::new()
            .set_degree(16384)
            .set_plaintext_modulus_biguint(t_2_64())
            .set_moduli(&[
                0xffff_fffd_8001,
                0xffff_fffa_0001,
                0xffff_fff0_0001,
                0x1_ffff_fff6_8001,
                0x1_ffff_fff5_0001,
                0x1_ffff_ffee_8001,
            ])
            .build_arc()
    }

    /// Consumes `self` and returns the underlying BFV ciphertext, as an
    /// escape hatch to the low-level API.
    #[must_use]
    pub fn into_ciphertext(self) -> Ciphertext {
        self.ct
    }
}

impl FheParametrized for FheUint64 {
    type Parameters = BfvParameters;
}

impl Serialize for FheUint64 {
    fn to_bytes(&self) -> Vec<u8> {
        self.ct.to_bytes()
    }
}

impl DeserializeParametrized for FheUint64 {
    type Error = Error;

    /// Deserializes a ciphertext, validating that the parameters have
    /// plaintext modulus t = 2^64.
    fn from_bytes(bytes: &[u8], par: &Arc<BfvParameters>) -> Result<Self> {
        check_parameters(par)?;
        Ok(Self {
            ct: Ciphertext::from_bytes(bytes, par)?,
        })
    }
}

impl From<FheUint64> for Ciphertext {
    fn from(value: FheUint64) -> Self {
        value.ct
    }
}

impl Add<&FheUint64> for &FheUint64 {
    type Output = FheUint64;

    fn add(self, rhs: &FheUint64) -> FheUint64 {
        FheUint64 {
            ct: &self.ct + &rhs.ct,
        }
    }
}

impl Add<&FheUint64> for FheUint64 {
    type Output = FheUint64;

    fn add(mut self, rhs: &FheUint64) -> FheUint64 {
        self += rhs;
        self
    }
}

impl AddAssign<&FheUint64> for FheUint64 {
    fn add_assign(&mut self, rhs: &FheUint64) {
        self.ct += &rhs.ct;
    }
}

impl Sub<&FheUint64> for &FheUint64 {
    type Output = FheUint64;

    fn sub(self, rhs: &FheUint64) -> FheUint64 {
        FheUint64 {
            ct: &self.ct - &rhs.ct,
        }
    }
}

impl Sub<&FheUint64> for FheUint64 {
    type Output = FheUint64;

    fn sub(mut self, rhs: &FheUint64) -> FheUint64 {
        self -= rhs;
        self
    }
}

impl SubAssign<&FheUint64> for FheUint64 {
    fn sub_assign(&mut self, rhs: &FheUint64) {
        self.ct -= &rhs.ct;
    }
}

impl Neg for &FheUint64 {
    type Output = FheUint64;

    fn neg(self) -> FheUint64 {
        FheUint64 { ct: -&self.ct }
    }
}

impl Neg for FheUint64 {
    type Output = FheUint64;

    fn neg(self) -> FheUint64 {
        FheUint64 { ct: -self.ct }
    }
}

impl Mul<&FheUint64> for &FheUint64 {
    type Output = FheUint64;

    /// Multiplies and relinearizes with the thread-local [`ServerKey`].
    ///
    /// # Panics
    /// Panics if no server key was installed via [`set_server_key`] on this
    /// thread, or if relinearization fails (e.g. the key was generated for
    /// different parameters). This matches tfhe-rs, whose operators also
    /// panic without a server key.
    fn mul(self, rhs: &FheUint64) -> FheUint64 {
        let mut ct = &self.ct * &rhs.ct;
        let relinearized = with_server_key(|k| k.rk.relinearizes(&mut ct));
        assert!(
            relinearized.is_ok(),
            "relinearization failed: server key does not match ciphertext parameters"
        );
        FheUint64 { ct }
    }
}

impl Mul<&FheUint64> for FheUint64 {
    type Output = FheUint64;

    fn mul(self, rhs: &FheUint64) -> FheUint64 {
        &self * rhs
    }
}
