//! Typed SIMD wrapper over the Goldilocks field t = 2^64 - 2^32 + 1.
//!
//! [`FheGoldilocks`] is the SIMD counterpart of [`FheUint64`](super::FheUint64):
//! a ciphertext holds `degree` independent slots, and `+`, `-`, `*` act
//! slot-wise. Arithmetic is **field arithmetic modulo
//! t = 2^64 - 2^32 + 1** — the Goldilocks prime used by Plonky2/Plonky3 —
//! not wrapping `u64` arithmetic. Because 2^32 divides t - 1, a plaintext
//! NTT exists for every power-of-two degree up to 2^31, which is what makes
//! SIMD batching possible (t = 2^64 has no such NTT, so `FheUint64` has no
//! slots).
//!
//! # Reduction behavior
//!
//! Inputs to [`FheGoldilocks::encrypt_slots`] are reduced modulo t before
//! encryption: a slot value `x >= t` (there are 2^32 - 1 such `u64` values)
//! encrypts the field element `x - t`. Decryption always returns values in
//! `0..t`.
//!
//! # Example
//!
//! ```rust
//! use fhe::typed::{FheGoldilocks, GOLDILOCKS_MODULUS, ServerKey, set_server_key};
//! use rand::rng;
//!
//! let mut rng = rng();
//! // Toy parameters so the example runs quickly; production code should use
//! // `FheGoldilocks::default_parameters_128()`.
//! let params = FheGoldilocks::parameters(16, &[60, 60, 60, 60])?;
//! let sk = fhe::bfv::SecretKey::random(&params, &mut rng);
//! set_server_key(ServerKey::new(&sk, &mut rng)?);
//!
//! let a = FheGoldilocks::encrypt_slots(&[GOLDILOCKS_MODULUS - 1, 2], &sk, &mut rng)?;
//! let b = FheGoldilocks::encrypt_slots(&[2, 3], &sk, &mut rng)?;
//!
//! // Slot-wise field arithmetic: (t - 1) + 2 wraps to 1 modulo t.
//! let sum = (&a + &b).decrypt_slots(&sk)?;
//! assert_eq!(&sum[..2], &[1, 5]);
//!
//! let product = (&a * &b).decrypt_slots(&sk)?;
//! assert_eq!(&product[..2], &[GOLDILOCKS_MODULUS - 2, 6]);
//! # Ok::<(), fhe::Error>(())
//! ```

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use std::sync::Arc;

use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

use crate::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use crate::{Error, Result};

use super::with_server_key;

/// The Goldilocks prime t = 2^64 - 2^32 + 1, the field of Plonky2/Plonky3.
pub const GOLDILOCKS_MODULUS: u64 = 18446744069414584321;

/// A SIMD vector of encrypted Goldilocks field elements, with slot-wise
/// arithmetic modulo t = 2^64 - 2^32 + 1.
///
/// Wraps a BFV [`Ciphertext`] whose parameters have plaintext modulus t.
/// Each of the `degree` slots is an independent field element; `+`, `-`, `*`
/// act slot-wise in the field zk circuits (Plonky2/Plonky3) use. See the
/// [module documentation](self) for an example and the reduction behavior.
#[derive(Clone)]
pub struct FheGoldilocks {
    ct: Ciphertext,
}

fn check_parameters(par: &Arc<BfvParameters>) -> Result<()> {
    if *par.plaintext_big() != BigUint::from(GOLDILOCKS_MODULUS) {
        return Err(Error::DefaultError(
            "FheGoldilocks requires parameters with plaintext modulus t = 2^64 - 2^32 + 1"
                .to_string(),
        ));
    }
    Ok(())
}

/// Reduces each value modulo t and pads with zeros to `degree` slots.
fn encode_slots(values: &[u64], par: &Arc<BfvParameters>) -> Result<Plaintext> {
    if values.len() > par.degree() {
        return Err(Error::TooManyValues {
            actual: values.len(),
            limit: par.degree(),
        });
    }
    let mut v: Vec<u64> = values.iter().map(|&x| x % GOLDILOCKS_MODULUS).collect();
    v.resize(par.degree(), 0);
    Plaintext::try_encode(v.as_slice(), Encoding::simd(), par)
}

impl FheGoldilocks {
    /// Encrypts `values` slot-wise under the secret key.
    ///
    /// Each value is reduced modulo t = 2^64 - 2^32 + 1 before encryption;
    /// see the [module documentation](self). At most `degree` values fit in
    /// one ciphertext; unused slots are zero.
    ///
    /// Fails if there are more than `degree` values or the key's parameters
    /// do not have plaintext modulus t.
    pub fn encrypt_slots<R: RngCore + CryptoRng>(
        values: &[u64],
        sk: &SecretKey,
        rng: &mut R,
    ) -> Result<Self> {
        check_parameters(&sk.par)?;
        let pt = encode_slots(values, &sk.par)?;
        Ok(Self {
            ct: sk.try_encrypt(&pt, rng)?,
        })
    }

    /// Encrypts `values` slot-wise under the public key.
    ///
    /// Same reduction and slot-count rules as
    /// [`FheGoldilocks::encrypt_slots`].
    pub fn encrypt_slots_with_public_key<R: RngCore + CryptoRng>(
        values: &[u64],
        pk: &PublicKey,
        rng: &mut R,
    ) -> Result<Self> {
        check_parameters(&pk.par)?;
        let pt = encode_slots(values, &pk.par)?;
        Ok(Self {
            ct: pk.try_encrypt(&pt, rng)?,
        })
    }

    /// Decrypts all `degree` slots; every returned value is in `0..t`.
    pub fn decrypt_slots(&self, sk: &SecretKey) -> Result<Vec<u64>> {
        let pt = sk.try_decrypt(&self.ct)?;
        Vec::<u64>::try_decode(&pt, Encoding::simd())
    }

    /// Builds Goldilocks parameters with the given degree and ciphertext
    /// moduli sizes. Useful for tests and examples; production code should
    /// prefer [`FheGoldilocks::default_parameters_128`].
    pub fn parameters(degree: usize, moduli_sizes: &[usize]) -> Result<Arc<BfvParameters>> {
        BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus_biguint(BigUint::from(GOLDILOCKS_MODULUS))
            .set_moduli_sizes(moduli_sizes)
            .build_arc()
    }

    /// Curated parameters for `FheGoldilocks` at 128 bits of security:
    /// degree 16384 (so 16384 SIMD slots) with the same 291-bit ciphertext
    /// modulus as [`FheUint64::default_parameters_128`](super::FheUint64::default_parameters_128),
    /// since both plaintext moduli are ~2^64 and need the same noise budget.
    ///
    /// Supports a multiplicative depth of at least 2 (verified empirically
    /// by `tests/typed_goldilocks.rs`), plus additions.
    pub fn default_parameters_128() -> Result<Arc<BfvParameters>> {
        BfvParametersBuilder::new()
            .set_degree(16384)
            .set_plaintext_modulus_biguint(BigUint::from(GOLDILOCKS_MODULUS))
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

impl From<FheGoldilocks> for Ciphertext {
    fn from(value: FheGoldilocks) -> Self {
        value.ct
    }
}

impl Add<&FheGoldilocks> for &FheGoldilocks {
    type Output = FheGoldilocks;

    fn add(self, rhs: &FheGoldilocks) -> FheGoldilocks {
        FheGoldilocks {
            ct: &self.ct + &rhs.ct,
        }
    }
}

impl Add<&FheGoldilocks> for FheGoldilocks {
    type Output = FheGoldilocks;

    fn add(mut self, rhs: &FheGoldilocks) -> FheGoldilocks {
        self += rhs;
        self
    }
}

impl AddAssign<&FheGoldilocks> for FheGoldilocks {
    fn add_assign(&mut self, rhs: &FheGoldilocks) {
        self.ct += &rhs.ct;
    }
}

impl Sub<&FheGoldilocks> for &FheGoldilocks {
    type Output = FheGoldilocks;

    fn sub(self, rhs: &FheGoldilocks) -> FheGoldilocks {
        FheGoldilocks {
            ct: &self.ct - &rhs.ct,
        }
    }
}

impl Sub<&FheGoldilocks> for FheGoldilocks {
    type Output = FheGoldilocks;

    fn sub(mut self, rhs: &FheGoldilocks) -> FheGoldilocks {
        self -= rhs;
        self
    }
}

impl SubAssign<&FheGoldilocks> for FheGoldilocks {
    fn sub_assign(&mut self, rhs: &FheGoldilocks) {
        self.ct -= &rhs.ct;
    }
}

impl Neg for &FheGoldilocks {
    type Output = FheGoldilocks;

    fn neg(self) -> FheGoldilocks {
        FheGoldilocks { ct: -&self.ct }
    }
}

impl Neg for FheGoldilocks {
    type Output = FheGoldilocks;

    fn neg(self) -> FheGoldilocks {
        FheGoldilocks { ct: -self.ct }
    }
}

impl Mul<&FheGoldilocks> for &FheGoldilocks {
    type Output = FheGoldilocks;

    /// Multiplies slot-wise and relinearizes with the thread-local
    /// [`ServerKey`](super::ServerKey).
    ///
    /// # Panics
    /// Panics if no server key was installed via
    /// [`set_server_key`](super::set_server_key) on this thread, or if
    /// relinearization fails (e.g. the key was generated for different
    /// parameters), matching [`FheUint64`](super::FheUint64)'s `*`.
    fn mul(self, rhs: &FheGoldilocks) -> FheGoldilocks {
        let mut ct = &self.ct * &rhs.ct;
        let relinearized = with_server_key(|k| k.rk.relinearizes(&mut ct));
        assert!(
            relinearized.is_ok(),
            "relinearization failed: server key does not match ciphertext parameters"
        );
        FheGoldilocks { ct }
    }
}

impl Mul<&FheGoldilocks> for FheGoldilocks {
    type Output = FheGoldilocks;

    fn mul(self, rhs: &FheGoldilocks) -> FheGoldilocks {
        &self * rhs
    }
}
