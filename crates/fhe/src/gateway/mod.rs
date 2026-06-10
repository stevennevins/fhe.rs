//! An in-process threshold committee and decryption gateway for the typed
//! API, in the style of fhEVM's KMS/gateway, built on the multiparty BFV
//! primitives of [`crate::mbfv`].
//!
//! A [`Committee`] is a set of N parties that collectively generate the
//! public key and relinearization key for a [`FheUint64`] deployment. No
//! single party ever holds the secret key: it exists only as N additive
//! shares, and every decryption requires a share from **all** N parties
//! (the Mouchet et al. multiparty BFV scheme is N-of-N; there is no
//! Shamir-style t < N reconstruction in [`crate::mbfv`]).
//!
//! v1 is in-process: each party is a value owned by the [`Committee`] and
//! "protocol messages" are function returns. The protocol structure — who
//! contributes what share, and what each party gets to see — is exactly
//! what a networked deployment would use; only the transport is missing.
//!
//! The committee provides three services:
//!
//! - [`Committee::threshold_decrypt`]: designated decryption of a
//!   ciphertext from all N parties' decryption shares.
//! - [`Committee::refresh`]: recryption of a ciphertext to a fresh
//!   low-noise encryption of the same value, without any party seeing the
//!   plaintext. BFV has no bootstrapping, so a long-lived ciphertext (a
//!   token balance) **must** be refreshed periodically or it dies of
//!   noise; refresh is a correctness requirement, not an optimization.
//! - [`Committee::compare_ge`]: interactive comparison. Comparisons are
//!   not computed homomorphically (a BFV comparison circuit would blow the
//!   depth budget without bootstrapping); instead the committee decrypts a
//!   blinded difference and returns a fresh encryption of the 0/1 result.
//!
//! # Leakage
//!
//! "The committee learns nothing it shouldn't" needs a definition of
//! "shouldn't". This section is that definition; every claim in it is
//! asserted by a test in `tests/gateway.rs` against the actual transcript
//! values ([`CompareTranscript`], [`RefreshTranscript`]).
//!
//! **Per `threshold_decrypt` invocation**: every party learns the
//! plaintext. This is by design — it is the designated-decryption service —
//! and callers must only submit ciphertexts whose plaintext is meant to
//! become committee-public.
//!
//! **Per `refresh` invocation**, party i learns:
//! - its own additive mask `m_i` (its private randomness), and
//! - the revealed masked value `v = x + m_1 + ... + m_N (mod 2^64)`, where
//!   `x` is the refreshed plaintext.
//!
//! As long as at least one party j != i keeps `m_j` secret, `v` minus
//! everything party i knows is `x + sum of other parties' masks`, which is
//! uniformly distributed mod 2^64 and independent of `x` — a one-time pad.
//! A single party (and any coalition short of all N) learns *nothing*
//! about the refreshed value.
//!
//! **Per `compare_ge(a, b)` invocation**, party i learns:
//! - its own multiplicative blind `r_i` (odd, in `[3, 2^B)` where
//!   `B = [`blind_bits`](Committee::blind_bits)`),
//! - the revealed blinded difference
//!   `m = (r_1 * ... * r_N) * (a - b) (mod 2^64)`, and therefore
//! - the comparison outcome `a >= b` (the sign of `m` as an `i64`), and
//! - whether `a == b` exactly (`m == 0`).
//!
//! A single party cannot recover the true difference `a - b` from its
//! view: it knows `r_i` but not the other parties' blinds, and every
//! other blind is > 1. Even the full coalition, which can recover
//! `a - b`, learns nothing more about the raw operands: `a` and `b` are
//! information-theoretically hidden given only their difference. What IS
//! leaked to every party is the outcome bit, exact-equality, and the
//! magnitude of the difference up to the unknown blind factor
//! (`|a - b| <= |m| <= (a - b) * 2^(N*B)`, i.e. roughly its order of
//! magnitude). Callers for whom the outcome bit itself is sensitive must
//! not use the interactive comparison.
//!
//! # Operand bound for comparisons
//!
//! `compare_ge` requires both operands to be `< 2^40`
//! ([`MAX_COMPARE_OPERAND`]). The blinded difference must stay within the
//! positive/negative halves of the 2^64 ring for its sign to be readable,
//! which caps `blind * |a - b|` below 2^62. With operands below 2^40 the
//! committee has 22 bits of blinding budget to split between its parties;
//! [`Committee::new`] rejects committees too large to give each party at
//! least 2 bits. Operands are encrypted, so this is a documented caller
//! precondition, not a checked one: out-of-range operands yield an
//! arbitrary comparison result (but still leak nothing more than above).

use std::sync::Arc;

use rand::{CryptoRng, Rng, RngCore};

use crate::bfv::{BfvParameters, Ciphertext, PublicKey, RelinearizationKey, SecretKey};
use crate::mbfv::{
    Aggregate, CommonRandomPoly, DecryptionShare, PublicKeyShare, RelinKeyGenerator, RelinKeyShare,
    round::R1Aggregated,
};
use crate::typed::{FheUint64, ServerKey, check_parameters, encode};
use crate::{Error, Result};
use fhe_traits::FheDecoder;

/// Exclusive upper bound on `compare_ge` operands: 2^40.
///
/// See the [module documentation](self) for why the bound exists and what
/// happens when it is violated.
pub const MAX_COMPARE_OPERAND: u64 = 1 << 40;

/// Bits available for multiplicative blinding in `compare_ge`:
/// blind * |a - b| must stay below 2^62, and |a - b| < 2^40.
const BLIND_BITS_BUDGET: usize = 22;

/// One committee member: its additive share of the collective secret key.
struct Party {
    sk: SecretKey,
}

/// What every party saw during one [`Committee::compare_ge`] invocation.
///
/// `blinds[i]` is private to party i; `revealed` is seen by all parties.
/// Exposed so that the leakage claims in the [module documentation](self)
/// can be audited and tested against real protocol values.
pub struct CompareTranscript {
    /// Party i's multiplicative blind `r_i` (party i's private randomness).
    pub blinds: Vec<u64>,
    /// The decrypted blinded difference `(prod r_i) * (a - b) mod 2^64`,
    /// revealed to every party.
    pub revealed: u64,
}

/// What every party saw during one [`Committee::refresh`] invocation.
///
/// `masks[i]` is private to party i; `revealed` is seen by all parties.
pub struct RefreshTranscript {
    /// Party i's additive mask `m_i` (party i's private randomness).
    pub masks: Vec<u64>,
    /// The decrypted masked value `x + sum(masks) mod 2^64`, revealed to
    /// every party.
    pub revealed: u64,
}

/// An in-process committee of N parties holding additive shares of a
/// collective BFV secret key, acting as the decryption gateway for
/// [`FheUint64`] ciphertexts.
///
/// See the [module documentation](self) for the trust model and the
/// precise leakage of each operation.
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::typed::FheUint64;
/// use rand::rng;
///
/// let mut rng = rng();
/// // Toy parameters so the example runs quickly; production code should
/// // use `FheUint64::default_parameters_128()`.
/// let params = FheUint64::parameters(16, &[60, 60, 60, 60])?;
/// let committee = Committee::new(3, &params, &mut rng)?;
///
/// let ct = committee.encrypt(42, &mut rng)?;
/// assert_eq!(committee.threshold_decrypt(&ct, &mut rng)?, 42);
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct Committee {
    par: Arc<BfvParameters>,
    parties: Vec<Party>,
    pk: PublicKey,
    rk: RelinearizationKey,
}

impl Committee {
    /// Runs collective key generation among `n` freshly sampled parties.
    ///
    /// Generates the collective public key (Protocol 1, EncKeyGen) and the
    /// collective relinearization key (Protocol 2, RelinKeyGen) of
    /// [Multiparty BFV](https://eprint.iacr.org/2020/304.pdf). The
    /// collective secret key is never materialized.
    ///
    /// Fails if `n < 2`, if the parameters do not have plaintext modulus
    /// t = 2^64, or if `n` is too large for the comparison blinding budget
    /// (each party must get at least 2 blind bits; see the
    /// [module documentation](self)).
    pub fn new<R: RngCore + CryptoRng>(
        n: usize,
        par: &Arc<BfvParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        check_parameters(par)?;
        if n < 2 {
            return Err(Error::DefaultError(
                "a committee needs at least 2 parties".to_string(),
            ));
        }
        if BLIND_BITS_BUDGET / n < 2 {
            return Err(Error::DefaultError(format!(
                "committee of {n} parties leaves fewer than 2 comparison blind bits per party"
            )));
        }

        let parties: Vec<Party> = (0..n)
            .map(|_| Party {
                sk: SecretKey::random(par, rng),
            })
            .collect();

        // Protocol 1: collective public key.
        let crp = CommonRandomPoly::new(par, rng)?;
        let pk = PublicKey::from_shares(
            parties
                .iter()
                .map(|p| PublicKeyShare::new(&p.sk, crp.clone(), rng))
                .collect::<Result<Vec<_>>>()?,
        )?;

        // Protocol 2: collective relinearization key (two rounds).
        let crp_vec = CommonRandomPoly::new_vec(par, rng)?;
        let generators = parties
            .iter()
            .map(|p| RelinKeyGenerator::new(&p.sk, &crp_vec, rng))
            .collect::<Result<Vec<_>>>()?;
        let r1 = Arc::new(RelinKeyShare::<R1Aggregated>::from_shares(
            generators
                .iter()
                .map(|g| g.round_1(rng))
                .collect::<Result<Vec<_>>>()?,
        )?);
        let rk = RelinearizationKey::from_shares(
            generators
                .iter()
                .map(|g| g.round_2(&r1, rng))
                .collect::<Result<Vec<_>>>()?,
        )?;

        Ok(Self {
            par: par.clone(),
            parties,
            pk,
            rk,
        })
    }

    /// The collective public key. Anyone may encrypt under it.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    /// A server key wrapping the collective relinearization key, for
    /// installation via [`crate::typed::set_server_key`].
    #[must_use]
    pub fn server_key(&self) -> ServerKey {
        ServerKey::from_relinearization_key(self.rk.clone())
    }

    /// The number of committee parties.
    #[must_use]
    pub fn num_parties(&self) -> usize {
        self.parties.len()
    }

    /// Bits of multiplicative blinding each party contributes to a
    /// comparison.
    #[must_use]
    pub fn blind_bits(&self) -> usize {
        BLIND_BITS_BUDGET / self.parties.len()
    }

    /// Encrypts `value` under the collective public key.
    pub fn encrypt<R: RngCore + CryptoRng>(&self, value: u64, rng: &mut R) -> Result<FheUint64> {
        FheUint64::encrypt_with_public_key(value, &self.pk, rng)
    }

    /// Party `party`'s decryption share for `ct` — one protocol message of
    /// the designated-decryption protocol. Aggregating all N shares (and
    /// only all N: the scheme is N-of-N) yields the plaintext.
    pub fn decryption_share<R: RngCore + CryptoRng>(
        &self,
        party: usize,
        ct: &Arc<Ciphertext>,
        rng: &mut R,
    ) -> Result<DecryptionShare> {
        let p = self
            .parties
            .get(party)
            .ok_or_else(|| Error::DefaultError(format!("no committee party {party}")))?;
        DecryptionShare::new(&p.sk, ct, rng)
    }

    /// Designated decryption: every party contributes a decryption share
    /// and the aggregate reveals the plaintext (to all parties).
    pub fn threshold_decrypt<R: RngCore + CryptoRng>(
        &self,
        ct: &FheUint64,
        rng: &mut R,
    ) -> Result<u64> {
        let ct = Arc::new(ct.ct.clone());
        let pt = crate::bfv::Plaintext::from_shares(
            (0..self.parties.len())
                .map(|i| self.decryption_share(i, &ct, rng))
                .collect::<Result<Vec<_>>>()?,
        )?;
        let v = Vec::<u64>::try_decode(&pt, crate::bfv::Encoding::poly())?;
        v.first().copied().ok_or_else(|| {
            Error::DefaultError("decrypted plaintext has no coefficients".to_string())
        })
    }

    /// Recrypts `ct` to a fresh low-noise encryption of the same value
    /// without revealing that value to any party. See
    /// [`Committee::refresh_with_transcript`] for the protocol and the
    /// [module documentation](self) for what each party learns.
    pub fn refresh<R: RngCore + CryptoRng>(
        &self,
        ct: &FheUint64,
        rng: &mut R,
    ) -> Result<FheUint64> {
        Ok(self.refresh_with_transcript(ct, rng)?.0)
    }

    /// [`Committee::refresh`], also returning the protocol transcript for
    /// leakage auditing.
    ///
    /// Protocol (collective recryption by additive one-time-pad masking):
    /// 1. each party i samples a uniform mask `m_i` and publishes a fresh
    ///    encryption `E(m_i)` under the collective key;
    /// 2. the committee designated-decrypts `ct + sum E(m_i)`, revealing
    ///    only the masked value `v = x + sum m_i (mod 2^64)`;
    /// 3. the fresh ciphertext is `E(v) - sum E(m_i)`: a fresh encryption
    ///    of `v` minus the published mask encryptions, whose noise is that
    ///    of N + 1 fresh encryptions regardless of how worn `ct` was.
    pub fn refresh_with_transcript<R: RngCore + CryptoRng>(
        &self,
        ct: &FheUint64,
        rng: &mut R,
    ) -> Result<(FheUint64, RefreshTranscript)> {
        let masks: Vec<u64> = self.parties.iter().map(|_| rng.next_u64()).collect();
        let enc_masks = masks
            .iter()
            .map(|m| FheUint64::encrypt_with_public_key(*m, &self.pk, rng))
            .collect::<Result<Vec<_>>>()?;

        let mut masked = ct.clone();
        for em in &enc_masks {
            masked += em;
        }
        let revealed = self.threshold_decrypt(&masked, rng)?;

        let mut fresh = FheUint64::encrypt_with_public_key(revealed, &self.pk, rng)?;
        for em in &enc_masks {
            fresh -= em;
        }
        Ok((fresh, RefreshTranscript { masks, revealed }))
    }

    /// Interactive comparison: returns a fresh encryption of 1 if `a >= b`
    /// (as values below [`MAX_COMPARE_OPERAND`]) and of 0 otherwise.
    ///
    /// See [`Committee::compare_ge_with_transcript`] for the protocol and
    /// the [module documentation](self) for the operand bound and what
    /// each party learns.
    pub fn compare_ge<R: RngCore + CryptoRng>(
        &self,
        a: &FheUint64,
        b: &FheUint64,
        rng: &mut R,
    ) -> Result<FheUint64> {
        Ok(self.compare_ge_with_transcript(a, b, rng)?.0)
    }

    /// [`Committee::compare_ge`], also returning the protocol transcript
    /// for leakage auditing.
    ///
    /// Protocol (blinded-difference decryption):
    /// 1. compute `d = a - b` homomorphically; for in-bound operands the
    ///    signed value of `d` is in `(-2^40, 2^40)`;
    /// 2. each party i multiplies the ciphertext by a private odd blind
    ///    `r_i` in `[3, 2^blind_bits)` (a plaintext-scalar multiply);
    /// 3. the committee designated-decrypts the result, revealing only
    ///    `m = (prod r_i) * d (mod 2^64)`, with `|m| < 2^62` so the sign
    ///    of `m` as an `i64` is the sign of `d`;
    /// 4. the result, 1 if `m as i64 >= 0` else 0, is re-encrypted fresh
    ///    under the collective key.
    pub fn compare_ge_with_transcript<R: RngCore + CryptoRng>(
        &self,
        a: &FheUint64,
        b: &FheUint64,
        rng: &mut R,
    ) -> Result<(FheUint64, CompareTranscript)> {
        let bits = self.blind_bits();
        // Odd, in [3, 2^bits): never 1, so each party's blind actually
        // blinds, and the product is odd (nonzero mod 2^64).
        let blinds: Vec<u64> = self
            .parties
            .iter()
            .map(|_| (rng.random_range(1u64..(1 << (bits - 1))) << 1) | 1)
            .collect();

        let mut blinded = (a - b).ct;
        for r in &blinds {
            blinded *= &encode(*r, &self.par)?;
        }
        let revealed = self.threshold_decrypt(&FheUint64 { ct: blinded }, rng)?;

        let ge = u64::from(revealed as i64 >= 0);
        let bit = FheUint64::encrypt_with_public_key(ge, &self.pk, rng)?;
        Ok((bit, CompareTranscript { blinds, revealed }))
    }
}
