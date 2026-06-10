//! A confidential token service with ERC7984-style core semantics, on top
//! of [`crate::gateway`] and [`crate::typed::safe_math`].
//!
//! Balances and the total supply are [`FheUint64`] ciphertexts encrypted
//! under a committee's collective key and addressed by opaque [`Handle`]s
//! through a minimal ACL, mirroring the `FHE.allow` model of
//! OpenZeppelin's confidential contracts. Mint amounts are public (as in
//! ERC7984 mints); everything after a mint is encrypted.
//!
//! # Never-revert transfers
//!
//! [`ConfidentialToken::transfer`] always completes. On insufficient
//! balance, the transferred amount selects to an encryption of zero and
//! both balances are rebuilt unchanged — the handles rotate, the gateway
//! performs the same comparison and refresh traffic, and the
//! transferred-amount ciphertext exists either way. An observer of the
//! ciphertexts and the call trace cannot distinguish a failed transfer
//! from a zero-amount transfer. (The committee itself learns the guard
//! outcomes, as documented in the [`crate::gateway`] leakage section.)
//!
//! # Refresh policy
//!
//! Every transfer updates both balances through
//! [`crate::typed::safe_math`]'s guarded operations, whose cmux consumes
//! one multiplicative level of the balance per transfer. At the curated
//! [`FheUint64::default_parameters_128`] parameters the budget is two
//! levels: measured empirically (the no-refresh companion test in
//! `tests/confidential_token_e2e.rs`), an unrefreshed balance survives
//! two transfers and decrypts to garbage on the third. The token
//! therefore refreshes every touched balance on **every transfer**
//! ([`RefreshPolicy::EveryTransfer`]), spending one of the two levels per
//! transfer and keeping a full level of measured noise margin — enough
//! that one additional guarded operation on a stale read can never
//! corrupt state. A higher-depth parameter set could justify refreshing
//! every k > 1 transfers; with a 2-level budget there is no safe k > 1.
//!
//! [`RefreshPolicy::Never`] exists to prove the policy is load-bearing:
//! the companion test asserts balances become garbage without refresh.
//!
//! # ACL
//!
//! Each stored ciphertext handle carries an allow-list of accounts.
//! Handles are readable only by allowed accounts
//! ([`ConfidentialToken::ciphertext`],
//! [`ConfidentialToken::decrypt_for`]); an account already on a handle's
//! list may extend it ([`ConfidentialToken::allow`]), mirroring
//! `FHE.allow`'s chain of custody. Balance handles are allowed to their
//! owner; transferred-amount handles to both transfer parties. The total
//! supply is intentionally not ACL'd: mint amounts are public, so the
//! supply is public information already.

use std::collections::{HashMap, HashSet};

use rand::{CryptoRng, RngCore};

use crate::gateway::Committee;
use crate::typed::FheUint64;
use crate::typed::safe_math::{MAX_SAFE_VALUE, select, try_sub};
use crate::{Error, Result};

/// An account identifier. The token does no signature checking — caller
/// authenticity is the embedding application's problem, as it is for a
/// smart contract's `msg.sender`.
pub type Account = u64;

/// An opaque reference to a stored ciphertext, in the style of fhEVM
/// handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u64);

/// When the token recrypts touched balances through the gateway. See the
/// [module documentation](self) for the measured justification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPolicy {
    /// Refresh every touched balance on every transfer (the default and
    /// the only safe policy at the curated depth-2 parameters).
    EveryTransfer,
    /// Never refresh. Balances die of noise after two transfers; exists
    /// so tests can prove the refresh is load-bearing.
    Never,
}

/// A confidential token: encrypted balances under a committee's
/// collective key, with ERC7984-style mint/transfer semantics.
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::typed::{FheUint64, set_server_key};
/// use rand::rng;
///
/// let mut rng = rng();
/// // Toy parameters so the example runs quickly; production code should
/// // use `FheUint64::default_parameters_128()`.
/// let params = FheUint64::parameters(16, &[60, 60, 60, 60])?;
/// let committee = Committee::new(3, &params, &mut rng)?;
/// set_server_key(committee.server_key());
/// let mut token = ConfidentialToken::new(committee, &mut rng)?;
///
/// const ALICE: u64 = 1;
/// const BOB: u64 = 2;
/// token.mint(ALICE, 1000, &mut rng)?;
///
/// let amount = token.committee().encrypt(250, &mut rng)?;
/// token.transfer(ALICE, BOB, &amount, &mut rng)?;
///
/// let alice_balance = token.balance_handle(ALICE).unwrap();
/// assert_eq!(token.decrypt_for(alice_balance, ALICE, &mut rng)?, 750);
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct ConfidentialToken {
    committee: Committee,
    refresh_policy: RefreshPolicy,
    store: HashMap<Handle, FheUint64>,
    acl: HashMap<Handle, HashSet<Account>>,
    balances: HashMap<Account, Handle>,
    total_supply: FheUint64,
    /// Public running total of mints; mint amounts are public, so this
    /// tracks no secret. Used to enforce the safe-math domain bound.
    minted: u64,
    next_handle: u64,
}

impl ConfidentialToken {
    /// Deploys a token under `committee`'s collective key, with the
    /// default [`RefreshPolicy::EveryTransfer`].
    pub fn new<R: RngCore + CryptoRng>(committee: Committee, rng: &mut R) -> Result<Self> {
        Self::with_refresh_policy(committee, RefreshPolicy::EveryTransfer, rng)
    }

    /// Deploys a token with an explicit refresh policy. Production code
    /// has no reason to pass anything but
    /// [`RefreshPolicy::EveryTransfer`]; see the
    /// [module documentation](self).
    pub fn with_refresh_policy<R: RngCore + CryptoRng>(
        committee: Committee,
        refresh_policy: RefreshPolicy,
        rng: &mut R,
    ) -> Result<Self> {
        let total_supply = committee.encrypt(0, rng)?;
        Ok(Self {
            committee,
            refresh_policy,
            store: HashMap::new(),
            acl: HashMap::new(),
            balances: HashMap::new(),
            total_supply,
            minted: 0,
            next_handle: 0,
        })
    }

    /// The committee this token deploys under.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// The encrypted total supply. Not ACL'd: mint amounts are public, so
    /// the supply is publicly derivable anyway.
    #[must_use]
    pub fn total_supply(&self) -> &FheUint64 {
        &self.total_supply
    }

    /// The current balance handle of `account`, if it has ever held
    /// tokens.
    #[must_use]
    pub fn balance_handle(&self, account: Account) -> Option<Handle> {
        self.balances.get(&account).copied()
    }

    /// Whether `account` may read the ciphertext behind `handle`.
    #[must_use]
    pub fn is_allowed(&self, handle: Handle, account: Account) -> bool {
        self.acl.get(&handle).is_some_and(|s| s.contains(&account))
    }

    /// Grants `grantee` read access to `handle`. `grantor` must already
    /// be allowed on the handle (chain of custody, as with `FHE.allow`).
    pub fn allow(&mut self, handle: Handle, grantor: Account, grantee: Account) -> Result<()> {
        if !self.is_allowed(handle, grantor) {
            return Err(Error::DefaultError(format!(
                "account {grantor} is not allowed on handle {handle:?}"
            )));
        }
        self.acl.entry(handle).or_default().insert(grantee);
        Ok(())
    }

    /// ACL-checked ciphertext read.
    pub fn ciphertext(&self, handle: Handle, caller: Account) -> Result<&FheUint64> {
        if !self.is_allowed(handle, caller) {
            return Err(Error::DefaultError(format!(
                "account {caller} is not allowed on handle {handle:?}"
            )));
        }
        self.store.get(&handle).ok_or_else(|| {
            Error::DefaultError(format!("no ciphertext stored under handle {handle:?}"))
        })
    }

    /// ACL-checked threshold decryption of `handle` on behalf of
    /// `caller`. The decrypted value becomes committee-public (see the
    /// [`crate::gateway`] leakage section).
    pub fn decrypt_for<R: RngCore + CryptoRng>(
        &self,
        handle: Handle,
        caller: Account,
        rng: &mut R,
    ) -> Result<u64> {
        let ct = self.ciphertext(handle, caller)?;
        self.committee.threshold_decrypt(ct, rng)
    }

    /// Mints `amount` (public, as in ERC7984 mints) to `to`, returning
    /// `to`'s new balance handle.
    ///
    /// Fails if the total minted supply would exceed the safe-math domain
    /// bound [`MAX_SAFE_VALUE`] — the bound every later encrypted
    /// comparison depends on, and checkable here because mint amounts are
    /// public.
    pub fn mint<R: RngCore + CryptoRng>(
        &mut self,
        to: Account,
        amount: u64,
        rng: &mut R,
    ) -> Result<Handle> {
        let minted = self
            .minted
            .checked_add(amount)
            .filter(|m| *m <= MAX_SAFE_VALUE);
        let Some(minted) = minted else {
            return Err(Error::DefaultError(format!(
                "minting {amount} would push total supply over MAX_SAFE_VALUE"
            )));
        };
        self.minted = minted;

        let enc_amount = self.committee.encrypt(amount, rng)?;
        let new_balance = match self.balances.get(&to).copied() {
            Some(h) => self.stored(h)? + &enc_amount,
            None => enc_amount.clone(),
        };
        self.total_supply = &self.total_supply + &enc_amount;
        Ok(self.store_balance(to, new_balance))
    }

    /// Transfers an encrypted amount from `from` to `to`. **Never
    /// rejects** on insufficient balance: the call completes, the
    /// transferred amount selects to an encryption of zero, and both
    /// balances are rebuilt unchanged. Returns the handle of the
    /// transferred-amount ciphertext (allowed to both parties).
    ///
    /// `amount` should be a fresh encryption under the committee's key,
    /// of a value within the safe-math domain (`<=` [`MAX_SAFE_VALUE`]).
    /// Errors only on structural problems (unknown sender); an observer
    /// cannot distinguish a failed transfer from a zero-amount one.
    ///
    /// # Panics
    /// Panics if no server key is installed on this thread (see
    /// [`crate::typed::set_server_key`]).
    pub fn transfer<R: RngCore + CryptoRng>(
        &mut self,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        let from_handle = self.balances.get(&from).copied().ok_or_else(|| {
            Error::DefaultError(format!("account {from} has no balance to transfer from"))
        })?;
        let from_balance = self.stored(from_handle)?.clone();
        let to_balance = match self.balances.get(&to).copied() {
            Some(h) => self.stored(h)?.clone(),
            None => self.committee.encrypt(0, rng)?,
        };

        // Guarded sender update: on insufficient balance the subtraction
        // rolls back and the success bit encrypts 0.
        let (success, new_from) = try_sub(&self.committee, &from_balance, amount, rng)?;
        // The actually-transferred amount: `amount` on success, 0 on
        // failure — indistinguishable ciphertexts either way.
        let zero = self.committee.encrypt(0, rng)?;
        let actual = select(&success, amount, &zero);
        // Guarded receiver update with the same success bit (NOT an
        // independent try_add: its overflow guard could in principle
        // disagree and break supply conservation; minted supply is bounded
        // at mint time, so the receiver sum cannot leave the domain).
        let (_, new_to) = try_add_with_bit(&self.committee, &to_balance, &actual, &success, rng)?;

        let (new_from, new_to) = match self.refresh_policy {
            RefreshPolicy::EveryTransfer => (
                self.committee.refresh(&new_from, rng)?,
                self.committee.refresh(&new_to, rng)?,
            ),
            RefreshPolicy::Never => (new_from, new_to),
        };

        self.store_balance(from, new_from);
        self.store_balance(to, new_to);

        let amount_handle = self.store_ciphertext(actual);
        self.acl
            .entry(amount_handle)
            .or_default()
            .extend([from, to]);
        Ok(amount_handle)
    }

    /// The ciphertext behind a handle the token itself created; an absent
    /// entry is internal-state corruption, reported rather than unwrapped.
    fn stored(&self, handle: Handle) -> Result<&FheUint64> {
        self.store.get(&handle).ok_or_else(|| {
            Error::DefaultError(format!("no ciphertext stored under handle {handle:?}"))
        })
    }

    /// Stores `ct` as `account`'s new balance, allowed to its owner.
    fn store_balance(&mut self, account: Account, ct: FheUint64) -> Handle {
        let handle = self.store_ciphertext(ct);
        self.acl.entry(handle).or_default().insert(account);
        self.balances.insert(account, handle);
        handle
    }

    fn store_ciphertext(&mut self, ct: FheUint64) -> Handle {
        let handle = Handle(self.next_handle);
        self.next_handle += 1;
        self.store.insert(handle, ct);
        handle
    }
}

/// `try_add`'s guarded update with an externally supplied success bit
/// instead of a fresh overflow comparison: `bit*(a+b) + (1-bit)*a`.
fn try_add_with_bit<R: RngCore + CryptoRng>(
    committee: &Committee,
    a: &FheUint64,
    b: &FheUint64,
    bit: &FheUint64,
    rng: &mut R,
) -> Result<(FheUint64, FheUint64)> {
    let one = committee.encrypt(1, rng)?;
    let not_bit = &one - bit;
    let sum = a + b;
    let result = &(bit * &sum) + &(&not_bit * a);
    Ok((bit.clone(), result))
}
