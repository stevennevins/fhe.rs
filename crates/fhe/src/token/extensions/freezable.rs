//! Encrypted per-account frozen amounts, mirroring `ERC7984Freezable.sol`.
//!
//! A freezer role sets an encrypted frozen amount per account
//! ([`Freezable::set_confidential_frozen`]); transfers through
//! [`Freezable::transfer`] are guarded by the **available** balance
//! `available = balance − frozen` instead of the raw balance. The guard
//! is branch-free: a transfer exceeding the available amount selects to
//! zero exactly like an insufficient-balance transfer in the core token,
//! indistinguishable to observers of ciphertexts and call traces. Frozen
//! amounts above the balance saturate (`available = 0`), they never
//! underflow.
//!
//! # Circuit and depth
//!
//! The freezable transfer uses the **combined-guard** circuit (variant
//! (a) of the kit's depth-budget analysis): a single success bit
//! `success = (available >= amount)`, where the plain balance check is
//! implied by `available <= balance`. The available amount is built
//! branch-free as `select(balance >= frozen, balance − frozen, 0)`,
//! which costs one multiplicative level — but only on the *guard input*,
//! which the interactive comparison consumes; the stored sender balance
//! still passes through exactly one cmux, the same level cost as a core
//! transfer. The depth audit in `tests/freezable_depth_audit.rs` pins
//! this at the curated production parameters.
//!
//! # Leakage
//!
//! A freezable transfer performs **two** committee comparisons instead
//! of the core transfer's one, and the committee learns both outcomes
//! (the [`crate::gateway`] leakage section): whether the balance covers
//! the frozen amount, and whether the available amount covers the
//! transfer. Both transcripts are kept in
//! [`FreezableTransferAudit`] entries of [`Freezable::audit_log`] so the
//! claims can be audited; [`Freezable::confidential_available`] performs
//! the first comparison on its own and logs it in
//! [`Freezable::available_compares`].

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::gateway::{CompareTranscript, RefreshTranscript};
use crate::token::{Account, ConfidentialToken, Handle, RefreshPolicy};
use crate::typed::FheUint64;
use crate::typed::safe_math::{cmux, select};
use crate::{Error, Result};

/// The committee's view of one freezable transfer: both comparison
/// transcripts and the refreshes of the touched balances.
pub struct FreezableTransferAudit {
    /// The saturation guard (`balance >= frozen`) behind the available
    /// amount.
    pub available_compare: CompareTranscript,
    /// The transfer guard (`available >= amount`).
    pub guard_compare: CompareTranscript,
    /// The refreshes of the touched balances (empty under
    /// [`RefreshPolicy::Never`]).
    pub refreshes: Vec<RefreshTranscript>,
}

/// Encrypted frozen amounts gating transfers by available balance.
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::freezable::Freezable;
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
/// const FREEZER: u64 = 0;
/// const ALICE: u64 = 1;
/// const BOB: u64 = 2;
/// token.mint(ALICE, 1000, &mut rng)?;
///
/// let mut freezable = Freezable::new(FREEZER);
/// let frozen = token.committee().encrypt(600, &mut rng)?;
/// freezable.set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)?;
///
/// // 401 exceeds the available 400: silently selects to zero.
/// let amount = token.committee().encrypt(401, &mut rng)?;
/// let handle = freezable.transfer(&mut token, ALICE, BOB, &amount, &mut rng)?;
/// assert_eq!(token.decrypt_for(handle, ALICE, &mut rng)?, 0);
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct Freezable {
    freezer: Account,
    frozen: HashMap<Account, Handle>,
    audit_log: Vec<FreezableTransferAudit>,
    available_compares: Vec<CompareTranscript>,
}

impl Freezable {
    /// An empty frozen ledger whose amounts only `freezer` may set.
    #[must_use]
    pub fn new(freezer: Account) -> Self {
        Self {
            freezer,
            frozen: HashMap::new(),
            audit_log: Vec::new(),
            available_compares: Vec::new(),
        }
    }

    /// The account allowed to set frozen amounts.
    #[must_use]
    pub fn freezer(&self) -> Account {
        self.freezer
    }

    /// The committee's view of every freezable transfer so far, for
    /// leakage auditing.
    #[must_use]
    pub fn audit_log(&self) -> &[FreezableTransferAudit] {
        &self.audit_log
    }

    /// The saturation-guard transcripts of standalone
    /// [`Self::confidential_available`] queries.
    #[must_use]
    pub fn available_compares(&self) -> &[CompareTranscript] {
        &self.available_compares
    }

    /// Sets `account`'s encrypted frozen amount, returning its handle
    /// (allowed to the account and the freezer). Only the freezer may
    /// call this. Amounts above the balance are fine: the available
    /// amount saturates to zero rather than underflowing.
    pub fn set_confidential_frozen(
        &mut self,
        token: &mut ConfidentialToken,
        caller: Account,
        account: Account,
        amount: FheUint64,
    ) -> Result<Handle> {
        if caller != self.freezer {
            return Err(Error::DefaultError(format!(
                "account {caller} is not the freezer"
            )));
        }
        Ok(self.store_frozen(token, account, amount))
    }

    /// Stores `amount` as `account`'s frozen ciphertext (no role check;
    /// the public entry point is [`Self::set_confidential_frozen`]).
    pub(crate) fn store_frozen(
        &mut self,
        token: &mut ConfidentialToken,
        account: Account,
        amount: FheUint64,
    ) -> Handle {
        let handle = token.store_ciphertext(amount);
        token
            .acl
            .entry(handle)
            .or_default()
            .extend([account, self.freezer]);
        self.frozen.insert(account, handle);
        handle
    }

    /// Drops `account`'s frozen entry (back to an implicit zero).
    pub(crate) fn clear_frozen(&mut self, account: Account) {
        self.frozen.remove(&account);
    }

    /// `account`'s current frozen-amount handle, if one was ever set.
    #[must_use]
    pub fn confidential_frozen(&self, account: Account) -> Option<Handle> {
        self.frozen.get(&account).copied()
    }

    /// Computes `account`'s available amount (`balance − frozen`,
    /// saturating at zero) and stores it under a fresh handle allowed to
    /// the account. Performs one committee comparison, logged in
    /// [`Self::available_compares`].
    pub fn confidential_available<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        account: Account,
        rng: &mut R,
    ) -> Result<Handle> {
        let balance_handle = token
            .balances
            .get(&account)
            .copied()
            .ok_or_else(|| Error::DefaultError(format!("account {account} has no balance")))?;
        let balance = token.stored(balance_handle)?.clone();
        let frozen = self.frozen_ct(token, account, rng)?;
        let (available, compare) = available_with_transcript(token, &balance, &frozen, rng)?;
        self.available_compares.push(compare);
        let handle = token.store_ciphertext(available);
        token.acl.entry(handle).or_default().insert(account);
        Ok(handle)
    }

    /// Transfers an encrypted amount guarded by the **available**
    /// balance: like [`ConfidentialToken::transfer`] this never rejects
    /// on funds — a transfer exceeding `balance − frozen` selects to
    /// zero, indistinguishable from a zero-amount transfer — but the
    /// guard is `available >= amount` (the combined-guard circuit; see
    /// the [module documentation](self)). Returns the handle of the
    /// transferred-amount ciphertext (allowed to both parties).
    pub fn transfer<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        let from_handle = token.balances.get(&from).copied().ok_or_else(|| {
            Error::DefaultError(format!("account {from} has no balance to transfer from"))
        })?;
        let from_balance = token.stored(from_handle)?.clone();
        let to_balance = match token.balances.get(&to).copied() {
            Some(h) => token.stored(h)?.clone(),
            None => token.committee.encrypt(0, rng)?,
        };
        let frozen = self.frozen_ct(token, from, rng)?;

        // Variant (a), the combined guard: success = (available >=
        // amount) alone — available <= balance makes the plain balance
        // check redundant. The sender balance still passes through
        // exactly one cmux, as in the core transfer.
        let (available, available_compare) =
            available_with_transcript(token, &from_balance, &frozen, rng)?;
        let (success, guard_compare) = token
            .committee
            .compare_ge_with_transcript(&available, amount, rng)?;
        let new_from = cmux(
            &token.committee,
            &success,
            &(&from_balance - amount),
            &from_balance,
            rng,
        )?;
        let zero = token.committee.encrypt(0, rng)?;
        let actual = select(&success, amount, &zero);
        let new_to = cmux(
            &token.committee,
            &success,
            &(&to_balance + &actual),
            &to_balance,
            rng,
        )?;

        let mut refreshes = Vec::new();
        let (new_from, new_to) = match token.refresh_policy {
            RefreshPolicy::EveryTransfer => {
                let (new_from, t_from) = token.committee.refresh_with_transcript(&new_from, rng)?;
                let (new_to, t_to) = token.committee.refresh_with_transcript(&new_to, rng)?;
                refreshes.extend([t_from, t_to]);
                (new_from, new_to)
            }
            RefreshPolicy::Never => (new_from, new_to),
        };
        self.audit_log.push(FreezableTransferAudit {
            available_compare,
            guard_compare,
            refreshes,
        });

        token.store_balance(from, new_from);
        token.store_balance(to, new_to);

        let amount_handle = token.store_ciphertext(actual);
        token
            .acl
            .entry(amount_handle)
            .or_default()
            .extend([from, to]);
        Ok(amount_handle)
    }

    /// `account`'s frozen ciphertext, or a fresh encryption of zero if
    /// none was ever set.
    pub(crate) fn frozen_ct<R: RngCore + CryptoRng>(
        &self,
        token: &ConfidentialToken,
        account: Account,
        rng: &mut R,
    ) -> Result<FheUint64> {
        match self.frozen.get(&account).copied() {
            Some(h) => Ok(token.stored(h)?.clone()),
            None => token.committee.encrypt(0, rng),
        }
    }
}

/// `balance − frozen`, saturating at zero, with the saturation guard's
/// transcript: `select(balance >= frozen, balance − frozen, 0)`.
fn available_with_transcript<R: RngCore + CryptoRng>(
    token: &ConfidentialToken,
    balance: &FheUint64,
    frozen: &FheUint64,
    rng: &mut R,
) -> Result<(FheUint64, CompareTranscript)> {
    let (ge, compare) = token
        .committee
        .compare_ge_with_transcript(balance, frozen, rng)?;
    let zero = token.committee.encrypt(0, rng)?;
    let available = select(&ge, &(balance - frozen), &zero);
    Ok((available, compare))
}
