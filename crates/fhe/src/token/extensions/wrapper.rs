//! A public↔confidential wrapper, mirroring `ERC7984ERC20Wrapper.sol`
//! adapted to this kit: there is no ERC20 here, so the public side is a
//! [`PublicLedger`] of plain `u64` balances owned by the module.
//!
//! [`PublicLedger::wrap`] moves public balance into a confidential mint;
//! unwrapping is two-phase ([`PublicLedger::request_unwrap`] then
//! [`PublicLedger::finalize_unwrap`]) because the amount must be
//! threshold-decrypted by the committee before the public ledger can be
//! credited.
//!
//! # Leakage
//!
//! **An unwrap reveals its amount, by design**: the finalize step
//! threshold-decrypts the requested amount (every committee party learns
//! it — the [`crate::gateway`] decryption leakage) and then decrypts the
//! funds-check outcome to decide publicly whether the unwrap succeeds.
//! Both land in [`PublicLedger::audit_log`] as [`UnwrapAudit`] entries.
//! Wrap amounts are public to begin with (they are public-ledger moves,
//! like ERC7984 mints).
//!
//! # Failed unwraps
//!
//! `finalize_unwrap` of a request whose account lacks the encrypted
//! funds returns an `Err` and credits **nothing** — the documented
//! choice between "credit 0" and "fail". The encrypted balance is left
//! untouched; only the revealed amount and the failed funds-check are
//! observable (and logged).
//!
//! # Conservation
//!
//! Public total + confidential total supply is constant across
//! wrap/unwrap (tested); only [`PublicLedger::credit`], the public-side
//! faucet, changes the combined total.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::gateway::{CompareTranscript, RefreshTranscript};
use crate::token::{Account, ConfidentialToken, Handle, RefreshPolicy};
use crate::typed::FheUint64;
use crate::typed::safe_math::MAX_SAFE_VALUE;
use crate::{Error, Result};

/// The committee's view of one [`PublicLedger::finalize_unwrap`]: the
/// revealed amount (by design), the funds-check transcript, and the
/// balance refresh on success.
pub struct UnwrapAudit {
    /// The threshold-decrypted unwrap amount, revealed to every party.
    pub amount: u64,
    /// The funds check (`balance >= amount`), whose outcome is also
    /// decrypted (the success of an unwrap is public).
    pub guard_compare: CompareTranscript,
    /// The refresh of the debited balance (empty on a failed unwrap or
    /// under [`RefreshPolicy::Never`]).
    pub refreshes: Vec<RefreshTranscript>,
}

/// A pending unwrap: the account and the still-encrypted amount, waiting
/// for the committee's finalize step.
pub struct UnwrapRequest {
    account: Account,
    amount: FheUint64,
}

impl UnwrapRequest {
    /// The account whose confidential balance will be debited.
    #[must_use]
    pub fn account(&self) -> Account {
        self.account
    }
}

/// Plain public balances, wrappable into (and unwrappable out of) a
/// [`ConfidentialToken`].
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::wrapper::PublicLedger;
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
/// let mut ledger = PublicLedger::new();
/// ledger.credit(ALICE, 1000);
/// ledger.wrap(&mut token, ALICE, 400, &mut rng)?;
/// assert_eq!(ledger.balance(ALICE), 600);
///
/// let amount = token.committee().encrypt(150, &mut rng)?;
/// let request = ledger.request_unwrap(ALICE, amount);
/// // The finalize step threshold-decrypts the amount (by design).
/// assert_eq!(ledger.finalize_unwrap(&mut token, request, &mut rng)?, 150);
/// assert_eq!(ledger.balance(ALICE), 750);
/// # Ok::<(), fhe::Error>(())
/// ```
#[derive(Default)]
pub struct PublicLedger {
    balances: HashMap<Account, u64>,
    audit_log: Vec<UnwrapAudit>,
}

impl PublicLedger {
    /// An empty public ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `account`'s public balance.
    #[must_use]
    pub fn balance(&self, account: Account) -> u64 {
        self.balances.get(&account).copied().unwrap_or_default()
    }

    /// The total public supply.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.balances.values().sum()
    }

    /// The committee's view of every finalized unwrap, for leakage
    /// auditing.
    #[must_use]
    pub fn audit_log(&self) -> &[UnwrapAudit] {
        &self.audit_log
    }

    /// Credits `account`'s public balance — the public-side faucet (the
    /// stand-in for receiving the underlying public token). The only
    /// operation that changes the combined public + confidential total.
    pub fn credit(&mut self, account: Account, amount: u64) {
        *self.balances.entry(account).or_default() += amount;
    }

    /// Moves `amount` from `account`'s public balance into a
    /// confidential mint, returning the new confidential balance handle.
    /// Errs publicly if the public balance is insufficient (public
    /// funds, public check).
    pub fn wrap<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        account: Account,
        amount: u64,
        rng: &mut R,
    ) -> Result<Handle> {
        let balance = self.balance(account);
        if balance < amount {
            return Err(Error::DefaultError(format!(
                "account {account} has public balance {balance}, cannot wrap {amount}"
            )));
        }
        let handle = token.mint(account, amount, rng)?;
        self.balances.insert(account, balance - amount);
        Ok(handle)
    }

    /// Phase one of an unwrap: records the account and the encrypted
    /// amount. Nothing is decrypted and no state changes until
    /// [`Self::finalize_unwrap`].
    #[must_use]
    pub fn request_unwrap(&self, account: Account, amount: FheUint64) -> UnwrapRequest {
        UnwrapRequest { account, amount }
    }

    /// Phase two of an unwrap: the committee threshold-decrypts the
    /// requested amount (**revealing it — the documented leakage**) and
    /// the funds-check outcome. On success the confidential balance is
    /// debited and the public ledger credited; if the account lacks the
    /// encrypted funds this is an `Err` and credits nothing (the
    /// documented failure semantics). Returns the revealed amount.
    pub fn finalize_unwrap<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        request: UnwrapRequest,
        rng: &mut R,
    ) -> Result<u64> {
        let UnwrapRequest { account, amount } = request;
        let balance_handle = token
            .balances
            .get(&account)
            .copied()
            .ok_or_else(|| Error::DefaultError(format!("account {account} has no balance")))?;
        let balance = token.stored(balance_handle)?.clone();

        // The documented reveal: every party learns the unwrap amount.
        let revealed = token.committee.threshold_decrypt(&amount, rng)?;
        if revealed > MAX_SAFE_VALUE {
            return Err(Error::DefaultError(format!(
                "unwrap amount {revealed} is outside the safe-math domain"
            )));
        }

        let (success, guard_compare) = token
            .committee
            .compare_ge_with_transcript(&balance, &amount, rng)?;
        // The success of an unwrap is public (the public ledger is
        // credited or not), so decrypting the guard outcome leaks
        // nothing extra.
        let succeeded = token.committee.threshold_decrypt(&success, rng)? == 1;
        if !succeeded {
            self.audit_log.push(UnwrapAudit {
                amount: revealed,
                guard_compare,
                refreshes: Vec::new(),
            });
            return Err(Error::DefaultError(format!(
                "account {account} lacks the confidential funds to unwrap {revealed}"
            )));
        }

        // Plain (additive) debit: the guard outcome is already public,
        // so no cmux is needed and the balance spends no level here.
        let new_balance = &balance - &amount;
        let mut refreshes = Vec::new();
        let new_balance = match token.refresh_policy {
            RefreshPolicy::EveryTransfer => {
                let (fresh, t) = token.committee.refresh_with_transcript(&new_balance, rng)?;
                refreshes.push(t);
                fresh
            }
            RefreshPolicy::Never => new_balance,
        };
        self.audit_log.push(UnwrapAudit {
            amount: revealed,
            guard_compare,
            refreshes,
        });
        token.store_balance(account, new_balance);
        token.total_supply = &token.total_supply - &amount;
        token.minted -= revealed;
        self.credit(account, revealed);
        Ok(revealed)
    }
}
