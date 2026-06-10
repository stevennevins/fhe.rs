//! Per-account transfer restrictions, mirroring `ERC7984Restricted.sol`.
//!
//! Restriction state is **public, by design**: like the Solidity
//! original, [`Restrictions::set_restriction`] writes plain state and a
//! restricted party makes [`Restrictions::transfer`] return a structural
//! `Err` before any encrypted work happens — no new handles are created
//! and no committee comparison runs. Restriction status and its
//! enforcement are intentionally visible to every observer; do not put
//! anything secret in them.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::token::{Account, ConfidentialToken, Handle};
use crate::typed::FheUint64;
use crate::{Error, Result};

/// How unlisted accounts are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictionMode {
    /// Accounts are allowed unless explicitly [`Restriction::Blocked`].
    Blocklist,
    /// Accounts are blocked unless explicitly [`Restriction::Allowed`].
    Allowlist,
}

/// One account's restriction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Restriction {
    /// No explicit state; the [`RestrictionMode`] decides.
    #[default]
    Default,
    /// Explicitly blocked, in either mode.
    Blocked,
    /// Explicitly allowed, in either mode.
    Allowed,
}

/// Public per-account restriction state gating transfers.
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::restricted::{Restriction, RestrictionMode, Restrictions};
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
/// token.mint(ALICE, 100, &mut rng)?;
///
/// let mut restrictions = Restrictions::new(RestrictionMode::Blocklist);
/// restrictions.set_restriction(BOB, Restriction::Blocked);
///
/// let amount = token.committee().encrypt(10, &mut rng)?;
/// // A blocked recipient is a public, structural error.
/// assert!(restrictions.transfer(&mut token, ALICE, BOB, &amount, &mut rng).is_err());
///
/// restrictions.set_restriction(BOB, Restriction::Default);
/// restrictions.transfer(&mut token, ALICE, BOB, &amount, &mut rng)?;
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct Restrictions {
    mode: RestrictionMode,
    accounts: HashMap<Account, Restriction>,
}

impl Restrictions {
    /// An empty restriction list under `mode`.
    #[must_use]
    pub fn new(mode: RestrictionMode) -> Self {
        Self {
            mode,
            accounts: HashMap::new(),
        }
    }

    /// The mode unlisted accounts fall back to.
    #[must_use]
    pub fn mode(&self) -> RestrictionMode {
        self.mode
    }

    /// `account`'s explicit restriction state.
    #[must_use]
    pub fn restriction(&self, account: Account) -> Restriction {
        self.accounts.get(&account).copied().unwrap_or_default()
    }

    /// Sets `account`'s restriction state (public state, public effect).
    pub fn set_restriction(&mut self, account: Account, restriction: Restriction) {
        self.accounts.insert(account, restriction);
    }

    /// Whether `account` may currently send or receive transfers.
    #[must_use]
    pub fn is_user_allowed(&self, account: Account) -> bool {
        match self.restriction(account) {
            Restriction::Blocked => false,
            Restriction::Allowed => true,
            Restriction::Default => self.mode == RestrictionMode::Blocklist,
        }
    }

    /// Errs if either transfer party is restricted. Public check, run
    /// before any encrypted work.
    pub fn check_transfer(&self, from: Account, to: Account) -> Result<()> {
        if !self.is_user_allowed(from) {
            return Err(Error::DefaultError(format!("account {from} is restricted")));
        }
        if !self.is_user_allowed(to) {
            return Err(Error::DefaultError(format!("account {to} is restricted")));
        }
        Ok(())
    }

    /// [`ConfidentialToken::transfer`] gated by [`Self::check_transfer`].
    /// A restricted party is a structural `Err` before any encrypted
    /// work: no handles are created and no committee comparison runs.
    pub fn transfer<R: RngCore + CryptoRng>(
        &self,
        token: &mut ConfidentialToken,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        self.check_transfer(from, to)?;
        token.transfer(from, to, amount, rng)
    }
}
