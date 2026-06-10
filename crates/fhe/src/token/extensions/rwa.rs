//! The RWA composition, mirroring `ERC7984Rwa.sol`: restrictions +
//! encrypted freezing + pause + an agent role, in one policy object.
//!
//! Pause and restriction checks are public structural `Err`s, exactly
//! like the standalone extensions. [`Rwa::force_transfer`] (agent-only)
//! bypasses pause, restrictions, and the frozen guard but NOT the
//! balance guard — a forced transfer still cannot overdraw, it silently
//! zeroes like any core transfer. [`Rwa::recover`] force-moves a lost
//! wallet's full balance INCLUDING frozen amounts to a recipient and
//! re-freezes the recovered frozen portion there.
//!
//! # Leakage
//!
//! Recovery computes the carried frozen amount as an encrypted
//! `min(frozen, balance)` — one committee comparison (outcome leaked,
//! per the [`crate::gateway`] leakage section) and one select. The
//! frozen value itself is **never threshold-decrypted** during
//! recovery: the committee's whole view of it is the blinded comparison
//! and the masked refreshes, kept in [`RecoverAudit`] entries of
//! [`Rwa::recover_audits`] so the claim is testable. Regular transfers
//! through [`Rwa::transfer`] have the freezable double-guard leakage
//! documented in [`super::freezable`].

use rand::{CryptoRng, RngCore};

use crate::gateway::{CompareTranscript, RefreshTranscript};
use crate::token::{Account, ConfidentialToken, Handle, RefreshPolicy};
use crate::typed::FheUint64;
use crate::typed::safe_math::select;
use crate::{Error, Result};

use super::freezable::Freezable;
use super::restricted::{Restriction, RestrictionMode, Restrictions};

/// The committee's view of one [`Rwa::recover`]: the encrypted-min
/// comparison and the refreshes of the rebuilt ciphertexts. Notably, NO
/// decryption transcript: the recovered frozen amount is never revealed.
pub struct RecoverAudit {
    /// The `balance >= frozen` comparison behind the encrypted min.
    pub min_compare: CompareTranscript,
    /// The refreshes of the recipient's new balance and frozen amount
    /// (empty under [`RefreshPolicy::Never`]).
    pub refreshes: Vec<RefreshTranscript>,
}

/// An RWA token policy: blocklist restrictions, encrypted freezing,
/// pause, and an agent role, composed over one [`ConfidentialToken`].
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::rwa::Rwa;
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
/// const AGENT: u64 = 0;
/// const ALICE: u64 = 1;
/// const BOB: u64 = 2;
/// token.mint(ALICE, 100, &mut rng)?;
///
/// let mut rwa = Rwa::new(AGENT);
/// rwa.pause(AGENT)?;
/// let amount = token.committee().encrypt(10, &mut rng)?;
/// // Paused transfers are public structural errors...
/// assert!(rwa.transfer(&mut token, ALICE, BOB, &amount, &mut rng).is_err());
/// // ...but an agent can still force-transfer.
/// rwa.force_transfer(&mut token, AGENT, ALICE, BOB, &amount, &mut rng)?;
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct Rwa {
    agent: Account,
    paused: bool,
    restrictions: Restrictions,
    freezable: Freezable,
    recover_audits: Vec<RecoverAudit>,
}

impl Rwa {
    /// A fresh RWA policy in blocklist mode, with `agent` holding the
    /// agent (and freezer) role.
    #[must_use]
    pub fn new(agent: Account) -> Self {
        Self {
            agent,
            paused: false,
            restrictions: Restrictions::new(RestrictionMode::Blocklist),
            freezable: Freezable::new(agent),
            recover_audits: Vec::new(),
        }
    }

    /// Whether `account` holds the agent role.
    #[must_use]
    pub fn is_agent(&self, account: Account) -> bool {
        account == self.agent
    }

    /// Whether transfers are currently paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// The composed restriction state.
    #[must_use]
    pub fn restrictions(&self) -> &Restrictions {
        &self.restrictions
    }

    /// The composed frozen ledger (for handle reads and audit access).
    #[must_use]
    pub fn freezable(&self) -> &Freezable {
        &self.freezable
    }

    /// The committee's view of every recovery, for leakage auditing.
    #[must_use]
    pub fn recover_audits(&self) -> &[RecoverAudit] {
        &self.recover_audits
    }

    /// Pauses transfers (agent-only).
    pub fn pause(&mut self, caller: Account) -> Result<()> {
        self.require_agent(caller)?;
        self.paused = true;
        Ok(())
    }

    /// Unpauses transfers (agent-only).
    pub fn unpause(&mut self, caller: Account) -> Result<()> {
        self.require_agent(caller)?;
        self.paused = false;
        Ok(())
    }

    /// Blocks `account` from transferring (agent-only; public state).
    pub fn block_user(&mut self, caller: Account, account: Account) -> Result<()> {
        self.require_agent(caller)?;
        self.restrictions
            .set_restriction(account, Restriction::Blocked);
        Ok(())
    }

    /// Lifts `account`'s block (agent-only; public state).
    pub fn unblock_user(&mut self, caller: Account, account: Account) -> Result<()> {
        self.require_agent(caller)?;
        self.restrictions
            .set_restriction(account, Restriction::Default);
        Ok(())
    }

    /// Sets `account`'s encrypted frozen amount (agent-only). See
    /// [`Freezable::set_confidential_frozen`].
    pub fn set_confidential_frozen(
        &mut self,
        token: &mut ConfidentialToken,
        caller: Account,
        account: Account,
        amount: FheUint64,
    ) -> Result<Handle> {
        self.require_agent(caller)?;
        self.freezable
            .set_confidential_frozen(token, self.freezable.freezer(), account, amount)
    }

    /// A policy-checked transfer: `Err` while paused or for restricted
    /// parties (public checks, before any encrypted work), then the
    /// freezable double-guard transfer.
    pub fn transfer<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        if self.paused {
            return Err(Error::DefaultError("transfers are paused".to_string()));
        }
        self.restrictions.check_transfer(from, to)?;
        self.freezable.transfer(token, from, to, amount, rng)
    }

    /// An agent-only transfer that bypasses pause, restrictions, and the
    /// frozen guard — but NOT the balance guard: a forced transfer of
    /// more than the balance silently zeroes like any core transfer.
    pub fn force_transfer<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        caller: Account,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        self.require_agent(caller)?;
        token.transfer(from, to, amount, rng)
    }

    /// Recovers a lost wallet (agent-only): force-moves `lost`'s FULL
    /// balance — including frozen amounts — to `recipient`, and
    /// re-freezes the recovered frozen portion there. The carried frozen
    /// amount travels encrypted as `min(frozen, balance)` (saturating:
    /// a frozen amount above the balance carries only the balance) and
    /// is never threshold-decrypted; see the
    /// [module documentation](self).
    pub fn recover<R: RngCore + CryptoRng>(
        &mut self,
        token: &mut ConfidentialToken,
        caller: Account,
        lost: Account,
        recipient: Account,
        rng: &mut R,
    ) -> Result<()> {
        self.require_agent(caller)?;
        let lost_handle = token.balances.get(&lost).copied().ok_or_else(|| {
            Error::DefaultError(format!("account {lost} has no balance to recover"))
        })?;
        let lost_balance = token.stored(lost_handle)?.clone();
        let recipient_balance = match token.balances.get(&recipient).copied() {
            Some(h) => token.stored(h)?.clone(),
            None => token.committee.encrypt(0, rng)?,
        };
        let frozen = self.freezable.frozen_ct(token, lost, rng)?;

        // The carried frozen portion: an encrypted min(frozen, balance),
        // via one comparison and one select — never decrypted.
        let (ge, min_compare) =
            token
                .committee
                .compare_ge_with_transcript(&lost_balance, &frozen, rng)?;
        let carried = select(&ge, &frozen, &lost_balance);
        // The full balance moves unguarded: it cannot overdraw itself,
        // and the supply is mint-bounded, so the sum stays in-domain.
        let new_recipient = &recipient_balance + &lost_balance;
        let new_lost = token.committee.encrypt(0, rng)?;
        // Re-freeze at the recipient on top of any existing frozen
        // amount.
        let recipient_frozen = self.freezable.frozen_ct(token, recipient, rng)?;
        let new_frozen = &recipient_frozen + &carried;

        let mut refreshes = Vec::new();
        let (new_recipient, new_frozen) = match token.refresh_policy {
            RefreshPolicy::EveryTransfer => {
                let (b, t_b) = token
                    .committee
                    .refresh_with_transcript(&new_recipient, rng)?;
                let (f, t_f) = token.committee.refresh_with_transcript(&new_frozen, rng)?;
                refreshes.extend([t_b, t_f]);
                (b, f)
            }
            RefreshPolicy::Never => (new_recipient, new_frozen),
        };
        self.recover_audits.push(RecoverAudit {
            min_compare,
            refreshes,
        });

        token.store_balance(recipient, new_recipient);
        token.store_balance(lost, new_lost);
        self.freezable.store_frozen(token, recipient, new_frozen);
        self.freezable.clear_frozen(lost);
        Ok(())
    }

    fn require_agent(&self, caller: Account) -> Result<()> {
        if !self.is_agent(caller) {
            return Err(Error::DefaultError(format!(
                "account {caller} is not an agent"
            )));
        }
        Ok(())
    }
}
