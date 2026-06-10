//! Per-account observers, mirroring `ERC7984ObserverAccess.sol`.
//!
//! From the moment an observer is set for an account, every NEW handle
//! that account's activity creates through this extension — its rotated
//! balance handles, and the transferred-amount handles of transfers it
//! participates in — is also ACL-allowed to the observer.
//!
//! Removing the observer stops future grants but does **not** revoke
//! past ones (the OZ semantics): handles granted while the observer was
//! set keep decrypting for it forever. The ACL has no revocation, so an
//! observer's access to history is permanent by construction.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};

use crate::Result;
use crate::token::{Account, ConfidentialToken, Handle};
use crate::typed::FheUint64;

/// Per-account observer registry granting observers access to new
/// handles.
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::observer::Observers;
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
/// const EVE: u64 = 3;
/// token.mint(ALICE, 100, &mut rng)?;
///
/// let mut observers = Observers::new();
/// observers.set_observer(ALICE, EVE);
///
/// let amount = token.committee().encrypt(10, &mut rng)?;
/// let amount_handle = observers.transfer(&mut token, ALICE, BOB, &amount, &mut rng)?;
/// // Eve sees the transferred amount and alice's rotated balance.
/// assert_eq!(token.decrypt_for(amount_handle, EVE, &mut rng)?, 10);
/// let alice_balance = token.balance_handle(ALICE).unwrap();
/// assert_eq!(token.decrypt_for(alice_balance, EVE, &mut rng)?, 90);
/// # Ok::<(), fhe::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct Observers {
    observers: HashMap<Account, Account>,
}

impl Observers {
    /// An empty registry: no account is observed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `observer` as `account`'s observer, replacing any previous
    /// one. Only affects handles created from now on.
    pub fn set_observer(&mut self, account: Account, observer: Account) {
        self.observers.insert(account, observer);
    }

    /// Removes `account`'s observer. Stops future grants; handles
    /// already granted stay readable by the old observer (no
    /// revocation, the documented OZ semantics).
    pub fn remove_observer(&mut self, account: Account) {
        self.observers.remove(&account);
    }

    /// `account`'s current observer, if any.
    #[must_use]
    pub fn observer(&self, account: Account) -> Option<Account> {
        self.observers.get(&account).copied()
    }

    /// [`ConfidentialToken::transfer`], then grants each party's
    /// observer access to the new handles of that party's activity: the
    /// party's rotated balance handle and the transferred-amount handle.
    pub fn transfer<R: RngCore + CryptoRng>(
        &self,
        token: &mut ConfidentialToken,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut R,
    ) -> Result<Handle> {
        let amount_handle = token.transfer(from, to, amount, rng)?;
        for party in [from, to] {
            if let Some(observer) = self.observer(party) {
                // The party is allowed on both new handles, so it can
                // chain-of-custody them to its observer.
                let balance = token.balance_handle(party).ok_or_else(|| {
                    crate::Error::DefaultError(format!(
                        "account {party} has no balance handle after transfer"
                    ))
                })?;
                token.allow(balance, party, observer)?;
                token.allow(amount_handle, party, observer)?;
            }
        }
        Ok(amount_handle)
    }

    /// [`ConfidentialToken::mint`], then grants the recipient's observer
    /// access to the new balance handle.
    pub fn mint<R: RngCore + CryptoRng>(
        &self,
        token: &mut ConfidentialToken,
        to: Account,
        amount: u64,
        rng: &mut R,
    ) -> Result<Handle> {
        let balance = token.mint(to, amount, rng)?;
        if let Some(observer) = self.observer(to) {
            token.allow(balance, to, observer)?;
        }
        Ok(balance)
    }
}
