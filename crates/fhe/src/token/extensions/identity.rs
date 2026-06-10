//! Recipient identity verification, mirroring `ERC7984IdentityCheck.sol`.
//!
//! An [`IdentityRegistry`] answers "is this account verified?" and an
//! [`IdentityCheck`] gates transfers and mints on the RECIPIENT being
//! verified. Like the Solidity original the check is public: an
//! unverified recipient is a structural `Err` before any encrypted work,
//! so verification status and its enforcement are intentionally visible.

use std::collections::HashSet;

use rand::{CryptoRng, RngCore};

use crate::token::{Account, ConfidentialToken, Handle};
use crate::typed::FheUint64;
use crate::{Error, Result};

/// A pluggable identity registry (an ERC-3643-style identity oracle in
/// the Solidity stack).
pub trait IdentityRegistry {
    /// Whether `account` has a verified identity.
    fn is_verified(&self, account: Account) -> bool;
}

/// An in-memory [`IdentityRegistry`] for tests and examples.
#[derive(Debug, Default)]
pub struct InMemoryIdentityRegistry {
    verified: HashSet<Account>,
}

impl InMemoryIdentityRegistry {
    /// An empty registry: no account is verified.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `account` verified or unverified.
    pub fn set_verified(&mut self, account: Account, verified: bool) {
        if verified {
            self.verified.insert(account);
        } else {
            self.verified.remove(&account);
        }
    }
}

impl IdentityRegistry for InMemoryIdentityRegistry {
    fn is_verified(&self, account: Account) -> bool {
        self.verified.contains(&account)
    }
}

/// Gates transfers and mints on the recipient being verified in an
/// [`IdentityRegistry`].
///
/// ```rust
/// use fhe::gateway::Committee;
/// use fhe::token::ConfidentialToken;
/// use fhe::token::extensions::identity::{IdentityCheck, InMemoryIdentityRegistry};
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
/// let mut check = IdentityCheck::new(InMemoryIdentityRegistry::new());
/// // Minting to an unverified recipient is a public, structural error.
/// assert!(check.mint(&mut token, ALICE, 100, &mut rng).is_err());
///
/// check.registry_mut().set_verified(ALICE, true);
/// check.mint(&mut token, ALICE, 100, &mut rng)?;
/// # Ok::<(), fhe::Error>(())
/// ```
pub struct IdentityCheck<R: IdentityRegistry> {
    registry: R,
}

impl<R: IdentityRegistry> IdentityCheck<R> {
    /// Gates on `registry`.
    pub fn new(registry: R) -> Self {
        Self { registry }
    }

    /// The underlying registry.
    pub fn registry(&self) -> &R {
        &self.registry
    }

    /// The underlying registry, mutably.
    pub fn registry_mut(&mut self) -> &mut R {
        &mut self.registry
    }

    /// Errs if `to` is not verified. Public check, run before any
    /// encrypted work.
    pub fn check_recipient(&self, to: Account) -> Result<()> {
        if !self.registry.is_verified(to) {
            return Err(Error::DefaultError(format!(
                "account {to} has no verified identity"
            )));
        }
        Ok(())
    }

    /// [`ConfidentialToken::transfer`] gated on the recipient's identity.
    pub fn transfer<G: RngCore + CryptoRng>(
        &self,
        token: &mut ConfidentialToken,
        from: Account,
        to: Account,
        amount: &FheUint64,
        rng: &mut G,
    ) -> Result<Handle> {
        self.check_recipient(to)?;
        token.transfer(from, to, amount, rng)
    }

    /// [`ConfidentialToken::mint`] gated on the recipient's identity.
    pub fn mint<G: RngCore + CryptoRng>(
        &self,
        token: &mut ConfidentialToken,
        to: Account,
        amount: u64,
        rng: &mut G,
    ) -> Result<Handle> {
        self.check_recipient(to)?;
        token.mint(to, amount, rng)
    }
}
