//! The coprocessor's durable state: the committee-backed token, the
//! composed ERC7984 extensions, the ciphertext store behind every
//! on-chain handle, and the `Address ↔ Account` binding that turns
//! `msg.sender` into the kit's authenticated caller.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::{Address, B256, keccak256};
use fhe::bfv::BfvParameters;
use fhe::gateway::Committee;
use fhe::token::ConfidentialToken;
use fhe::token::extensions::observer::Observers;
use fhe::token::extensions::rwa::Rwa;
use fhe::token::extensions::wrapper::PublicLedger;
use fhe::typed::{FheUint64, set_server_key};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::requests::{Fulfillment, HandleCommitment, Request};
use crate::{Error, Result};

/// A ciphertext the coprocessor stores on behalf of the chain: the
/// serialized bytes and the keccak256 commitment anchored on-chain.
struct StoredCiphertext {
    bytes: Vec<u8>,
    commitment: B256,
}

/// The kit account bound to the agent address (account 0, matching
/// `Rwa::new`).
const AGENT_ACCOUNT: u64 = 0;

/// The off-chain half of the deployment: ciphertexts, the threshold
/// committee (inside [`ConfidentialToken`]), and the composed
/// extensions. See the crate docs for the trust model.
///
/// This value is the DURABLE state — in production it would persist on
/// disk; v1 keeps it as a value a restarted event loop takes over,
/// which is the documented scope cut.
pub struct Coprocessor {
    token: ConfidentialToken,
    rwa: Rwa,
    observers: Observers,
    ledger: PublicLedger,
    params: Arc<BfvParameters>,
    /// Address → kit account, assigned sequentially on first sight in
    /// event order (deterministic under replay).
    accounts: HashMap<Address, u64>,
    next_account: u64,
    /// Registered input ciphertexts (ownership is enforced on-chain).
    inputs: HashMap<B256, FheUint64>,
    store: HashMap<B256, StoredCiphertext>,
    /// On-chain handle → kit-internal handle for coprocessor outputs.
    kit_handles: HashMap<B256, fhe::token::Handle>,
    rng: ChaCha20Rng,
    handle_nonce: u64,
}

impl Coprocessor {
    /// Creates the durable state: a fresh token under `committee` (which
    /// knows its own parameters) with `agent` holding the agent (and
    /// freezer) role.
    pub fn new(committee: Committee, agent: Address) -> Result<Self> {
        let params = committee.params().clone();
        let mut rng = ChaCha20Rng::from_os_rng();
        let token = ConfidentialToken::new(committee, &mut rng)?;
        let mut accounts = HashMap::new();
        accounts.insert(agent, AGENT_ACCOUNT);
        Ok(Self {
            token,
            rwa: Rwa::new(AGENT_ACCOUNT),
            observers: Observers::new(),
            ledger: PublicLedger::new(),
            params,
            accounts,
            next_account: AGENT_ACCOUNT + 1,
            inputs: HashMap::new(),
            store: HashMap::new(),
            kit_handles: HashMap::new(),
            rng,
            handle_nonce: 0,
        })
    }

    /// The committee this deployment runs under.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        self.token.committee()
    }

    /// The token behind the gateway, for state assertions in tests.
    #[must_use]
    pub fn token(&self) -> &ConfidentialToken {
        &self.token
    }

    /// The composed RWA policy (pause, blocklist, freezing, recovery
    /// audits), for state assertions and leakage sweeps in tests.
    #[must_use]
    pub fn rwa(&self) -> &Rwa {
        &self.rwa
    }

    /// The public-ledger mirror (faucet credits, wrap/unwrap audits).
    #[must_use]
    pub fn ledger(&self) -> &PublicLedger {
        &self.ledger
    }

    /// The kit account bound to `address`, assigned on first sight.
    pub fn account_of(&mut self, address: Address) -> u64 {
        if let Some(id) = self.accounts.get(&address) {
            return *id;
        }
        let id = self.next_account;
        self.next_account += 1;
        self.accounts.insert(address, id);
        id
    }

    // ------------------------------------------------------------------
    // Input registration (the off-chain half of the transport split).
    // ------------------------------------------------------------------

    /// Registers a user's encrypted input: validates that `bytes`
    /// deserialize to an [`FheUint64`] under the deployment parameters,
    /// stores the ciphertext, and returns `(handle, commitment)` — the
    /// commitment is `keccak256(bytes)` and the handle is a fresh opaque
    /// id. The caller (the client) anchors the pair on-chain via
    /// `registerInput`, which is where ownership is bound and enforced;
    /// the user then passes only the handle in their transaction.
    pub fn register_input(&mut self, bytes: &[u8]) -> Result<(B256, B256)> {
        let ciphertext = FheUint64::from_bytes(bytes, &self.params)?;
        let commitment = keccak256(bytes);
        let handle = self.fresh_handle(commitment);
        self.store.insert(
            handle,
            StoredCiphertext {
                bytes: bytes.to_vec(),
                commitment,
            },
        );
        self.inputs.insert(handle, ciphertext);
        Ok((handle, commitment))
    }

    /// The serialized ciphertext bytes stored behind `handle`, if any.
    #[must_use]
    pub fn stored_bytes(&self, handle: B256) -> Option<&[u8]> {
        self.store.get(&handle).map(|s| s.bytes.as_slice())
    }

    /// Whether the bytes stored behind `handle` still hash to the
    /// commitment recorded (and anchored on-chain) for it. `false` means
    /// the store was corrupted or tampered with.
    #[must_use]
    pub fn verify_stored(&self, handle: B256) -> bool {
        self.store
            .get(&handle)
            .is_some_and(|s| keccak256(&s.bytes) == s.commitment)
    }

    /// Replaces the bytes stored behind `handle` — the persistence seam
    /// (a real deployment reloads the store from disk, which is where
    /// tampering enters). Exists so tests can prove tampering is
    /// detected; does NOT update the commitment.
    pub fn replace_stored_bytes(&mut self, handle: B256, bytes: Vec<u8>) -> Result<()> {
        let stored = self
            .store
            .get_mut(&handle)
            .ok_or_else(|| Error::State(format!("no ciphertext stored behind handle {handle}")))?;
        stored.bytes = bytes;
        Ok(())
    }

    /// The registered input ciphertext behind `handle`, integrity-checked
    /// against its commitment before use.
    pub fn input_ciphertext(&self, handle: B256) -> Result<&FheUint64> {
        if !self.verify_stored(handle) {
            return Err(Error::State(format!(
                "stored bytes behind input {handle} no longer match their commitment"
            )));
        }
        self.inputs
            .get(&handle)
            .ok_or_else(|| Error::State(format!("no registered input behind handle {handle}")))
    }

    // ------------------------------------------------------------------
    // Request processing (the encrypted half of every state transition).
    // ------------------------------------------------------------------

    /// Executes the kit operation mapped to `request` and returns the
    /// fulfillment to post. Public policy was already enforced by the
    /// contract (and is re-checked here only through the mirrored RWA
    /// state, which is consistent by construction); encrypted guards run
    /// here and NEVER turn into an error — an insufficient transfer
    /// produces the same fulfillment shape as a successful one.
    ///
    /// Errors mean a structural inconsistency between the chain and the
    /// mirror (a missing input, a corrupted store) and stop the loop
    /// loudly rather than skipping a request.
    pub(crate) fn process(&mut self, request: &Request) -> Result<Fulfillment> {
        // Multiplications (cmux/select) need the relinearization key on
        // the executing thread.
        set_server_key(self.token.committee().server_key());
        match *request {
            Request::Faucet {
                id,
                account,
                amount,
            } => {
                let account = self.account_of(account);
                self.ledger.credit(account, amount);
                Ok(Fulfillment::Ack { id })
            }
            Request::Wrap {
                id,
                account,
                amount,
            } => {
                let acct = self.account_of(account);
                let balance = self
                    .ledger
                    .wrap(&mut self.token, acct, amount, &mut self.rng)?;
                // The same grant `Observers::mint` performs: a wrap is the
                // wrapper's mint.
                if let Some(observer) = self.observers.observer(acct) {
                    self.token.allow(balance, acct, observer)?;
                }
                let new_balance = self.export_balance(account)?;
                Ok(Fulfillment::Wrap {
                    id,
                    account,
                    amount,
                    new_balance,
                })
            }
            Request::Transfer {
                id,
                from,
                to,
                amount_handle,
            } => {
                let amount = self.input_ciphertext(amount_handle)?.clone();
                let from_acct = self.account_of(from);
                let to_acct = self.account_of(to);
                // The RWA policy transfer: the freezable double guard,
                // after re-checking the mirrored pause/blocklist state the
                // contract already enforced.
                let transferred_kit = self.rwa.transfer(
                    &mut self.token,
                    from_acct,
                    to_acct,
                    &amount,
                    &mut self.rng,
                )?;
                self.grant_transfer_observers(from_acct, to_acct, transferred_kit)?;
                let new_from = self.export_balance(from)?;
                let new_to = self.export_balance(to)?;
                let transferred = self.export(transferred_kit, from_acct)?;
                Ok(Fulfillment::Transfer {
                    id,
                    from,
                    to,
                    amount_handle,
                    new_from,
                    new_to,
                    transferred,
                })
            }
            Request::SetObserver {
                id,
                account,
                observer,
            } => {
                let acct = self.account_of(account);
                if observer == Address::ZERO {
                    self.observers.remove_observer(acct);
                } else {
                    let observer = self.account_of(observer);
                    self.observers.set_observer(acct, observer);
                }
                Ok(Fulfillment::Ack { id })
            }
            // Identity is a PUBLIC recipient check enforced by the
            // contract before any request reaches this loop; there is no
            // encrypted state to mirror.
            Request::SetVerified { id, .. } => Ok(Fulfillment::Ack { id }),
            Request::SetFrozen {
                id,
                account,
                amount_handle,
            } => {
                let amount = self.input_ciphertext(amount_handle)?.clone();
                let acct = self.account_of(account);
                let frozen_kit = self.rwa.set_confidential_frozen(
                    &mut self.token,
                    AGENT_ACCOUNT,
                    acct,
                    amount,
                )?;
                let new_frozen = self.export(frozen_kit, acct)?;
                Ok(Fulfillment::FrozenSet {
                    id,
                    account,
                    amount_handle,
                    new_frozen,
                })
            }
            Request::SetBlocked {
                id,
                account,
                blocked,
            } => {
                let acct = self.account_of(account);
                if blocked {
                    self.rwa.block_user(AGENT_ACCOUNT, acct)?;
                } else {
                    self.rwa.unblock_user(AGENT_ACCOUNT, acct)?;
                }
                Ok(Fulfillment::Ack { id })
            }
            Request::SetPaused { id, paused } => {
                if paused {
                    self.rwa.pause(AGENT_ACCOUNT)?;
                } else {
                    self.rwa.unpause(AGENT_ACCOUNT)?;
                }
                Ok(Fulfillment::Ack { id })
            }
            Request::ForceTransfer {
                id,
                from,
                to,
                amount_handle,
            } => {
                let amount = self.input_ciphertext(amount_handle)?.clone();
                let from_acct = self.account_of(from);
                let to_acct = self.account_of(to);
                // Bypasses pause, restrictions, and the frozen guard —
                // but NOT the balance guard (it silently zeroes). Not an
                // observed transfer: like Goal E, only transfers through
                // the observer extension grant.
                let transferred_kit = self.rwa.force_transfer(
                    &mut self.token,
                    AGENT_ACCOUNT,
                    from_acct,
                    to_acct,
                    &amount,
                    &mut self.rng,
                )?;
                let new_from = self.export_balance(from)?;
                let new_to = self.export_balance(to)?;
                let transferred = self.export(transferred_kit, from_acct)?;
                Ok(Fulfillment::Transfer {
                    id,
                    from,
                    to,
                    amount_handle,
                    new_from,
                    new_to,
                    transferred,
                })
            }
            Request::Recover {
                id,
                lost,
                recipient,
            } => {
                let lost_acct = self.account_of(lost);
                let recipient_acct = self.account_of(recipient);
                self.rwa.recover(
                    &mut self.token,
                    AGENT_ACCOUNT,
                    lost_acct,
                    recipient_acct,
                    &mut self.rng,
                )?;
                let new_lost = self.export_balance(lost)?;
                let new_recipient = self.export_balance(recipient)?;
                let frozen_kit = self
                    .rwa
                    .freezable()
                    .confidential_frozen(recipient_acct)
                    .ok_or_else(|| {
                        Error::State(format!(
                            "recovery into {recipient} left no frozen handle behind"
                        ))
                    })?;
                let new_recipient_frozen = self.export(frozen_kit, recipient_acct)?;
                Ok(Fulfillment::Recover {
                    id,
                    lost,
                    recipient,
                    new_lost,
                    new_recipient,
                    new_recipient_frozen,
                })
            }
            Request::Unwrap {
                id,
                account,
                amount_handle,
            } => {
                let amount_ct = self.input_ciphertext(amount_handle)?.clone();
                let acct = self.account_of(account);
                let audits_before = self.ledger.audit_log().len();
                let unwrap_request = self.ledger.request_unwrap(acct, amount_ct);
                match self
                    .ledger
                    .finalize_unwrap(&mut self.token, unwrap_request, &mut self.rng)
                {
                    Ok(amount) => {
                        let new_balance = self.export_balance(account)?;
                        Ok(Fulfillment::Unwrap {
                            id,
                            account,
                            amount_handle,
                            amount,
                            success: true,
                            new_balance,
                        })
                    }
                    // A failed FUNDS CHECK is a public, fulfillable
                    // outcome (the wrapper logged the revealed amount);
                    // anything else is structural and propagates.
                    Err(e) => {
                        let Some(audit) = self.ledger.audit_log().get(audits_before) else {
                            return Err(e.into());
                        };
                        Ok(Fulfillment::Unwrap {
                            id,
                            account,
                            amount_handle,
                            amount: audit.amount,
                            success: false,
                            new_balance: HandleCommitment {
                                handle: B256::ZERO,
                                commitment: B256::ZERO,
                            },
                        })
                    }
                }
            }
        }
    }

    /// The on-chain read path: threshold-decrypts the ciphertext behind
    /// an on-chain `handle` on behalf of `caller`, enforcing the token
    /// ACL that on-chain transactions (ownership, observer grants)
    /// built. Integrity-checks the store first.
    pub fn decrypt_for(&mut self, handle: B256, caller: Address) -> Result<u64> {
        if !self.verify_stored(handle) {
            return Err(Error::State(format!(
                "stored bytes behind {handle} no longer match their commitment"
            )));
        }
        let account = *self
            .accounts
            .get(&caller)
            .ok_or_else(|| Error::State(format!("address {caller} is not bound to any account")))?;
        let kit_handle = self
            .kit_handles
            .get(&handle)
            .ok_or_else(|| Error::State(format!("no coprocessor output behind handle {handle}")))?;
        Ok(self
            .token
            .decrypt_for(*kit_handle, account, &mut self.rng)?)
    }

    /// Replays `Observers::transfer`'s grants over the RWA transfer's
    /// new handles: each party's observer gets that party's rotated
    /// balance handle and the transferred-amount handle.
    fn grant_transfer_observers(
        &mut self,
        from: u64,
        to: u64,
        transferred: fhe::token::Handle,
    ) -> Result<()> {
        for party in [from, to] {
            if let Some(observer) = self.observers.observer(party) {
                let balance = self.token.balance_handle(party).ok_or_else(|| {
                    Error::State(format!("account {party} has no balance after transfer"))
                })?;
                self.token.allow(balance, party, observer)?;
                self.token.allow(transferred, party, observer)?;
            }
        }
        Ok(())
    }

    /// Exports `account`'s current balance ciphertext under a fresh
    /// on-chain handle.
    fn export_balance(&mut self, account: Address) -> Result<HandleCommitment> {
        let acct = self.account_of(account);
        let kit_handle = self
            .token
            .balance_handle(acct)
            .ok_or_else(|| Error::State(format!("account {account} has no balance handle")))?;
        self.export(kit_handle, acct)
    }

    /// Stores the ciphertext behind `kit_handle` (read as `reader`, an
    /// account on its ACL) under a fresh on-chain handle and returns the
    /// (handle, commitment) pair for the fulfillment.
    fn export(&mut self, kit_handle: fhe::token::Handle, reader: u64) -> Result<HandleCommitment> {
        let bytes = self.token.ciphertext(kit_handle, reader)?.to_bytes();
        let commitment = keccak256(&bytes);
        let handle = self.fresh_handle(commitment);
        self.store
            .insert(handle, StoredCiphertext { bytes, commitment });
        self.kit_handles.insert(handle, kit_handle);
        Ok(HandleCommitment { handle, commitment })
    }

    /// A fresh opaque on-chain handle: keccak of the commitment, a
    /// monotonic nonce, and a domain tag — unlinkable to the plaintext,
    /// unique per registration/output.
    fn fresh_handle(&mut self, commitment: B256) -> B256 {
        let nonce = self.handle_nonce;
        self.handle_nonce += 1;
        let mut preimage = Vec::with_capacity(32 + 8 + 4);
        preimage.extend_from_slice(commitment.as_slice());
        preimage.extend_from_slice(&nonce.to_be_bytes());
        preimage.extend_from_slice(b"fhe!");
        keccak256(preimage)
    }
}
