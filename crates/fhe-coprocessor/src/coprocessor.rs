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
use fhe::typed::FheUint64;
use fhe_traits::DeserializeParametrized;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{Error, Result};

/// A ciphertext the coprocessor stores on behalf of the chain: the
/// serialized bytes and the keccak256 commitment anchored on-chain.
struct StoredCiphertext {
    bytes: Vec<u8>,
    commitment: B256,
}

/// A registered encrypted input, spendable (on-chain) only by `owner`.
struct EncryptedInput {
    ciphertext: FheUint64,
    owner: Address,
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
    params: Arc<BfvParameters>,
    /// Address → kit account, assigned sequentially on first sight in
    /// event order (deterministic under replay).
    accounts: HashMap<Address, u64>,
    next_account: u64,
    inputs: HashMap<B256, EncryptedInput>,
    store: HashMap<B256, StoredCiphertext>,
    handle_nonce: u64,
}

impl Coprocessor {
    /// Creates the durable state: a fresh token under `committee` (whose
    /// `params` the caller already holds) with `agent` holding the agent
    /// (and freezer) role.
    pub fn new(committee: Committee, params: Arc<BfvParameters>, agent: Address) -> Result<Self> {
        let mut rng = ChaCha20Rng::from_os_rng();
        let token = ConfidentialToken::new(committee, &mut rng)?;
        let mut accounts = HashMap::new();
        accounts.insert(agent, AGENT_ACCOUNT);
        Ok(Self {
            token,
            params,
            accounts,
            next_account: AGENT_ACCOUNT + 1,
            inputs: HashMap::new(),
            store: HashMap::new(),
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
    /// id. The caller (the service loop) anchors the pair on-chain via
    /// `registerInput`; the user then passes only the handle in their
    /// transaction.
    pub fn register_input(&mut self, owner: Address, bytes: &[u8]) -> Result<(B256, B256)> {
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
        self.inputs
            .insert(handle, EncryptedInput { ciphertext, owner });
        Ok((handle, commitment))
    }

    /// The serialized ciphertext bytes stored behind `handle`, if any.
    #[must_use]
    pub fn stored_bytes(&self, handle: B256) -> Option<&[u8]> {
        self.store.get(&handle).map(|s| s.bytes.as_slice())
    }

    /// The commitment recorded for `handle` at registration time.
    #[must_use]
    pub fn stored_commitment(&self, handle: B256) -> Option<B256> {
        self.store.get(&handle).map(|s| s.commitment)
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

    /// The address allowed (on-chain) to spend the registered input
    /// behind `handle`.
    #[must_use]
    pub fn input_owner(&self, handle: B256) -> Option<Address> {
        self.inputs.get(&handle).map(|i| i.owner)
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
            .map(|i| &i.ciphertext)
            .ok_or_else(|| Error::State(format!("no registered input behind handle {handle}")))
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
