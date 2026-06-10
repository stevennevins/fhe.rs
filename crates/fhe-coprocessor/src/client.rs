//! The user-facing client: the fhEVM-shaped flow. Build an encrypted
//! input, send one entry-point transaction, read back what the ACL
//! allows — rng, serialization, anchoring, and fulfillment waiting all
//! live inside.
//!
//! Every state-changing method subscribes to the gateway's events
//! BEFORE sending its transaction, extracts the request id from the
//! receipt, and resolves when the matching fulfillment event lands —
//! event-driven, not polling. A [`crate::Operator`] must therefore be
//! running (spawned) for these calls to complete.
//!
//! A client is structurally user-side only: it can encrypt-and-register
//! inputs, send transactions, and decrypt through the read path the
//! on-chain ACL grants its address. It exposes no committee, no
//! ciphertext store, and no request processing.

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{Filter, Log, TransactionReceipt};
use alloy::sol_types::SolEvent;
use fhe::bfv::PublicKey;
use fhe::typed::FheUint64;
use fhe_traits::Serialize;
use futures_util::{Stream, StreamExt};
use tokio::sync::Mutex;

use crate::abi::IConfidentialTokenGateway::{self as gw, IConfidentialTokenGatewayInstance};
use crate::coprocessor::Coprocessor;
use crate::{Error, Result, chain_err};

/// Every request event's signature hash; the request id is `topics[1]`
/// in all of them.
const REQUEST_EVENTS: [B256; 11] = [
    gw::FaucetRequested::SIGNATURE_HASH,
    gw::WrapRequested::SIGNATURE_HASH,
    gw::TransferRequested::SIGNATURE_HASH,
    gw::ObserverSetRequested::SIGNATURE_HASH,
    gw::VerifiedSetRequested::SIGNATURE_HASH,
    gw::FrozenSetRequested::SIGNATURE_HASH,
    gw::BlockedSetRequested::SIGNATURE_HASH,
    gw::PausedSetRequested::SIGNATURE_HASH,
    gw::ForceTransferRequested::SIGNATURE_HASH,
    gw::RecoverRequested::SIGNATURE_HASH,
    gw::UnwrapRequested::SIGNATURE_HASH,
];

/// Every fulfillment event's signature hash; the fulfilled request id
/// is `topics[1]` in all of them.
const FULFILLMENT_EVENTS: [B256; 6] = [
    gw::RequestAcked::SIGNATURE_HASH,
    gw::WrapFulfilled::SIGNATURE_HASH,
    gw::TransferFulfilled::SIGNATURE_HASH,
    gw::FrozenSetFulfilled::SIGNATURE_HASH,
    gw::RecoverFulfilled::SIGNATURE_HASH,
    gw::UnwrapFulfilled::SIGNATURE_HASH,
];

/// Sends one entry-point call and resolves to the fulfillment event's
/// log: subscribe (before the send), send, extract the request id from
/// the receipt, await the matching fulfillment. A macro because every
/// generated call builder is its own type.
macro_rules! transact {
    ($self:expr, $call:expr) => {{
        let mut fulfillments = $self.subscribe().await?;
        let pending = $call.send().await.map_err(chain_err)?;
        let receipt = wait_receipt($self.gateway.provider(), *pending.tx_hash()).await?;
        if !receipt.status() {
            return Err(Error::Chain(format!(
                "transaction {} reverted",
                receipt.transaction_hash
            )));
        }
        let id = request_id(&receipt)?;
        $self.wait_fulfilled(&mut fulfillments, id).await
    }};
}

/// One user (or agent) of a deployment, bound to one wallet. Built by
/// [`crate::Operator::client`].
pub struct Client {
    address: Address,
    /// The gateway through the user's own wallet (entry points, views).
    gateway: IConfidentialTokenGatewayInstance<DynProvider>,
    /// The gateway through the operator's wallet — input anchoring
    /// only, the one gateway call users cannot send themselves.
    anchor: IConfidentialTokenGatewayInstance<DynProvider>,
    /// The committee's collective public key (encryption is public).
    public_key: PublicKey,
    /// The shared coprocessor state: input registration and the
    /// ACL-enforced decryption read path. Private — nothing here leaks
    /// the committee or the store to the user.
    state: Arc<Mutex<Coprocessor>>,
}

impl Client {
    pub(crate) fn new(
        address: Address,
        gateway: IConfidentialTokenGatewayInstance<DynProvider>,
        anchor: IConfidentialTokenGatewayInstance<DynProvider>,
        public_key: PublicKey,
        state: Arc<Mutex<Coprocessor>>,
    ) -> Self {
        Self {
            address,
            gateway,
            anchor,
            public_key,
            state,
        }
    }

    /// The wallet address this client signs with.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    // ------------------------------------------------------------------
    // Encrypted inputs.
    // ------------------------------------------------------------------

    /// Builds a registered encrypted input: encrypts `value` under the
    /// committee's public key, registers the ciphertext with the
    /// coprocessor, anchors `(handle, commitment, owner)` on-chain, and
    /// returns the handle to pass in a transaction. Only this client's
    /// address may spend it.
    pub async fn encrypt_input(&self, value: u64) -> Result<B256> {
        let ciphertext = FheUint64::encrypt_with_public_key(value, &self.public_key, &mut rng())?;
        let bytes = ciphertext.to_bytes();
        // The state lock is held across the anchoring send: the anchor
        // wallet is the operator's fulfillment wallet, and the lock
        // serializes their nonces (see the operator module docs).
        let mut state = self.state.lock().await;
        let (handle, commitment) = state.register_input(&bytes)?;
        let pending = self
            .anchor
            .registerInput(handle, commitment, self.address)
            .send()
            .await
            .map_err(chain_err)?;
        let receipt = wait_receipt(self.anchor.provider(), *pending.tx_hash()).await?;
        if !receipt.status() {
            return Err(Error::Chain(format!(
                "registerInput reverted in tx {}",
                receipt.transaction_hash
            )));
        }
        Ok(handle)
    }

    // ------------------------------------------------------------------
    // Entry points (one method per gateway entry point; each resolves
    // when its request is fulfilled).
    // ------------------------------------------------------------------

    /// Credits the caller's public balance (test stand-in for receiving
    /// the underlying token).
    pub async fn faucet(&self, amount: u64) -> Result<()> {
        transact!(self, self.gateway.faucet(amount)).map(drop)
    }

    /// Wraps `amount` of the caller's public balance into the
    /// confidential balance (public amount, as in ERC7984 mints).
    pub async fn wrap(&self, amount: u64) -> Result<()> {
        transact!(self, self.gateway.wrap(amount)).map(drop)
    }

    /// Confidentially transfers a registered encrypted input to `to`.
    /// Resolves on fulfillment whether the encrypted guard passed or
    /// silently zeroed — only decryption can tell the difference, by
    /// design. Errors are public-policy reverts (pause, blocklist,
    /// identity, input ownership).
    pub async fn transfer(&self, to: Address, input: B256) -> Result<()> {
        transact!(self, self.gateway.confidentialTransfer(to, input)).map(drop)
    }

    /// Unwraps a registered encrypted input back to the caller's public
    /// balance. The amount is revealed at fulfillment (the wrapper's
    /// documented leakage); returns `(amount, success)` — an
    /// insufficient balance is a PUBLIC failed outcome, not an error.
    pub async fn unwrap(&self, input: B256) -> Result<(u64, bool)> {
        let log = transact!(self, self.gateway.unwrap(input))?;
        let event = log
            .log_decode::<gw::UnwrapFulfilled>()
            .map_err(chain_err)?
            .inner
            .data;
        Ok((event.amount, event.success))
    }

    /// Sets the caller's OWN observer (the zero address removes it).
    pub async fn set_observer(&self, observer: Address) -> Result<()> {
        transact!(self, self.gateway.setObserver(observer)).map(drop)
    }

    /// Marks `account` (un)verified in the identity registry
    /// (agent-only).
    pub async fn set_verified(&self, account: Address, verified: bool) -> Result<()> {
        transact!(self, self.gateway.setVerified(account, verified)).map(drop)
    }

    /// Sets `account`'s encrypted frozen amount to a registered input
    /// (agent-only; the agent is the freezer).
    pub async fn set_frozen(&self, account: Address, input: B256) -> Result<()> {
        transact!(self, self.gateway.setConfidentialFrozen(account, input)).map(drop)
    }

    /// Blocks or unblocks `account` (agent-only).
    pub async fn set_blocked(&self, account: Address, blocked: bool) -> Result<()> {
        transact!(self, self.gateway.setBlocked(account, blocked)).map(drop)
    }

    /// Pauses or unpauses transfers (agent-only).
    pub async fn set_paused(&self, paused: bool) -> Result<()> {
        transact!(self, self.gateway.setPaused(paused)).map(drop)
    }

    /// Transfers a registered encrypted input from `from` to `to`,
    /// bypassing pause, blocklist, identity, and the frozen guard — but
    /// not the encrypted balance guard (agent-only).
    pub async fn force_transfer(&self, from: Address, to: Address, input: B256) -> Result<()> {
        transact!(self, self.gateway.forceTransfer(from, to, input)).map(drop)
    }

    /// Recovers `lost`'s full confidential balance (frozen included)
    /// into `recipient` (agent-only).
    pub async fn recover(&self, lost: Address, recipient: Address) -> Result<()> {
        transact!(self, self.gateway.recover(lost, recipient)).map(drop)
    }

    // ------------------------------------------------------------------
    // Reads (decryption goes through the on-chain ACL; a handle this
    // address was never granted errors cleanly).
    // ------------------------------------------------------------------

    /// Decrypts `account`'s confidential balance as this client. Works
    /// for the account itself and for anyone its on-chain history
    /// granted (an observer); errors for everyone else.
    pub async fn balance(&self, account: Address) -> Result<u64> {
        let handle = self
            .gateway
            .confidentialBalanceOf(account)
            .call()
            .await
            .map_err(chain_err)?;
        self.decrypt(handle, account, "balance").await
    }

    /// Decrypts `account`'s confidential frozen amount as this client.
    pub async fn frozen(&self, account: Address) -> Result<u64> {
        let handle = self
            .gateway
            .confidentialFrozen(account)
            .call()
            .await
            .map_err(chain_err)?;
        self.decrypt(handle, account, "frozen amount").await
    }

    /// `account`'s public ERC20-side balance (a plain view call).
    pub async fn public_balance(&self, account: Address) -> Result<u64> {
        self.gateway
            .publicBalance(account)
            .call()
            .await
            .map_err(chain_err)
    }

    /// The ACL-enforced read path over an on-chain handle.
    async fn decrypt(&self, handle: B256, account: Address, what: &str) -> Result<u64> {
        if handle == B256::ZERO {
            return Err(Error::State(format!(
                "account {account} has no confidential {what}"
            )));
        }
        self.state.lock().await.decrypt_for(handle, self.address)
    }

    /// A subscription over the gateway's events, opened before the
    /// request transaction is sent so the fulfillment cannot be missed.
    async fn subscribe(&self) -> Result<impl Stream<Item = Log> + Unpin> {
        let filter = Filter::new().address(*self.gateway.address());
        Ok(self
            .gateway
            .provider()
            .subscribe_logs(&filter)
            .await
            .map_err(chain_err)?
            .into_stream())
    }

    /// Resolves when the fulfillment event for request `id` arrives on
    /// the subscription. The websocket subscription buffer is small and
    /// silently lossy under load (alloy drops on broadcast lag), so a
    /// quiet stream is periodically cross-checked against the durable
    /// event log — the subscription is the fast path, the log the
    /// source of truth.
    async fn wait_fulfilled(
        &self,
        fulfillments: &mut (impl Stream<Item = Log> + Unpin),
        id: u64,
    ) -> Result<Log> {
        loop {
            match tokio::time::timeout(Duration::from_secs(2), fulfillments.next()).await {
                Ok(Some(log)) => {
                    if event_id(&log, &FULFILLMENT_EVENTS) == Some(id) {
                        return Ok(log);
                    }
                }
                Ok(None) => {
                    return Err(Error::Chain(format!(
                        "event subscription ended before request {id} was fulfilled"
                    )));
                }
                Err(_quiet) => {
                    let filter = Filter::new().address(*self.gateway.address()).from_block(0);
                    let logs = self
                        .gateway
                        .provider()
                        .get_logs(&filter)
                        .await
                        .map_err(chain_err)?;
                    if let Some(log) = logs
                        .iter()
                        .find(|log| event_id(log, &FULFILLMENT_EVENTS) == Some(id))
                    {
                        return Ok(log.clone());
                    }
                }
            }
        }
    }
}

/// A thread-local CSPRNG; the user never threads an rng through the
/// client.
fn rng() -> rand::rngs::ThreadRng {
    rand::rng()
}

/// The request id assigned to the transaction behind `receipt`,
/// extracted from its request event.
fn request_id(receipt: &TransactionReceipt) -> Result<u64> {
    receipt
        .logs()
        .iter()
        .find_map(|log| event_id(log, &REQUEST_EVENTS))
        .ok_or_else(|| {
            Error::Chain(format!(
                "transaction {} emitted no request event",
                receipt.transaction_hash
            ))
        })
}

/// Fetches the receipt of `hash` by direct lookup, retrying until the
/// transaction is mined (bounded). The ws `get_receipt` watcher can
/// miss an instantly-mined transaction when the heartbeat's block
/// subscription lags (its buffer drops silently), which strands the
/// caller forever on an automining devnet — a direct lookup cannot.
pub(crate) async fn wait_receipt(provider: &DynProvider, hash: B256) -> Result<TransactionReceipt> {
    // 30 s: an automined receipt is available within one round trip;
    // this bound only decides how loudly a dropped transaction fails.
    for _ in 0..600 {
        if let Some(receipt) = provider
            .get_transaction_receipt(hash)
            .await
            .map_err(chain_err)?
        {
            return Ok(receipt);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(Error::Chain(format!(
        "transaction {hash} was not mined within 30s"
    )))
}

/// The `uint64 indexed id` of `log` if its event is one of `events`.
fn event_id(log: &Log, events: &[B256]) -> Option<u64> {
    let topic0 = log.topic0()?;
    if !events.contains(topic0) {
        return None;
    }
    let id_topic = log.topics().get(1)?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(id_topic.as_slice().get(24..32)?);
    Some(u64::from_be_bytes(bytes))
}
