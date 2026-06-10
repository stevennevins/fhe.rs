//! The operator-facing service: one constructor over the committee, one
//! run surface (`spawn` for live operation, [`Operator::run_until_idle`]
//! and [`Operator::run_until`] for deterministic tests), and a
//! shutdown-and-handover seam for crash recovery.
//!
//! The event loop subscribes to the gateway over the anvil websocket,
//! decodes request events, executes them through the [`Coprocessor`] in
//! strict request-id order, and posts one fulfillment transaction per
//! request. Restart safety: the contract's `lastFulfilledId` is the
//! durable cursor. On every run the loop replays the historical event
//! log and skips requests at or below the cursor, so an operator that
//! crashed mid-lifecycle resumes exactly where the chain says it
//! stopped (idempotent per request id).
//!
//! Locking discipline: the coprocessor state behind an [`Operator`] is
//! shared with every [`Client`] it hands out, behind one async mutex.
//! Both the fulfillment loop and a client's input anchoring send
//! transactions from the SAME wallet (the coprocessor key), so each
//! holds the state lock across its send — the lock is the nonce
//! serializer, not just the state guard.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use fhe::gateway::Committee;
use futures_util::StreamExt;
use tokio::sync::{Mutex, MutexGuard, oneshot};

use crate::abi::IConfidentialTokenGateway::{self, IConfidentialTokenGatewayInstance};
use crate::client::{Client, wait_receipt};
use crate::requests::{Fulfillment, Request};
use crate::{Coprocessor, Error, Result, chain_err};

/// How long a quiet event subscription waits before cross-checking the
/// durable log (the ws buffer drops silently on lag; see the client
/// module on why the subscription is only the fast path).
const RESYNC_AFTER: std::time::Duration = std::time::Duration::from_secs(3);

/// The operator's durable state, detached from any event loop — what a
/// crashed operator hands over to its replacement. Opaque: only
/// [`Operator::resume`] consumes it.
pub struct OperatorState(Arc<Mutex<Coprocessor>>);

/// The operator half of the deployment: the durable [`Coprocessor`]
/// state plus the gateway binding the event loop drives.
pub struct Operator {
    state: Arc<Mutex<Coprocessor>>,
    gateway: IConfidentialTokenGatewayInstance<DynProvider>,
}

impl Operator {
    /// Creates a fresh deployment under `committee`, with `agent`
    /// holding the agent (and freezer) role, fulfilling through
    /// `provider` (which must be wallet-backed by the contract's
    /// coprocessor key and websocket-backed for event subscriptions) to
    /// the gateway at `address`.
    pub fn new(
        committee: Committee,
        agent: Address,
        provider: DynProvider,
        address: Address,
    ) -> Result<Self> {
        let coprocessor = Coprocessor::new(committee, agent)?;
        Ok(Self::resume(
            OperatorState(Arc::new(Mutex::new(coprocessor))),
            provider,
            address,
        ))
    }

    /// Rebuilds an operator over state handed over from a previous run —
    /// the restart half of the crash-recovery seam.
    #[must_use]
    pub fn resume(state: OperatorState, provider: DynProvider, address: Address) -> Self {
        Self {
            state: state.0,
            gateway: IConfidentialTokenGateway::new(address, provider),
        }
    }

    /// Tears this operator down into its durable state — the handover a
    /// restarted operator resumes from after a crash of the loop.
    #[must_use]
    pub fn into_state(self) -> OperatorState {
        OperatorState(self.state)
    }

    /// The durable state, for operator-side reads (test assertions over
    /// audit logs, the ciphertext store, the committee).
    pub async fn state(&self) -> MutexGuard<'_, Coprocessor> {
        self.state.lock().await
    }

    /// Hands out a user-facing client: `provider` is the user's
    /// wallet-backed websocket provider and `address` its address. The
    /// client can encrypt-and-register inputs, send entry-point
    /// transactions, and decrypt what the on-chain ACL allows — nothing
    /// else.
    pub async fn client(&self, provider: DynProvider, address: Address) -> Client {
        let public_key = self.state.lock().await.committee().public_key().clone();
        Client::new(
            address,
            IConfidentialTokenGateway::new(*self.gateway.address(), provider),
            self.gateway.clone(),
            public_key,
            self.state.clone(),
        )
    }

    /// Runs the loop on a background task until shut down. The returned
    /// handle is the only way to stop it and recover the operator.
    #[must_use]
    pub fn spawn(self) -> OperatorHandle {
        let (stop, stopped) = oneshot::channel();
        let state = self.state.clone();
        let task = tokio::spawn(async move {
            self.run_live(stopped).await?;
            Ok(self)
        });
        OperatorHandle { stop, task, state }
    }

    /// Processes every request emitted so far (up to the contract's
    /// current `nextRequestId - 1`) and returns the fulfillment
    /// transaction hashes, in request order.
    pub async fn run_until_idle(&self) -> Result<Vec<B256>> {
        let next_request = self
            .gateway
            .nextRequestId()
            .call()
            .await
            .map_err(chain_err)?;
        self.run_until(next_request.saturating_sub(1)).await
    }

    /// Processes requests in strict id order until `target` is fulfilled
    /// (inclusive), returning the fulfillment transaction hashes sent by
    /// THIS call. Already-fulfilled requests are skipped via the
    /// on-chain cursor; missing history is replayed from the event log.
    /// This is the deterministic crash-injection seam: a test that
    /// stops here has died mid-lifecycle.
    pub async fn run_until(&self, target: u64) -> Result<Vec<B256>> {
        let mut sent = Vec::new();
        let mut next = self.cursor().await? + 1;
        if next > target {
            return Ok(sent);
        }
        let filter = Filter::new().address(*self.gateway.address());
        // Subscribe BEFORE replaying history so no event can fall
        // between the two.
        let mut live = self
            .gateway
            .provider()
            .subscribe_logs(&filter)
            .await
            .map_err(chain_err)?
            .into_stream();
        let mut pending = self.replay_history(&filter, next).await?;
        loop {
            if next > target {
                return Ok(sent);
            }
            if let Some(request) = pending.remove(&next) {
                sent.push(self.fulfill(&request).await?);
                next += 1;
                continue;
            }
            match tokio::time::timeout(RESYNC_AFTER, live.next()).await {
                Ok(Some(log)) => {
                    if let Some(request) = Request::from_log(&log)?
                        && request.id() >= next
                    {
                        pending.insert(request.id(), request);
                    }
                }
                Ok(None) => {
                    return Err(Error::Chain(
                        "event subscription ended before the target request".to_string(),
                    ));
                }
                // Quiet too long while a request is owed: the
                // subscription may have dropped it — resync from the log.
                Err(_quiet) => pending.append(&mut self.replay_history(&filter, next).await?),
            }
        }
    }

    /// The live loop behind [`Operator::spawn`]: processes every request
    /// as it arrives, in id order, until the stop signal fires.
    async fn run_live(&self, mut stopped: oneshot::Receiver<()>) -> Result<()> {
        let mut next = self.cursor().await? + 1;
        let filter = Filter::new().address(*self.gateway.address());
        // Subscribe BEFORE replaying history so no event can fall
        // between the two.
        let mut live = self
            .gateway
            .provider()
            .subscribe_logs(&filter)
            .await
            .map_err(chain_err)?
            .into_stream();
        let mut pending = self.replay_history(&filter, next).await?;
        loop {
            if let Some(request) = pending.remove(&next) {
                self.fulfill(&request).await?;
                next += 1;
                continue;
            }
            tokio::select! {
                _ = &mut stopped => return Ok(()),
                log = live.next() => {
                    let log = log.ok_or_else(|| {
                        Error::Chain("event subscription ended".to_string())
                    })?;
                    if let Some(request) = Request::from_log(&log)?
                        && request.id() >= next
                    {
                        pending.insert(request.id(), request);
                    }
                }
                // Quiet too long: the subscription may have dropped an
                // event (its buffer is lossy on lag) — resync from the
                // durable log.
                () = tokio::time::sleep(RESYNC_AFTER) => {
                    pending.append(&mut self.replay_history(&filter, next).await?);
                }
            }
        }
    }

    /// The contract's durable fulfillment cursor.
    async fn cursor(&self) -> Result<u64> {
        self.gateway
            .lastFulfilledId()
            .call()
            .await
            .map_err(chain_err)
    }

    /// Replays the historical event log into a pending map, skipping
    /// everything below `next` (already fulfilled per the cursor).
    async fn replay_history(&self, filter: &Filter, next: u64) -> Result<BTreeMap<u64, Request>> {
        let history = self
            .gateway
            .provider()
            .get_logs(&filter.clone().from_block(0))
            .await
            .map_err(chain_err)?;
        let mut pending = BTreeMap::new();
        for log in &history {
            if let Some(request) = Request::from_log(log)?
                && request.id() >= next
            {
                pending.insert(request.id(), request);
            }
        }
        Ok(pending)
    }

    /// Executes one request and posts its fulfillment, holding the
    /// state lock across the send (see the module docs on locking).
    async fn fulfill(&self, request: &Request) -> Result<B256> {
        let mut state = self.state.lock().await;
        let fulfillment = state.process(request)?;
        send_fulfillment(&self.gateway, &fulfillment).await
    }
}

/// A running operator loop. [`OperatorHandle::shutdown`] stops it
/// cleanly and returns the operator; dropping the handle aborts the
/// loop without handover.
pub struct OperatorHandle {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<Operator>>,
    state: Arc<Mutex<Coprocessor>>,
}

impl OperatorHandle {
    /// The durable state, for operator-side reads while the loop runs.
    pub async fn state(&self) -> MutexGuard<'_, Coprocessor> {
        self.state.lock().await
    }

    /// Stops the loop after the request it is currently processing and
    /// returns the operator — the shutdown half of the handover seam.
    pub async fn shutdown(self) -> Result<Operator> {
        // The loop may already have stopped on an error; a failed
        // signal send is fine, the join surfaces the loop's error.
        let _ = self.stop.send(());
        self.task
            .await
            .map_err(|e| Error::State(format!("operator task panicked: {e}")))?
    }
}

/// Posts one fulfillment transaction and returns its hash. A revert is
/// an error: it means the fulfillment did not match its request, which
/// is a bug, not a condition to swallow.
async fn send_fulfillment(
    gateway: &IConfidentialTokenGatewayInstance<DynProvider>,
    fulfillment: &Fulfillment,
) -> Result<B256> {
    // Each generated call builder is its own type, so the send happens
    // inside the match arms.
    macro_rules! send {
        ($call:expr) => {
            $call.send().await.map_err(chain_err)?
        };
    }
    let pending = match *fulfillment {
        Fulfillment::Ack { id } => send!(gateway.fulfillAck(id)),
        Fulfillment::Wrap {
            id,
            account,
            amount,
            new_balance,
        } => send!(gateway.fulfillWrap(
            id,
            account,
            amount,
            new_balance.handle,
            new_balance.commitment,
        )),
        Fulfillment::Transfer {
            id,
            from,
            to,
            amount_handle,
            new_from,
            new_to,
            transferred,
        } => send!(gateway.fulfillTransfer(
            id,
            from,
            to,
            amount_handle,
            new_from.handle,
            new_from.commitment,
            new_to.handle,
            new_to.commitment,
            transferred.handle,
            transferred.commitment,
        )),
        Fulfillment::FrozenSet {
            id,
            account,
            amount_handle,
            new_frozen,
        } => send!(gateway.fulfillFrozenSet(
            id,
            account,
            amount_handle,
            new_frozen.handle,
            new_frozen.commitment,
        )),
        Fulfillment::Recover {
            id,
            lost,
            recipient,
            new_lost,
            new_recipient,
            new_recipient_frozen,
        } => send!(gateway.fulfillRecover(
            id,
            lost,
            recipient,
            new_lost.handle,
            new_lost.commitment,
            new_recipient.handle,
            new_recipient.commitment,
            new_recipient_frozen.handle,
            new_recipient_frozen.commitment,
        )),
        Fulfillment::Unwrap {
            id,
            account,
            amount_handle,
            amount,
            success,
            new_balance,
        } => send!(gateway.fulfillUnwrap(
            id,
            account,
            amount_handle,
            amount,
            success,
            new_balance.handle,
            new_balance.commitment,
        )),
    };
    let receipt = wait_receipt(gateway.provider(), *pending.tx_hash()).await?;
    if !receipt.status() {
        return Err(Error::Chain(format!(
            "fulfillment of request {} reverted in tx {}",
            fulfillment.id(),
            receipt.transaction_hash
        )));
    }
    Ok(receipt.transaction_hash)
}
