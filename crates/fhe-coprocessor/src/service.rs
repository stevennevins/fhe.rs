//! The event-driven service loop: subscribe to the gateway over the
//! anvil websocket, decode request events, execute them through the
//! [`Coprocessor`] in strict request-id order, and post one fulfillment
//! transaction per request.
//!
//! Restart safety: the contract's `lastFulfilledId` is the durable
//! cursor. On every run the loop replays the historical event log and
//! skips requests at or below the cursor, so a coprocessor that crashed
//! mid-lifecycle resumes exactly where the chain says it stopped
//! (idempotent per request id).

use std::collections::BTreeMap;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use futures_util::StreamExt;

use crate::abi::IConfidentialTokenGateway::{self, IConfidentialTokenGatewayInstance};
use crate::requests::{Fulfillment, Request};
use crate::{Coprocessor, Error, Result, chain_err};

/// A running coprocessor service bound to one deployed gateway.
pub struct Service {
    coprocessor: Coprocessor,
    gateway: IConfidentialTokenGatewayInstance<DynProvider>,
}

impl Service {
    /// Binds `coprocessor` to the gateway at `address`, sending
    /// registrations and fulfillments through `provider` (which must be
    /// wallet-backed by the contract's coprocessor key, and websocket-
    /// backed for event subscriptions).
    #[must_use]
    pub fn new(coprocessor: Coprocessor, provider: DynProvider, address: Address) -> Self {
        Self {
            coprocessor,
            gateway: IConfidentialTokenGateway::new(address, provider),
        }
    }

    /// The durable state behind this service.
    #[must_use]
    pub fn coprocessor(&self) -> &Coprocessor {
        &self.coprocessor
    }

    /// The durable state behind this service, mutably (the off-chain
    /// API surface: decryption reads).
    pub fn coprocessor_mut(&mut self) -> &mut Coprocessor {
        &mut self.coprocessor
    }

    /// Tears the service down into its durable state — the handover a
    /// restarted service takes over after a crash of the loop.
    #[must_use]
    pub fn into_coprocessor(self) -> Coprocessor {
        self.coprocessor
    }

    /// The full off-chain input path: registers the serialized
    /// ciphertext for `owner` and anchors `(handle, commitment, owner)`
    /// on-chain. Returns the handle the user passes in their transaction
    /// and the anchored commitment.
    pub async fn register_and_anchor(
        &mut self,
        owner: Address,
        bytes: &[u8],
    ) -> Result<(B256, B256)> {
        let (handle, commitment) = self.coprocessor.register_input(owner, bytes)?;
        let receipt = self
            .gateway
            .registerInput(handle, commitment, owner)
            .send()
            .await
            .map_err(chain_err)?
            .get_receipt()
            .await
            .map_err(chain_err)?;
        if !receipt.status() {
            return Err(Error::Chain(format!(
                "registerInput reverted in tx {}",
                receipt.transaction_hash
            )));
        }
        Ok((handle, commitment))
    }

    /// Processes every request emitted so far (up to the contract's
    /// current `nextRequestId - 1`) and returns the fulfillment
    /// transaction hashes, in request order.
    pub async fn catch_up(&mut self) -> Result<Vec<B256>> {
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
    pub async fn run_until(&mut self, target: u64) -> Result<Vec<B256>> {
        let mut sent = Vec::new();
        let mut next = self
            .gateway
            .lastFulfilledId()
            .call()
            .await
            .map_err(chain_err)?
            + 1;
        if next > target {
            return Ok(sent);
        }
        let provider = self.gateway.provider();
        let filter = Filter::new().address(*self.gateway.address());
        // Subscribe BEFORE replaying history so no event can fall
        // between the two.
        let mut live = provider
            .subscribe_logs(&filter)
            .await
            .map_err(chain_err)?
            .into_stream();
        let mut pending: BTreeMap<u64, Request> = BTreeMap::new();
        let history = provider
            .get_logs(&filter.clone().from_block(0))
            .await
            .map_err(chain_err)?;
        for log in &history {
            if let Some(request) = Request::from_log(log)?
                && request.id() >= next
            {
                pending.insert(request.id(), request);
            }
        }
        loop {
            if next > target {
                return Ok(sent);
            }
            if let Some(request) = pending.remove(&next) {
                let fulfillment = self.coprocessor.process(&request)?;
                sent.push(send_fulfillment(&self.gateway, &fulfillment).await?);
                next += 1;
                continue;
            }
            let log = live.next().await.ok_or_else(|| {
                Error::Chain("event subscription ended before the target request".to_string())
            })?;
            if let Some(request) = Request::from_log(&log)?
                && request.id() >= next
            {
                pending.insert(request.id(), request);
            }
        }
    }
}

/// Posts one fulfillment transaction and returns its hash. A revert is
/// an error: it means the fulfillment did not match its request, which
/// is a bug, not a condition to swallow.
pub(crate) async fn send_fulfillment(
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
    let receipt = pending.get_receipt().await.map_err(chain_err)?;
    if !receipt.status() {
        return Err(Error::Chain(format!(
            "fulfillment of request {} reverted in tx {}",
            fulfillment.id(),
            receipt.transaction_hash
        )));
    }
    Ok(receipt.transaction_hash)
}
