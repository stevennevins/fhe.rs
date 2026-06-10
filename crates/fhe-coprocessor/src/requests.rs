//! On-chain request events decoded into plain values, and the
//! fulfillments the coprocessor answers them with. One request maps to
//! exactly one fulfillment transaction; the contract enforces both the
//! order and the (op, payload) binding.

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;

use crate::abi::IConfidentialTokenGateway as gw;
use crate::{Result, chain_err};

/// A decoded request event, in the order its id assigns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Public faucet credit (test stand-in for the underlying token).
    Faucet {
        /// Request id.
        id: u64,
        /// Credited account.
        account: Address,
        /// Public amount.
        amount: u64,
    },
    /// Public balance → confidential mint.
    Wrap {
        /// Request id.
        id: u64,
        /// Wrapping account.
        account: Address,
        /// Public amount (as in ERC7984 mints).
        amount: u64,
    },
    /// Confidential transfer of a registered encrypted input.
    Transfer {
        /// Request id.
        id: u64,
        /// Sender (`msg.sender` of the request transaction).
        from: Address,
        /// Recipient.
        to: Address,
        /// Registered input handle of the encrypted amount.
        amount_handle: B256,
    },
    /// Observer change for the sender's own account.
    SetObserver {
        /// Request id.
        id: u64,
        /// The account whose observer changes (always `msg.sender`).
        account: Address,
        /// New observer; zero removes the observer.
        observer: Address,
    },
    /// Identity-registry change (enforced on-chain; mirrored as a no-op).
    SetVerified {
        /// Request id.
        id: u64,
        /// The (un)verified account.
        account: Address,
        /// New verification status.
        verified: bool,
    },
    /// Encrypted frozen-amount change (agent-only on-chain).
    SetFrozen {
        /// Request id.
        id: u64,
        /// The frozen account.
        account: Address,
        /// Registered input handle of the encrypted frozen amount.
        amount_handle: B256,
    },
    /// Blocklist change (enforced on-chain; mirrored into the RWA policy).
    SetBlocked {
        /// Request id.
        id: u64,
        /// The (un)blocked account.
        account: Address,
        /// New blocked status.
        blocked: bool,
    },
    /// Pause change (enforced on-chain; mirrored into the RWA policy).
    SetPaused {
        /// Request id.
        id: u64,
        /// New paused status.
        paused: bool,
    },
    /// Agent-only transfer bypassing public policy and the frozen guard.
    ForceTransfer {
        /// Request id.
        id: u64,
        /// Debited account.
        from: Address,
        /// Credited account.
        to: Address,
        /// Registered input handle of the encrypted amount.
        amount_handle: B256,
    },
    /// Lost-wallet recovery (agent-only).
    Recover {
        /// Request id.
        id: u64,
        /// The lost wallet.
        lost: Address,
        /// The receiving wallet.
        recipient: Address,
    },
    /// Confidential balance → public credit (amount revealed by design).
    Unwrap {
        /// Request id.
        id: u64,
        /// Unwrapping account.
        account: Address,
        /// Registered input handle of the encrypted amount.
        amount_handle: B256,
    },
}

impl Request {
    /// The request id ordering this request against all others.
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Self::Faucet { id, .. }
            | Self::Wrap { id, .. }
            | Self::Transfer { id, .. }
            | Self::SetObserver { id, .. }
            | Self::SetVerified { id, .. }
            | Self::SetFrozen { id, .. }
            | Self::SetBlocked { id, .. }
            | Self::SetPaused { id, .. }
            | Self::ForceTransfer { id, .. }
            | Self::Recover { id, .. }
            | Self::Unwrap { id, .. } => *id,
        }
    }

    /// Decodes a gateway log into a request, or `None` for logs that are
    /// not request events (fulfillments, input anchors).
    pub fn from_log(log: &Log) -> Result<Option<Self>> {
        let Some(topic) = log.topic0() else {
            return Ok(None);
        };
        let request = if *topic == gw::FaucetRequested::SIGNATURE_HASH {
            let e = decode::<gw::FaucetRequested>(log)?;
            Self::Faucet {
                id: e.id,
                account: e.account,
                amount: e.amount,
            }
        } else if *topic == gw::WrapRequested::SIGNATURE_HASH {
            let e = decode::<gw::WrapRequested>(log)?;
            Self::Wrap {
                id: e.id,
                account: e.account,
                amount: e.amount,
            }
        } else if *topic == gw::TransferRequested::SIGNATURE_HASH {
            let e = decode::<gw::TransferRequested>(log)?;
            Self::Transfer {
                id: e.id,
                from: e.from,
                to: e.to,
                amount_handle: e.amountHandle,
            }
        } else if *topic == gw::ObserverSetRequested::SIGNATURE_HASH {
            let e = decode::<gw::ObserverSetRequested>(log)?;
            Self::SetObserver {
                id: e.id,
                account: e.account,
                observer: e.observer,
            }
        } else if *topic == gw::VerifiedSetRequested::SIGNATURE_HASH {
            let e = decode::<gw::VerifiedSetRequested>(log)?;
            Self::SetVerified {
                id: e.id,
                account: e.account,
                verified: e.verified,
            }
        } else if *topic == gw::FrozenSetRequested::SIGNATURE_HASH {
            let e = decode::<gw::FrozenSetRequested>(log)?;
            Self::SetFrozen {
                id: e.id,
                account: e.account,
                amount_handle: e.amountHandle,
            }
        } else if *topic == gw::BlockedSetRequested::SIGNATURE_HASH {
            let e = decode::<gw::BlockedSetRequested>(log)?;
            Self::SetBlocked {
                id: e.id,
                account: e.account,
                blocked: e.blocked,
            }
        } else if *topic == gw::PausedSetRequested::SIGNATURE_HASH {
            let e = decode::<gw::PausedSetRequested>(log)?;
            Self::SetPaused {
                id: e.id,
                paused: e.paused,
            }
        } else if *topic == gw::ForceTransferRequested::SIGNATURE_HASH {
            let e = decode::<gw::ForceTransferRequested>(log)?;
            Self::ForceTransfer {
                id: e.id,
                from: e.from,
                to: e.to,
                amount_handle: e.amountHandle,
            }
        } else if *topic == gw::RecoverRequested::SIGNATURE_HASH {
            let e = decode::<gw::RecoverRequested>(log)?;
            Self::Recover {
                id: e.id,
                lost: e.lost,
                recipient: e.recipient,
            }
        } else if *topic == gw::UnwrapRequested::SIGNATURE_HASH {
            let e = decode::<gw::UnwrapRequested>(log)?;
            Self::Unwrap {
                id: e.id,
                account: e.account,
                amount_handle: e.amountHandle,
            }
        } else {
            return Ok(None);
        };
        Ok(Some(request))
    }
}

fn decode<E: SolEvent>(log: &Log) -> Result<E> {
    Ok(log.log_decode::<E>().map_err(chain_err)?.inner.data)
}

/// A fresh on-chain handle plus the keccak256 commitment to the
/// ciphertext bytes now stored behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleCommitment {
    /// The opaque 32-byte on-chain handle.
    pub handle: B256,
    /// keccak256 of the serialized ciphertext.
    pub commitment: B256,
}

/// The fulfillment answering one request — exactly the payload of the
/// corresponding `fulfill*` contract call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fulfillment {
    /// Acknowledges a request with no confidential state change.
    Ack {
        /// Request id.
        id: u64,
    },
    /// A wrap landed: the account's balance handle rotated.
    Wrap {
        /// Request id.
        id: u64,
        /// Wrapping account.
        account: Address,
        /// Public amount (echoed for the request binding).
        amount: u64,
        /// Rotated balance.
        new_balance: HandleCommitment,
    },
    /// A transfer (or force transfer) landed. The same shape whether the
    /// encrypted guard passed or silently zeroed.
    Transfer {
        /// Request id.
        id: u64,
        /// Sender.
        from: Address,
        /// Recipient.
        to: Address,
        /// The spent input handle (echoed for the request binding).
        amount_handle: B256,
        /// Rotated sender balance.
        new_from: HandleCommitment,
        /// Rotated recipient balance.
        new_to: HandleCommitment,
        /// The transferred-amount ciphertext (amount or zero).
        transferred: HandleCommitment,
    },
    /// A freeze landed: the account's frozen handle rotated.
    FrozenSet {
        /// Request id.
        id: u64,
        /// Frozen account.
        account: Address,
        /// The spent input handle (echoed for the request binding).
        amount_handle: B256,
        /// Rotated frozen amount.
        new_frozen: HandleCommitment,
    },
    /// A recovery landed.
    Recover {
        /// Request id.
        id: u64,
        /// The lost wallet.
        lost: Address,
        /// The receiving wallet.
        recipient: Address,
        /// The lost wallet's rotated (zeroed) balance.
        new_lost: HandleCommitment,
        /// The recipient's rotated balance.
        new_recipient: HandleCommitment,
        /// The recipient's rotated frozen amount.
        new_recipient_frozen: HandleCommitment,
    },
    /// An unwrap landed (successfully or not — both are public).
    Unwrap {
        /// Request id.
        id: u64,
        /// Unwrapping account.
        account: Address,
        /// The spent input handle (echoed for the request binding).
        amount_handle: B256,
        /// The revealed amount (the wrapper's documented leakage).
        amount: u64,
        /// Whether the funds check passed and the public credit happened.
        success: bool,
        /// Rotated balance on success; zero handles on failure (the
        /// balance is untouched).
        new_balance: HandleCommitment,
    },
}

impl Fulfillment {
    /// The id of the request this fulfillment answers.
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Self::Ack { id }
            | Self::Wrap { id, .. }
            | Self::Transfer { id, .. }
            | Self::FrozenSet { id, .. }
            | Self::Recover { id, .. }
            | Self::Unwrap { id, .. } => *id,
        }
    }
}
