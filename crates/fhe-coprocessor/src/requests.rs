//! On-chain request events decoded into plain values, and the
//! fulfillments the coprocessor answers them with. One request maps to
//! exactly one fulfillment transaction; the contract enforces both the
//! order and the (op, payload) binding.

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;

use crate::abi::IConfidentialTokenGateway as gw;
use crate::{Result, chain_err};

/// The symbolic-op alphabet, matching the contract's `SOP_*` constants.
pub mod ops {
    /// `lhs + rhs` (euint64; wraps mod 2^64 like the kit's `Add`).
    pub const ADD: u8 = 1;
    /// `lhs - rhs` (euint64; wraps mod 2^64 like the kit's `Sub`).
    pub const SUB: u8 = 2;
    /// `lhs >= rhs` (ebool; operands below 2^40, the committee bound).
    pub const GE: u8 = 3;
    /// `cond ? lhs : rhs` (euint64; `cond` is an ebool).
    pub const SELECT: u8 = 4;
}

/// fhEVM-style type tags carried in a symbolic handle's byte 30.
pub mod types {
    /// An encrypted boolean (a comparison result).
    pub const EBOOL: u8 = 0;
    /// An encrypted 64-bit integer.
    pub const EUINT64: u8 = 5;
}

/// One op of an atomic symbolic batch, mirroring the contract's
/// `SymbolicOp` struct. Build with the constructors; reference an
/// earlier op's result in the same batch with [`OpSpec::result_of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpSpec {
    /// The op tag ([`ops`]).
    pub op: u8,
    /// Left operand (a handle or an intra-batch reference).
    pub lhs: B256,
    /// Right operand (a handle or an intra-batch reference).
    pub rhs: B256,
    /// Select condition (zero for two-operand ops).
    pub cond: B256,
}

impl OpSpec {
    /// `lhs + rhs`.
    #[must_use]
    pub fn add(lhs: B256, rhs: B256) -> Self {
        Self {
            op: ops::ADD,
            lhs,
            rhs,
            cond: B256::ZERO,
        }
    }

    /// `lhs - rhs`.
    #[must_use]
    pub fn sub(lhs: B256, rhs: B256) -> Self {
        Self {
            op: ops::SUB,
            lhs,
            rhs,
            cond: B256::ZERO,
        }
    }

    /// `lhs >= rhs` (operands below 2^40, the committee bound).
    #[must_use]
    pub fn ge(lhs: B256, rhs: B256) -> Self {
        Self {
            op: ops::GE,
            lhs,
            rhs,
            cond: B256::ZERO,
        }
    }

    /// `cond ? lhs : rhs`.
    #[must_use]
    pub fn select(cond: B256, lhs: B256, rhs: B256) -> Self {
        Self {
            op: ops::SELECT,
            lhs,
            rhs,
            cond,
        }
    }

    /// The intra-batch reference marker for the result of op `index`
    /// (the contract's `batchRef`): result handles embed the request
    /// id, so an off-chain builder cannot name them in advance — only
    /// strictly earlier ops resolve.
    #[must_use]
    pub fn result_of(index: u64) -> B256 {
        let prefix = alloy::primitives::keccak256(b"fhe.rs/ref");
        let mut marker = B256::ZERO;
        marker.0[..24].copy_from_slice(&prefix.0[..24]);
        marker.0[24..].copy_from_slice(&index.to_be_bytes());
        marker
    }
}

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
    /// One symbolic encrypted op: the result handle was derived
    /// on-chain before the ciphertext exists; the coprocessor
    /// materializes it and posts the deferred commitment.
    SymbolicOp {
        /// Request id.
        id: u64,
        /// The requesting caller (allowed on every operand; granted on
        /// the result).
        caller: Address,
        /// The op tag ([`ops`]).
        op: u8,
        /// Left operand handle.
        lhs: B256,
        /// Right operand handle.
        rhs: B256,
        /// Select condition handle (zero for two-operand ops).
        cond: B256,
        /// The contract-derived symbolic result handle.
        result: B256,
    },
    /// An atomic ordered batch of symbolic ops: one request id, one
    /// fulfillment, intra-batch references already meaningful (the
    /// result handles were all derived on-chain at request time).
    Batch {
        /// Request id.
        id: u64,
        /// The requesting caller.
        caller: Address,
        /// The ops, in execution order, as submitted (markers
        /// unresolved — resolution is deterministic on both sides).
        ops: Vec<OpSpec>,
        /// The contract-derived result handles, one per op.
        results: Vec<B256>,
    },
    /// ACL grant (already authorized and written on-chain; mirrored
    /// into the coprocessor's read path in request order).
    Allow {
        /// Request id.
        id: u64,
        /// The granted handle.
        handle: B256,
        /// The account now allowed to read it.
        account: Address,
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
            | Self::Unwrap { id, .. }
            | Self::SymbolicOp { id, .. }
            | Self::Batch { id, .. }
            | Self::Allow { id, .. } => *id,
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
        } else if *topic == gw::OpRequested::SIGNATURE_HASH {
            let e = decode::<gw::OpRequested>(log)?;
            Self::SymbolicOp {
                id: e.id,
                caller: e.caller,
                op: e.op,
                lhs: e.lhs,
                rhs: e.rhs,
                cond: e.cond,
                result: e.result,
            }
        } else if *topic == gw::BatchRequested::SIGNATURE_HASH {
            let e = decode::<gw::BatchRequested>(log)?;
            Self::Batch {
                id: e.id,
                caller: e.caller,
                ops: e.ops.iter().map(OpSpec::from).collect(),
                results: e.results,
            }
        } else if *topic == gw::AllowRequested::SIGNATURE_HASH {
            let e = decode::<gw::AllowRequested>(log)?;
            Self::Allow {
                id: e.id,
                handle: e.handle,
                account: e.account,
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

impl From<&gw::SymbolicOp> for OpSpec {
    fn from(op: &gw::SymbolicOp) -> Self {
        Self {
            op: op.op,
            lhs: op.lhs,
            rhs: op.rhs,
            cond: op.cond,
        }
    }
}

impl From<&OpSpec> for gw::SymbolicOp {
    fn from(spec: &OpSpec) -> Self {
        Self {
            op: spec.op,
            lhs: spec.lhs,
            rhs: spec.rhs,
            cond: spec.cond,
        }
    }
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
    /// A symbolic op materialized: the deferred commitment for its
    /// contract-derived result handle.
    Op {
        /// Request id.
        id: u64,
        /// The requesting caller (echoed for the request binding).
        caller: Address,
        /// The op tag (echoed for the request binding).
        op: u8,
        /// Left operand (echoed for the request binding).
        lhs: B256,
        /// Right operand (echoed for the request binding).
        rhs: B256,
        /// Select condition (echoed for the request binding).
        cond: B256,
        /// The symbolic result handle (echoed for the request binding).
        result: B256,
        /// keccak256 of the materialized ciphertext — the deferred
        /// binding posted at fulfillment.
        commitment: B256,
    },
    /// A batch materialized: every result's deferred commitment, posted
    /// in one transaction.
    Batch {
        /// Request id.
        id: u64,
        /// The requesting caller (echoed for the request binding).
        caller: Address,
        /// The ops as submitted (echoed for the request binding).
        ops: Vec<OpSpec>,
        /// The result handles (echoed for the request binding).
        results: Vec<B256>,
        /// One commitment per result — the deferred bindings.
        commitments: Vec<B256>,
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
            | Self::Op { id, .. }
            | Self::Batch { id, .. }
            | Self::Unwrap { id, .. } => *id,
        }
    }
}
