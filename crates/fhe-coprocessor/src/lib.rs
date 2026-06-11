//! An off-chain FHE coprocessor that drives the [`fhe::token`]
//! confidential token kit from on-chain transactions, mirroring the
//! fhEVM deployment shape.
//!
//! The chain (a local anvil devnet running
//! `contracts/src/ConfidentialTokenGateway.sol`) holds 32-byte
//! ciphertext handles, keccak256 commitments to the ciphertext bytes,
//! and all public access-control state. This crate holds the
//! ciphertexts and the in-process threshold committee, subscribes to
//! the contract's request events, executes the mapped
//! [`fhe::token::extensions`] operation, and posts the resulting
//! handles back in a fulfillment transaction.
//!
//! # Transport split
//!
//! Ciphertexts never enter calldata: a degree-16384 ciphertext is
//! megabytes. An encrypted input (a transfer amount) is registered with
//! the coprocessor first (an off-chain call), which stores the bytes,
//! anchors `(handle, commitment, owner)` on-chain, and returns the
//! handle the user then passes in their transaction. This is the fhEVM
//! input-handle model, not a shortcut.
//!
//! # Trust model (v1)
//!
//! The coprocessor is a **trusted executor**. What it cannot do: decrypt
//! anything unilaterally — the committee inside it is N-of-N
//! ([`fhe::gateway::Committee`]) and this crate adds no new cryptography
//! — and, structurally, it cannot fulfill requests out of order or apply
//! a transition with no matching on-chain request (the contract binds
//! every fulfillment to the hash of exactly one request, in id order).
//! What it CAN do: censor (stop fulfilling) and stall — and it is the
//! sole holder of the ciphertext store, so losing it is a liveness
//! loss. That censorship/stalling gap is named here, not filled: no
//! fraud proofs, attestations, or staking in v1.
//!
//! # Ordering and crash recovery
//!
//! The chain is the source of truth for ordering and authorization; the
//! coprocessor is the source of truth for encrypted state. Requests are
//! processed strictly in request-id order and fulfilled one transaction
//! each; the contract's `lastFulfilledId` is the durable resume cursor,
//! and processing is idempotent per request id.

pub mod abi;
pub mod client;
mod coprocessor;
pub mod harness;
pub mod operator;
mod requests;

pub use client::Client;
pub use coprocessor::Coprocessor;
pub use operator::{Operator, OperatorHandle, OperatorState};

/// Errors of the coprocessor crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the FHE kit underneath.
    #[error("fhe: {0}")]
    Fhe(#[from] fhe::Error),
    /// An error talking to the chain.
    #[error("chain: {0}")]
    Chain(String),
    /// An internal-state inconsistency (a handle the chain references
    /// but the store does not hold, a malformed event, ...).
    #[error("state: {0}")]
    State(String),
}

/// Result alias for [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn chain_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Chain(e.to_string())
}
