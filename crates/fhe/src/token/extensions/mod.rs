//! ERC7984-style extensions for [`ConfidentialToken`], mirroring the
//! extension suite of OpenZeppelin's confidential contracts
//! (`contracts/token/ERC7984/extensions/`).
//!
//! Each extension is a small state struct whose methods take the
//! [`ConfidentialToken`] they operate on, so extensions compose freely:
//! one token can sit behind a public-balance wrapper, an observer
//! registry, and an RWA policy object at the same time (the
//! `tests/erc7984_extensions_e2e.rs` lifecycle does exactly that).
//!
//! Like the core token, extensions do no signature checking — methods
//! that are role-gated take an explicit caller account, and caller
//! authenticity is the embedding application's problem.
//!
//! [`ConfidentialToken`]: crate::token::ConfidentialToken

pub mod identity;
pub mod restricted;
