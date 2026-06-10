//! The freezable depth audit (Goal E's critical constraint): proof that
//! the double-guard freezable transfer fits the multiplicative budget of
//! the curated `FheUint64::default_parameters_128` parameters, and that
//! the refresh policy is still load-bearing for it.
//!
//! Runs at the curated production parameters (degree 16384), NOT toy
//! parameters.

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use fhe::gateway::Committee;
use fhe::token::extensions::freezable::Freezable;
use fhe::token::{Account, ConfidentialToken, RefreshPolicy};
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const FREEZER: Account = 0;
const ALICE: Account = 1;
const BOB: Account = 2;

/// ONE freezable transfer (saturation guard + combined transfer guard +
/// selects) on fresh ciphertexts at the curated production parameters:
/// every output decrypts exactly. This is the depth audit the freezable
/// design is gated on; it documents the circuit variant in its assertion
/// messages.
#[test]
fn freezable_transfer_fits_depth_budget_at_production_parameters() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();
    let mut freezable = Freezable::new(FREEZER);

    // Fresh ciphertexts: balance 1000, frozen 600, transfer 300 (within
    // the available 400).
    token.mint(ALICE, 1000, &mut rng).unwrap();
    token.mint(BOB, 50, &mut rng).unwrap();
    let frozen = token.committee().encrypt(600, &mut rng).unwrap();
    freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();

    let amount = token.committee().encrypt(300, &mut rng).unwrap();
    let amount_handle = freezable
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();

    // Every output of the circuit decrypts exactly. The circuit is
    // variant (a) of the goal's depth-budget analysis: a single combined
    // guard `success = (available >= amount)` (the plain balance check
    // is implied by available <= balance), with the available amount
    // built as `select(balance >= frozen, balance - frozen, 0)` feeding
    // only the interactive comparison — so the stored sender balance
    // passes through exactly one cmux, the same level cost as a core
    // transfer.
    let alice = token.balance_handle(ALICE).unwrap();
    assert_eq!(
        token.decrypt_for(alice, ALICE, &mut rng).unwrap(),
        700,
        "sender balance after one freezable transfer (combined-guard circuit, variant (a))"
    );
    let bob = token.balance_handle(BOB).unwrap();
    assert_eq!(
        token.decrypt_for(bob, BOB, &mut rng).unwrap(),
        350,
        "receiver balance after one freezable transfer (combined-guard circuit, variant (a))"
    );
    assert_eq!(
        token.decrypt_for(amount_handle, ALICE, &mut rng).unwrap(),
        300,
        "transferred amount of one freezable transfer (combined-guard circuit, variant (a))"
    );
    // The standalone available query also decrypts exactly on the
    // post-transfer (refreshed) balance: 700 - 600 = 100.
    let available = freezable
        .confidential_available(&mut token, ALICE, &mut rng)
        .unwrap();
    assert_eq!(
        token.decrypt_for(available, ALICE, &mut rng).unwrap(),
        100,
        "available amount (select over the saturation guard, variant (a))"
    );
    // The frozen amount itself is untouched by the transfer.
    let frozen_handle = freezable.confidential_frozen(ALICE).unwrap();
    assert_eq!(
        token.decrypt_for(frozen_handle, FREEZER, &mut rng).unwrap(),
        600,
        "frozen amount unchanged by a freezable transfer"
    );
}

/// The no-refresh companion, repeated for freezable transfers: with
/// refresh disabled the double-guard transfers corrupt balances within
/// a measured bound; with refresh enabled (the default) a 10-transfer
/// freezable sequence stays exact.
#[test]
fn freezable_transfers_without_refresh_corrupt_balances() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let mut token =
        ConfidentialToken::with_refresh_policy(committee, RefreshPolicy::Never, &mut rng).unwrap();
    let mut freezable = Freezable::new(FREEZER);
    let mut reference: HashMap<Account, u64> = HashMap::new();
    token.mint(ALICE, 1_000_000, &mut rng).unwrap();
    reference.insert(ALICE, 1_000_000);
    token.mint(BOB, 500_000, &mut rng).unwrap();
    reference.insert(BOB, 500_000);
    let frozen = token.committee().encrypt(100, &mut rng).unwrap();
    freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();

    let mut first_corruption = None;
    for i in 0..10u64 {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = 10_000 + i * 1_000;
        let enc = token.committee().encrypt(amount, &mut rng).unwrap();
        freezable
            .transfer(&mut token, from, to, &enc, &mut rng)
            .unwrap();
        // All amounts stay within available; the reference applies them.
        *reference.get_mut(&from).unwrap() -= amount;
        *reference.get_mut(&to).unwrap() += amount;

        let corrupted = reference.iter().any(|(account, expected)| {
            let handle = token.balance_handle(*account).unwrap();
            token.decrypt_for(handle, *account, &mut rng).unwrap() != *expected
        });
        if corrupted {
            first_corruption = Some(i + 1);
            break;
        }
    }

    // Without refresh the cmux noise kills balances early, exactly as in
    // the core token's companion test.
    let first_corruption = first_corruption.expect(
        "balances survived 10 unrefreshed freezable transfers; refresh is not load-bearing",
    );
    assert!(
        first_corruption <= 4,
        "corruption predicted within 4 unrefreshed freezable transfers, observed at {first_corruption}"
    );
}

/// With refresh enabled, a 10-transfer freezable sequence stays exact —
/// the refresh policy gives the double-guard circuit the same safe
/// lifecycle as core transfers.
#[test]
fn freezable_transfers_with_refresh_stay_exact() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();
    let mut freezable = Freezable::new(FREEZER);
    let mut reference: HashMap<Account, u64> = HashMap::new();
    token.mint(ALICE, 1_000_000, &mut rng).unwrap();
    reference.insert(ALICE, 1_000_000);
    token.mint(BOB, 500_000, &mut rng).unwrap();
    reference.insert(BOB, 500_000);
    let frozen = token.committee().encrypt(100, &mut rng).unwrap();
    freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();

    for i in 0..10u64 {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = 10_000 + i * 1_000;
        let enc = token.committee().encrypt(amount, &mut rng).unwrap();
        freezable
            .transfer(&mut token, from, to, &enc, &mut rng)
            .unwrap();
        *reference.get_mut(&from).unwrap() -= amount;
        *reference.get_mut(&to).unwrap() += amount;

        for (account, expected) in &reference {
            let handle = token.balance_handle(*account).unwrap();
            assert_eq!(
                token.decrypt_for(handle, *account, &mut rng).unwrap(),
                *expected,
                "balance of account {account} after {} refreshed freezable transfers",
                i + 1
            );
        }
    }
    // Every freezable transfer refreshed both touched balances.
    assert!(freezable.audit_log().iter().all(|a| a.refreshes.len() == 2));
}
