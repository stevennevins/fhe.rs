//! End-to-end validation of the confidential token kit — the master
//! verification for Goal D: committee keygen, serialization over the
//! "wire", mints, the success and insufficient-funds transfer paths, a
//! 10+-transfer noise-lifecycle run through gateway refresh, a plaintext
//! reference ledger checked after every step, and the leakage/ACL/supply
//! invariants. The companion test proves the refresh is load-bearing by
//! disabling it.
//!
//! Runs at the curated production parameters (degree 16384, 291-bit q),
//! NOT toy parameters.

use std::collections::HashMap;

use fhe::gateway::Committee;
use fhe::token::{Account, ConfidentialToken, RefreshPolicy};
use fhe::typed::safe_math::{try_add, try_sub};
use fhe::typed::{FheUint64, ServerKey, set_server_key};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::rng;
use rand::rngs::ThreadRng;

const ALICE: Account = 1;
const BOB: Account = 2;
const INTRUDER: Account = 999;

/// The plaintext reference ledger that runs alongside the encrypted one.
struct Reference {
    balances: HashMap<Account, u64>,
    supply: u64,
}

impl Reference {
    fn mint(&mut self, to: Account, amount: u64) {
        *self.balances.entry(to).or_default() += amount;
        self.supply += amount;
    }

    fn transfer(&mut self, from: Account, to: Account, amount: u64) {
        let from_balance = self.balances.entry(from).or_default();
        if *from_balance >= amount {
            *from_balance -= amount;
            *self.balances.entry(to).or_default() += amount;
        }
    }
}

/// Threshold-decrypts every balance and the total supply and asserts
/// exact equality with the reference ledger.
fn assert_ledger_matches(token: &ConfidentialToken, reference: &Reference, rng: &mut ThreadRng) {
    for (account, expected) in &reference.balances {
        let handle = token.balance_handle(*account).unwrap();
        assert_eq!(
            token.decrypt_for(handle, *account, rng).unwrap(),
            *expected,
            "balance of account {account}"
        );
    }
    assert_eq!(
        token
            .committee()
            .threshold_decrypt(token.total_supply(), rng)
            .unwrap(),
        reference.supply,
        "total supply"
    );
}

/// Asserts the per-step invariants: every stored handle respects the ACL,
/// and no single committee party's view contains a raw operand of any
/// comparison performed so far.
fn assert_invariants(token: &ConfidentialToken, raw_operands: &[(u64, u64)]) {
    // ACL: every stored ciphertext handle denies an account that was
    // never granted access.
    for handle in token.handles() {
        assert!(!token.is_allowed(handle, INTRUDER));
        assert!(token.ciphertext(handle, INTRUDER).is_err());
    }

    // Leakage: each transfer's comparison transcript, against the raw
    // operands (sender balance, amount) the reference ledger knows.
    assert_eq!(token.audit_log().len(), raw_operands.len());
    for (audit, (balance, amount)) in token.audit_log().iter().zip(raw_operands) {
        let true_difference = balance.wrapping_sub(*amount);
        let revealed = audit.compare.revealed;
        let revealed_signed = revealed as i64;

        // The revealed blinded difference is not a raw operand...
        assert_ne!(revealed, *balance);
        assert_ne!(revealed, *amount);
        // ...and (outside the documented exact-equality leak) is not even
        // the true difference, nor unblindable by any single party alone.
        if true_difference != 0 {
            assert_ne!(revealed, true_difference);
            for blind in &audit.compare.blinds {
                assert!(*blind >= 3);
                let partially_unblinded = revealed_signed.unsigned_abs() / blind;
                let residual = if revealed_signed < 0 {
                    (partially_unblinded as i64).wrapping_neg() as u64
                } else {
                    partially_unblinded
                };
                assert_ne!(residual, true_difference);
            }
        }
        // Refresh transcripts reveal only masked values: removing any
        // single party's own mask never exposes a raw operand.
        for refresh in &audit.refreshes {
            for mask in &refresh.masks {
                let view = refresh.revealed.wrapping_sub(*mask);
                assert_ne!(view, *balance);
                assert_ne!(view, *amount);
            }
        }
    }
}

/// The full lifecycle at production parameters. Every public item added
/// in G1-G4 is exercised here (see the PR description for the item-by-
/// item map).
#[test]
fn confidential_token_e2e() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();

    // Step 1: committee keygen, N = 3 — the token deploys under the
    // collective key; key material and ciphertexts cross the "wire" as
    // bytes (G1 serialization in real use).
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    assert_eq!(committee.num_parties(), 3);
    let server_key_bytes = committee.server_key().to_bytes();
    set_server_key(ServerKey::from_bytes(&server_key_bytes, &params).unwrap());

    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();
    let mut reference = Reference {
        balances: HashMap::new(),
        supply: 0,
    };
    // (sender balance, amount) per transfer, for the leakage invariant.
    let mut raw_operands: Vec<(u64, u64)> = Vec::new();

    // Step 2: mints (public amounts).
    token.mint(ALICE, 1_000_000, &mut rng).unwrap();
    reference.mint(ALICE, 1_000_000);
    token.mint(BOB, 500_000, &mut rng).unwrap();
    reference.mint(BOB, 500_000);
    assert_ledger_matches(&token, &reference, &mut rng);
    assert_invariants(&token, &raw_operands);

    // A transfer amount travels as bytes from the sender to the service.
    let mut transfer = |token: &mut ConfidentialToken,
                        reference: &mut Reference,
                        raw_operands: &mut Vec<(u64, u64)>,
                        from: Account,
                        to: Account,
                        amount: u64,
                        rng: &mut ThreadRng| {
        let enc = token.committee().encrypt(amount, rng).unwrap();
        let enc = FheUint64::from_bytes(&enc.to_bytes(), &params).unwrap();
        raw_operands.push((reference.balances[&from], amount));
        let amount_handle = token.transfer(from, to, &enc, rng).unwrap();
        reference.transfer(from, to, amount);
        amount_handle
    };

    // Step 3: success path — alice sends bob 300,000.
    transfer(
        &mut token,
        &mut reference,
        &mut raw_operands,
        ALICE,
        BOB,
        300_000,
        &mut rng,
    );
    assert_ledger_matches(&token, &reference, &mut rng);
    assert_invariants(&token, &raw_operands);

    // Step 4: insufficient funds — bob sends alice 10,000,000. The call
    // completes, balances are unchanged, and the transferred-amount
    // ciphertext decrypts to 0.
    let supply_before = reference.supply;
    let amount_handle = transfer(
        &mut token,
        &mut reference,
        &mut raw_operands,
        BOB,
        ALICE,
        10_000_000,
        &mut rng,
    );
    assert_eq!(token.decrypt_for(amount_handle, BOB, &mut rng).unwrap(), 0);
    assert_eq!(
        token.decrypt_for(amount_handle, ALICE, &mut rng).unwrap(),
        0
    );
    assert_eq!(reference.supply, supply_before);
    assert_ledger_matches(&token, &reference, &mut rng);
    assert_invariants(&token, &raw_operands);

    // Step 5: the noise-lifecycle proof — 10 further alternating
    // transfers, each routing both touched balances through gateway
    // refresh (the companion test below proves they MUST).
    for i in 0..10u64 {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = 10_000 + i * 1_000;
        transfer(
            &mut token,
            &mut reference,
            &mut raw_operands,
            from,
            to,
            amount,
            &mut rng,
        );
        // Step 6: reference ledger equality after EVERY step.
        assert_ledger_matches(&token, &reference, &mut rng);
        // Step 7: invariants at every step (supply constancy is implied
        // by ledger equality: reference.supply never changes under
        // transfers).
        assert_eq!(reference.supply, supply_before);
        assert_invariants(&token, &raw_operands);
    }
    // Every transfer refreshed both touched balances.
    assert!(token.audit_log().iter().all(|a| a.refreshes.len() == 2));

    // ACL grant flow on a real handle: alice lets bob read her balance.
    let alice_balance = token.balance_handle(ALICE).unwrap();
    assert!(token.decrypt_for(alice_balance, BOB, &mut rng).is_err());
    token.allow(alice_balance, ALICE, BOB).unwrap();
    assert_eq!(
        token.decrypt_for(alice_balance, BOB, &mut rng).unwrap(),
        reference.balances[&ALICE]
    );

    // The safe-math primitives transfers are built from, exercised
    // directly at production parameters against the same reference.
    let committee = token.committee();
    let a = committee.encrypt(900, &mut rng).unwrap();
    let b = committee.encrypt(400, &mut rng).unwrap();
    let (ok, sum) = try_add(committee, &a, &b, &mut rng).unwrap();
    assert_eq!(committee.threshold_decrypt(&ok, &mut rng).unwrap(), 1);
    assert_eq!(committee.threshold_decrypt(&sum, &mut rng).unwrap(), 1300);
    let (ok, diff) = try_sub(committee, &b, &a, &mut rng).unwrap();
    assert_eq!(committee.threshold_decrypt(&ok, &mut rng).unwrap(), 0);
    assert_eq!(committee.threshold_decrypt(&diff, &mut rng).unwrap(), 400);
}

/// The no-refresh companion: with refresh disabled, the same alternating
/// transfer sequence corrupts balances within the first few transfers —
/// the cmux consumes one multiplicative level per transfer against a
/// budget of two, so garbage is predicted by the third transfer touching
/// a balance. This is the proof that the refresh policy is load-bearing,
/// not decorative.
#[test]
fn transfers_without_refresh_corrupt_balances() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let mut token =
        ConfidentialToken::with_refresh_policy(committee, RefreshPolicy::Never, &mut rng).unwrap();
    let mut reference = Reference {
        balances: HashMap::new(),
        supply: 0,
    };
    token.mint(ALICE, 1_000_000, &mut rng).unwrap();
    reference.mint(ALICE, 1_000_000);
    token.mint(BOB, 500_000, &mut rng).unwrap();
    reference.mint(BOB, 500_000);

    let mut first_corruption = None;
    for i in 0..10u64 {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = 10_000 + i * 1_000;
        let enc = token.committee().encrypt(amount, &mut rng).unwrap();
        token.transfer(from, to, &enc, &mut rng).unwrap();
        reference.transfer(from, to, amount);

        let corrupted = reference.balances.iter().any(|(account, expected)| {
            let handle = token.balance_handle(*account).unwrap();
            token.decrypt_for(handle, *account, &mut rng).unwrap() != *expected
        });
        if corrupted {
            first_corruption = Some(i + 1);
            break;
        }
    }

    // Garbage as predicted: without refresh the balances die of noise,
    // and they die early (within 4 transfers), not just eventually.
    let first_corruption = first_corruption
        .expect("balances survived 10 unrefreshed transfers; refresh is not load-bearing");
    assert!(
        first_corruption <= 4,
        "corruption predicted within 4 unrefreshed transfers, observed at {first_corruption}"
    );
}
