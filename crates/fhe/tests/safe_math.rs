//! Tests for branch-free safe math: differential against a plaintext
//! reference, rollback semantics on out-of-domain results, and the depth
//! audit at the curated production parameters.

use fhe::gateway::Committee;
use fhe::typed::safe_math::{MAX_SAFE_VALUE, select, try_add, try_sub};
use fhe::typed::{FheUint64, set_server_key};
use rand::{Rng, rng};

fn toy_committee() -> Committee {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    committee
}

/// The plaintext semantics try_add must match: domain overflow rolls the
/// state back to `a` and reports failure.
fn reference_try_add(a: u64, b: u64) -> (u64, u64) {
    let sum = a + b;
    if sum <= MAX_SAFE_VALUE {
        (1, sum)
    } else {
        (0, a)
    }
}

/// The plaintext semantics try_sub must match: underflow rolls the state
/// back to `a` and reports failure.
fn reference_try_sub(a: u64, b: u64) -> (u64, u64) {
    if a >= b { (1, a - b) } else { (0, a) }
}

/// Operand pairs at and around every domain edge: 0, 1, max-1, max for
/// each operand.
fn boundary_pairs() -> Vec<(u64, u64)> {
    let edges = [0, 1, MAX_SAFE_VALUE - 1, MAX_SAFE_VALUE];
    let mut pairs = vec![];
    for a in edges {
        for b in edges {
            pairs.push((a, b));
        }
    }
    pairs
}

/// select must be an exact encrypted mux — it is the only branching
/// primitive every token transfer is built from.
#[test]
fn select_matches_reference() {
    let mut rng = rng();
    let committee = toy_committee();

    let mut triples = vec![
        (0u64, 0u64, 0u64),
        (1, 0, 0),
        (0, u64::MAX, 0),
        (1, u64::MAX, 0),
        (0, 0, u64::MAX),
        (1, 0, u64::MAX),
    ];
    for _ in 0..1000 {
        triples.push((rng.random_range(0..=1), rng.random(), rng.random()));
    }

    for (b, x, y) in triples {
        let ct_b = committee.encrypt(b, &mut rng).unwrap();
        let ct_x = committee.encrypt(x, &mut rng).unwrap();
        let ct_y = committee.encrypt(y, &mut rng).unwrap();
        let selected = select(&ct_b, &ct_x, &ct_y);
        let expected = if b == 1 { x } else { y };
        assert_eq!(
            committee.threshold_decrypt(&selected, &mut rng).unwrap(),
            expected,
            "select({b}, {x}, {y})"
        );
    }
}

/// try_add and try_sub must match the plaintext reference exactly — random
/// pairs plus every boundary combination — and their success bits must be
/// exactly 0 or 1 (anything else corrupts a downstream select).
#[test]
fn try_add_and_try_sub_match_reference() {
    let mut rng = rng();
    let committee = toy_committee();

    let mut pairs = boundary_pairs();
    for _ in 0..1000 {
        pairs.push((
            rng.random_range(0..=MAX_SAFE_VALUE),
            rng.random_range(0..=MAX_SAFE_VALUE),
        ));
    }

    for (a, b) in pairs {
        let ct_a = committee.encrypt(a, &mut rng).unwrap();
        let ct_b = committee.encrypt(b, &mut rng).unwrap();

        let (success, result) = try_add(&committee, &ct_a, &ct_b, &mut rng).unwrap();
        let success = committee.threshold_decrypt(&success, &mut rng).unwrap();
        let result = committee.threshold_decrypt(&result, &mut rng).unwrap();
        assert!(success == 0 || success == 1);
        assert_eq!(
            (success, result),
            reference_try_add(a, b),
            "try_add({a}, {b})"
        );

        let (success, result) = try_sub(&committee, &ct_a, &ct_b, &mut rng).unwrap();
        let success = committee.threshold_decrypt(&success, &mut rng).unwrap();
        let result = committee.threshold_decrypt(&result, &mut rng).unwrap();
        assert!(success == 0 || success == 1);
        assert_eq!(
            (success, result),
            reference_try_sub(a, b),
            "try_sub({a}, {b})"
        );
    }
}

/// Rollback semantics in isolation: on failure the result must be the
/// ORIGINAL value — a zeroed or wrapped result would corrupt a balance.
#[test]
fn failed_operations_roll_back_to_original_value() {
    let mut rng = rng();
    let committee = toy_committee();

    // Underflow: 5 - 6.
    let a = committee.encrypt(5, &mut rng).unwrap();
    let b = committee.encrypt(6, &mut rng).unwrap();
    let (success, result) = try_sub(&committee, &a, &b, &mut rng).unwrap();
    assert_eq!(committee.threshold_decrypt(&success, &mut rng).unwrap(), 0);
    assert_eq!(committee.threshold_decrypt(&result, &mut rng).unwrap(), 5);

    // Domain overflow: max + 1.
    let a = committee.encrypt(MAX_SAFE_VALUE, &mut rng).unwrap();
    let b = committee.encrypt(1, &mut rng).unwrap();
    let (success, result) = try_add(&committee, &a, &b, &mut rng).unwrap();
    assert_eq!(committee.threshold_decrypt(&success, &mut rng).unwrap(), 0);
    assert_eq!(
        committee.threshold_decrypt(&result, &mut rng).unwrap(),
        MAX_SAFE_VALUE
    );
}

/// Depth audit at the curated production parameters: one transfer's worth
/// of circuit — try_sub then a select on its outputs — applied to fresh
/// ciphertexts must decrypt correctly, proving the per-transfer circuit
/// fits the depth budget without an intermediate refresh.
#[test]
fn per_transfer_circuit_fits_depth_budget_at_production_parameters() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let balance = committee.encrypt(1_000_000, &mut rng).unwrap();
    let amount = committee.encrypt(300_000, &mut rng).unwrap();

    // One transfer's sender-side circuit: guard the subtraction, then
    // select the actually-transferred amount.
    let (success, new_balance) = try_sub(&committee, &balance, &amount, &mut rng).unwrap();
    let zero = committee.encrypt(0, &mut rng).unwrap();
    let transferred = select(&success, &amount, &zero);

    assert_eq!(
        committee.threshold_decrypt(&new_balance, &mut rng).unwrap(),
        700_000
    );
    assert_eq!(
        committee.threshold_decrypt(&transferred, &mut rng).unwrap(),
        300_000
    );
}
