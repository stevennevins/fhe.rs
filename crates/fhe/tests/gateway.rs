//! Tests for the committee/gateway module: collective keygen, threshold
//! decryption, recryption (refresh), and the interactive comparison —
//! including the leakage claims made in the `fhe::gateway` module docs.

#![allow(clippy::indexing_slicing)]

use std::sync::Arc;

use fhe::gateway::{Committee, MAX_COMPARE_OPERAND};
use fhe::mbfv::Aggregate;
use fhe::typed::{FheUint64, set_server_key};
use fhe_traits::FheDecoder;
use rand::{Rng, rng};

/// Small, fast, insecure parameters for protocol-correctness tests.
fn toy_params() -> Arc<fhe::bfv::BfvParameters> {
    FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap()
}

/// The token's trust anchor: a value encrypted under the collective key is
/// only recoverable through the committee.
#[test]
fn collective_key_threshold_decrypts() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();
    let ct = committee.encrypt(0xdead_beef_cafe, &mut rng).unwrap();
    assert_eq!(
        committee.threshold_decrypt(&ct, &mut rng).unwrap(),
        0xdead_beef_cafe
    );
}

/// N-of-N security: one party's decryption share alone must not reveal the
/// plaintext — otherwise a single corrupted party could read every balance.
#[test]
fn single_party_share_does_not_decrypt() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();
    let value = 0x1234_5678_9abc;
    let ct = committee.encrypt(value, &mut rng).unwrap();

    let inner = Arc::new(ct.clone().into_ciphertext());
    let lone_share = committee.decryption_share(0, &inner, &mut rng).unwrap();
    let pt = fhe::bfv::Plaintext::from_shares([lone_share]).unwrap();
    let decoded = Vec::<u64>::try_decode(&pt, fhe::bfv::Encoding::poly()).unwrap();
    assert_ne!(decoded[0], value);
}

/// The collective relinearization key must support homomorphic
/// multiplication: `select` (and thus every transfer) depends on it.
#[test]
fn collective_server_key_enables_multiplication() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();
    set_server_key(committee.server_key());

    let a = committee.encrypt(6, &mut rng).unwrap();
    let b = committee.encrypt(7, &mut rng).unwrap();
    let product = &a * &b;
    assert_eq!(committee.threshold_decrypt(&product, &mut rng).unwrap(), 42);
}

/// Refresh must ADD noise budget, not merely preserve correctness: a
/// ciphertext empirically within 2 multiplications of noise failure must
/// survive those 2 multiplications after a refresh, while its un-refreshed
/// copy fails them. This is the noise-lifecycle claim a long-lived token
/// balance depends on.
#[test]
fn refresh_restores_noise_budget() {
    let mut rng = rng();
    // Parameters with a real but small depth budget so the test can reach
    // noise failure quickly (insecure; correctness-only).
    let params = FheUint64::parameters(4096, &[55, 55, 55, 55, 55]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let value = 12345u64;
    let one = committee.encrypt(1, &mut rng).unwrap();
    let two_more = |ct: &FheUint64| &(ct * &one) * &one;

    // Empirically construct a ciphertext within 2 multiplications of noise
    // failure: multiply by an encryption of 1 until 2 further
    // multiplications decrypt incorrectly.
    let mut ct = committee.encrypt(value, &mut rng).unwrap();
    let mut depth = 0;
    while committee
        .threshold_decrypt(&two_more(&ct), &mut rng)
        .unwrap()
        == value
    {
        ct = &ct * &one;
        depth += 1;
        assert!(depth < 16, "never reached noise failure; params too large");
    }

    // The un-refreshed copy fails 2 more multiplications (that's how the
    // loop exited)...
    assert_ne!(
        committee
            .threshold_decrypt(&two_more(&ct), &mut rng)
            .unwrap(),
        value
    );

    // ...while the refreshed ciphertext holds the same value and survives
    // them: refresh added budget.
    let refreshed = committee.refresh(&ct, &mut rng).unwrap();
    assert_eq!(
        committee.threshold_decrypt(&refreshed, &mut rng).unwrap(),
        value
    );
    assert_eq!(
        committee
            .threshold_decrypt(&two_more(&refreshed), &mut rng)
            .unwrap(),
        value
    );
}

/// No party may see the refreshed plaintext: the revealed value must be the
/// masked sum, and removing any single party's own mask must still not
/// expose the plaintext (the other parties' masks still pad it).
#[test]
fn refresh_reveals_only_masked_value() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();
    let value = 777u64;
    let ct = committee.encrypt(value, &mut rng).unwrap();

    let (fresh, transcript) = committee.refresh_with_transcript(&ct, &mut rng).unwrap();
    assert_eq!(
        committee.threshold_decrypt(&fresh, &mut rng).unwrap(),
        value
    );

    // The revealed value is exactly the one-time-padded plaintext...
    let mask_sum = transcript
        .masks
        .iter()
        .fold(0u64, |acc, m| acc.wrapping_add(*m));
    assert_eq!(transcript.revealed, value.wrapping_add(mask_sum));

    // ...and no single party's view (revealed value minus its own mask)
    // contains the plaintext: the other parties' masks still cover it.
    for mask in &transcript.masks {
        assert_ne!(transcript.revealed.wrapping_sub(*mask), value);
    }
}

/// The comparison must be exact on random pairs and on the boundary set —
/// an off-by-one here is a token that lets you overdraw by one.
#[test]
fn compare_ge_random_and_boundary_pairs() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();

    let max = MAX_COMPARE_OPERAND - 1;
    let x = rng.random_range(0..max);
    let mut pairs = vec![(x, x), (x, x + 1), (x + 1, x), (0, 0), (0, max), (max, max)];
    for _ in 0..1000 {
        pairs.push((rng.random_range(0..=max), rng.random_range(0..=max)));
    }

    for (a, b) in pairs {
        let ct_a = committee.encrypt(a, &mut rng).unwrap();
        let ct_b = committee.encrypt(b, &mut rng).unwrap();
        let bit = committee.compare_ge(&ct_a, &ct_b, &mut rng).unwrap();
        let decrypted = committee.threshold_decrypt(&bit, &mut rng).unwrap();
        assert!(decrypted == 0 || decrypted == 1);
        assert_eq!(decrypted, u64::from(a >= b), "compare_ge({a}, {b})");
    }
}

/// The leakage claims of the module docs, asserted against a real protocol
/// transcript: the revealed value is blinded (differs from the true
/// difference), stays within the documented bound, and no single party can
/// undo the blinding with only its own blind.
#[test]
fn compare_ge_leaks_only_blinded_difference() {
    let mut rng = rng();
    let committee = Committee::new(3, &toy_params(), &mut rng).unwrap();

    for (a, b) in [(1_000_000u64, 300_000u64), (300_000, 1_000_000), (5, 5)] {
        let ct_a = committee.encrypt(a, &mut rng).unwrap();
        let ct_b = committee.encrypt(b, &mut rng).unwrap();
        let (bit, transcript) = committee
            .compare_ge_with_transcript(&ct_a, &ct_b, &mut rng)
            .unwrap();
        assert_eq!(
            committee.threshold_decrypt(&bit, &mut rng).unwrap(),
            u64::from(a >= b)
        );

        let true_difference = a.wrapping_sub(b);
        let revealed_signed = transcript.revealed as i64;

        if a == b {
            // Exact equality is documented leakage: the blinded difference
            // is exactly 0.
            assert_eq!(transcript.revealed, 0);
            continue;
        }

        // The revealed value is blinded: it differs from the true
        // difference (every blind is >= 3)...
        assert_ne!(transcript.revealed, true_difference);
        // ...and its magnitude respects the documented bound
        // |m| < 2^62 (sign-readable in the 2^64 ring).
        assert!(revealed_signed.unsigned_abs() < (1 << 62));
        // The blinded value is an exact multiple of the true difference by
        // the product of the blinds...
        let blind_product: u64 = transcript.blinds.iter().product();
        assert_eq!(
            transcript.revealed,
            true_difference.wrapping_mul(blind_product)
        );
        // ...so a single party, knowing only its own blind r_i, cannot
        // recover the true difference: the other parties' blinds are > 1.
        for r_i in &transcript.blinds {
            assert!(*r_i >= 3);
            let partially_unblinded = (revealed_signed.unsigned_abs() / r_i) as i64;
            let residual = if revealed_signed < 0 {
                (-partially_unblinded) as u64
            } else {
                partially_unblinded as u64
            };
            assert_ne!(residual, true_difference);
        }
    }
}

/// Committees the blinding budget cannot cover, and degenerate committees,
/// must be rejected at construction — not fail subtly during comparisons.
#[test]
fn committee_size_limits() {
    let mut rng = rng();
    let params = toy_params();
    assert!(Committee::new(1, &params, &mut rng).is_err());
    assert!(Committee::new(12, &params, &mut rng).is_err());
    assert!(Committee::new(3, &params, &mut rng).is_ok());
}
