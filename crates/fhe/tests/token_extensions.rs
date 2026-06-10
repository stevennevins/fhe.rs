//! Unit tests for the ERC7984 extension suite at toy parameters:
//! restriction modes, identity checks, and their "public check before
//! encrypted work" guarantee.

use fhe::gateway::Committee;
use fhe::token::extensions::freezable::Freezable;
use fhe::token::extensions::identity::{IdentityCheck, IdentityRegistry, InMemoryIdentityRegistry};
use fhe::token::extensions::observer::Observers;
use fhe::token::extensions::restricted::{Restriction, RestrictionMode, Restrictions};
use fhe::token::extensions::rwa::Rwa;
use fhe::token::extensions::wrapper::PublicLedger;
use fhe::token::{Account, ConfidentialToken};
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const ALICE: Account = 1;
const BOB: Account = 2;
const EVE: Account = 4;
const FREEZER: Account = 9;

fn toy_token() -> ConfidentialToken {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    ConfidentialToken::new(committee, &mut rng).unwrap()
}

fn balance_of(token: &ConfidentialToken, account: Account) -> u64 {
    let handle = token.balance_handle(account).unwrap();
    token.decrypt_for(handle, account, &mut rng()).unwrap()
}

/// Blocklist mode: a blocked sender and a blocked recipient each make
/// the transfer a structural Err — before any encrypted work, so no new
/// handles are created and no committee comparison runs. Unblocking
/// restores the transfer.
#[test]
fn blocklist_blocks_sender_and_recipient_publicly() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    let mut restrictions = Restrictions::new(RestrictionMode::Blocklist);

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    for blocked in [ALICE, BOB] {
        restrictions.set_restriction(blocked, Restriction::Blocked);
        assert!(!restrictions.is_user_allowed(blocked));

        let handles_before = token.handles().len();
        let comparisons_before = token.audit_log().len();
        assert!(
            restrictions
                .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
                .is_err()
        );
        // The check happened before any encrypted work: no new handles,
        // zero committee comparisons.
        assert_eq!(token.handles().len(), handles_before);
        assert_eq!(token.audit_log().len(), comparisons_before);

        restrictions.set_restriction(blocked, Restriction::Default);
    }

    // Unblocked: the transfer goes through.
    restrictions
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, ALICE), 90);
    assert_eq!(balance_of(&token, BOB), 10);
}

/// Allowlist mode: default-deny — a transfer between two unlisted
/// accounts fails; explicitly allowing both restores it.
#[test]
fn allowlist_denies_by_default() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    let mut restrictions = Restrictions::new(RestrictionMode::Allowlist);
    assert_eq!(restrictions.mode(), RestrictionMode::Allowlist);

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(
        restrictions
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    // Allowing only one party is not enough.
    restrictions.set_restriction(ALICE, Restriction::Allowed);
    assert!(
        restrictions
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );

    restrictions.set_restriction(BOB, Restriction::Allowed);
    restrictions
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, BOB), 10);
}

/// Unverified recipient: transfer and mint both Err with no encrypted
/// work; verifying the recipient through the registry restores both.
#[test]
fn identity_check_gates_recipient_on_transfer_and_mint() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut check = IdentityCheck::new(InMemoryIdentityRegistry::new());
    check.registry_mut().set_verified(ALICE, true);
    assert!(check.registry().is_verified(ALICE));
    check.mint(&mut token, ALICE, 100, &mut rng).unwrap();

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    let handles_before = token.handles().len();
    let comparisons_before = token.audit_log().len();
    assert!(
        check
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    assert!(check.mint(&mut token, BOB, 5, &mut rng).is_err());
    // Both rejections happened before any encrypted work.
    assert_eq!(token.handles().len(), handles_before);
    assert_eq!(token.audit_log().len(), comparisons_before);

    check.registry_mut().set_verified(BOB, true);
    check
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    check.mint(&mut token, BOB, 5, &mut rng).unwrap();
    assert_eq!(balance_of(&token, ALICE), 90);
    assert_eq!(balance_of(&token, BOB), 15);
}

/// After set_observer(alice, eve), a transfer's new sender balance
/// handle AND transferred-amount handle are allowed to eve and decrypt
/// for her; handles created BEFORE the observer was set stay denied.
#[test]
fn observer_sees_new_handles_but_not_old_ones() {
    let mut rng = rng();
    let mut token = toy_token();
    let observers = {
        let mut o = Observers::new();
        token.mint(ALICE, 100, &mut rng).unwrap();
        o.set_observer(ALICE, EVE);
        assert_eq!(o.observer(ALICE), Some(EVE));
        o
    };
    let pre_observer_balance = token.balance_handle(ALICE).unwrap();

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    let amount_handle = observers
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    let new_balance = token.balance_handle(ALICE).unwrap();

    assert!(token.is_allowed(new_balance, EVE));
    assert!(token.is_allowed(amount_handle, EVE));
    assert_eq!(token.decrypt_for(new_balance, EVE, &mut rng).unwrap(), 90);
    assert_eq!(token.decrypt_for(amount_handle, EVE, &mut rng).unwrap(), 10);
    // The balance handle from before the observer was set stays denied.
    assert!(!token.is_allowed(pre_observer_balance, EVE));
    assert!(
        token
            .decrypt_for(pre_observer_balance, EVE, &mut rng)
            .is_err()
    );
}

/// Removing the observer stops future grants but does not revoke past
/// ones — the documented OZ no-revocation semantics, pinned.
#[test]
fn removing_observer_stops_future_grants_keeps_past_ones() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut observers = Observers::new();
    observers.set_observer(ALICE, EVE);
    // Mint grants too: the new balance handle is observed.
    let observed_balance = observers.mint(&mut token, ALICE, 100, &mut rng).unwrap();
    assert!(token.is_allowed(observed_balance, EVE));

    observers.remove_observer(ALICE);
    assert_eq!(observers.observer(ALICE), None);

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    let amount_handle = observers
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    // New handles after removal: denied to eve.
    assert!(!token.is_allowed(token.balance_handle(ALICE).unwrap(), EVE));
    assert!(!token.is_allowed(amount_handle, EVE));
    // Previously granted handle still decrypts (no revocation).
    assert_eq!(
        token.decrypt_for(observed_balance, EVE, &mut rng).unwrap(),
        100
    );
}

/// An observer on the RECIPIENT side sees the recipient's rotated
/// balance and the transferred amount, but not the sender's balance.
#[test]
fn recipient_observer_sees_recipient_activity_only() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    let mut observers = Observers::new();
    observers.set_observer(BOB, EVE);

    let amount = token.committee().encrypt(30, &mut rng).unwrap();
    let amount_handle = observers
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();

    let bob_balance = token.balance_handle(BOB).unwrap();
    assert_eq!(token.decrypt_for(bob_balance, EVE, &mut rng).unwrap(), 30);
    assert_eq!(token.decrypt_for(amount_handle, EVE, &mut rng).unwrap(), 30);
    assert!(!token.is_allowed(token.balance_handle(ALICE).unwrap(), EVE));
}

/// confidential_available = balance - frozen, saturating at zero, on
/// 100+ random (balance, frozen) pairs including frozen = 0, frozen =
/// balance, and frozen > balance — all threshold-decrypted against a
/// plaintext reference.
#[test]
fn available_matches_plaintext_reference_on_random_pairs() {
    use rand::Rng;
    let mut rng = rng();
    let mut token = toy_token();
    let mut freezable = Freezable::new(FREEZER);

    let mut pairs: Vec<(u64, u64)> = vec![(1000, 0), (1000, 1000), (1000, 1001), (0, 0), (0, 5)];
    while pairs.len() < 100 {
        let balance = rng.random_range(0..1u64 << 20);
        let frozen = rng.random_range(0..1u64 << 21);
        pairs.push((balance, frozen));
    }

    for (i, (balance, frozen)) in pairs.into_iter().enumerate() {
        let account = 1000 + i as Account;
        token.mint(account, balance, &mut rng).unwrap();
        let enc_frozen = token.committee().encrypt(frozen, &mut rng).unwrap();
        freezable
            .set_confidential_frozen(&mut token, FREEZER, account, enc_frozen)
            .unwrap();
        let available = freezable
            .confidential_available(&mut token, account, &mut rng)
            .unwrap();
        assert_eq!(
            token.decrypt_for(available, account, &mut rng).unwrap(),
            balance.saturating_sub(frozen),
            "available of balance {balance}, frozen {frozen}"
        );
    }
}

/// Guard semantics: with balance 1000 and frozen 600, a transfer of 401
/// silently zeroes (balances unchanged, amount decrypts to 0) and a
/// transfer of 400 succeeds — and an observer of handles and call traces
/// cannot distinguish the zeroed case from a zero-amount transfer (same
/// assertions as the core never-revert test: both rotate handles, both
/// produce an amount ciphertext, both complete Ok).
#[test]
fn freezable_transfer_over_available_silently_zeroes() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut freezable = Freezable::new(FREEZER);
    token.mint(ALICE, 1000, &mut rng).unwrap();
    token.mint(BOB, 50, &mut rng).unwrap();
    let frozen = token.committee().encrypt(600, &mut rng).unwrap();
    freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();

    // 401 > available 400: silent zero.
    let alice_before = token.balance_handle(ALICE).unwrap();
    let bob_before = token.balance_handle(BOB).unwrap();
    let enc = token.committee().encrypt(401, &mut rng).unwrap();
    let zeroed = freezable
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(zeroed, ALICE, &mut rng).unwrap(), 0);
    assert_eq!(token.decrypt_for(zeroed, BOB, &mut rng).unwrap(), 0);
    assert_eq!(balance_of(&token, ALICE), 1000);
    assert_eq!(balance_of(&token, BOB), 50);
    // The call trace looks exactly like a successful transfer: handles
    // rotated, an amount ciphertext exists, the audit entry has the same
    // shape (two comparisons, two refreshes).
    assert_ne!(token.balance_handle(ALICE).unwrap(), alice_before);
    assert_ne!(token.balance_handle(BOB).unwrap(), bob_before);

    // 400 == available: succeeds.
    let enc = token.committee().encrypt(400, &mut rng).unwrap();
    let moved = freezable
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(moved, ALICE, &mut rng).unwrap(), 400);
    assert_eq!(balance_of(&token, ALICE), 600);
    assert_eq!(balance_of(&token, BOB), 450);

    // Indistinguishable audit shapes between the zeroed and successful
    // transfers.
    let log = freezable.audit_log();
    assert_eq!(log.len(), 2);
    for audit in log {
        assert_eq!(audit.refreshes.len(), 2);
        assert_eq!(
            audit.available_compare.blinds.len(),
            audit.guard_compare.blinds.len()
        );
    }
}

/// Only the freezer role may set frozen amounts.
#[test]
fn only_freezer_sets_frozen_amounts() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut freezable = Freezable::new(FREEZER);
    assert_eq!(freezable.freezer(), FREEZER);
    token.mint(ALICE, 100, &mut rng).unwrap();

    let frozen = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(
        freezable
            .set_confidential_frozen(&mut token, ALICE, ALICE, frozen)
            .is_err()
    );
    assert_eq!(freezable.confidential_frozen(ALICE), None);

    let frozen = token.committee().encrypt(10, &mut rng).unwrap();
    let handle = freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();
    // The frozen handle is ACL'd to the account and the freezer only.
    assert_eq!(token.decrypt_for(handle, ALICE, &mut rng).unwrap(), 10);
    assert_eq!(token.decrypt_for(handle, FREEZER, &mut rng).unwrap(), 10);
    assert!(token.decrypt_for(handle, BOB, &mut rng).is_err());
}

/// Leakage: the freezable transfer's extra comparison (the saturation
/// guard) appears in the audit log, and the single-party-view assertions
/// from the core token's e2e pass over BOTH comparisons — no transcript
/// value is a raw operand, and no single party can unblind the true
/// difference.
#[test]
fn freezable_audit_log_leaks_no_raw_operands() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut freezable = Freezable::new(FREEZER);
    let (balance, frozen_amount, amount) = (1000u64, 600u64, 401u64);
    token.mint(ALICE, balance, &mut rng).unwrap();
    let frozen = token.committee().encrypt(frozen_amount, &mut rng).unwrap();
    freezable
        .set_confidential_frozen(&mut token, FREEZER, ALICE, frozen)
        .unwrap();
    let enc = token.committee().encrypt(amount, &mut rng).unwrap();
    freezable
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();

    let available = balance.saturating_sub(frozen_amount);
    let audit = &freezable.audit_log()[0];
    // (transcript, lhs, rhs) for both comparisons of the transfer.
    let comparisons = [
        (&audit.available_compare, balance, frozen_amount),
        (&audit.guard_compare, available, amount),
    ];
    for (compare, lhs, rhs) in comparisons {
        let true_difference = lhs.wrapping_sub(rhs);
        let revealed = compare.revealed;
        assert_ne!(revealed, lhs);
        assert_ne!(revealed, rhs);
        assert_ne!(revealed, true_difference);
        for blind in &compare.blinds {
            assert!(*blind >= 3);
            let partially_unblinded = (revealed as i64).unsigned_abs() / blind;
            let residual = if (revealed as i64) < 0 {
                (partially_unblinded as i64).wrapping_neg() as u64
            } else {
                partially_unblinded
            };
            assert_ne!(residual, true_difference);
        }
    }
    // Refresh transcripts: removing any single party's own mask never
    // exposes a raw operand.
    for refresh in &audit.refreshes {
        for mask in &refresh.masks {
            let view = refresh.revealed.wrapping_sub(*mask);
            assert_ne!(view, balance);
            assert_ne!(view, frozen_amount);
            assert_ne!(view, amount);
        }
    }
    // The standalone available query logs its comparison too.
    freezable
        .confidential_available(&mut token, ALICE, &mut rng)
        .unwrap();
    assert_eq!(freezable.available_compares().len(), 1);
}

/// The confidential total supply, threshold-decrypted.
fn confidential_supply(token: &ConfidentialToken) -> u64 {
    token
        .committee()
        .threshold_decrypt(token.total_supply(), &mut rng())
        .unwrap()
}

/// Round-trip: wrap 1000 -> confidential transfer 300 -> unwrap 700
/// returns exactly 700 to the public ledger, with the reference model
/// matching at every step.
#[test]
fn wrap_transfer_unwrap_round_trip() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 1500);

    ledger.wrap(&mut token, ALICE, 1000, &mut rng).unwrap();
    assert_eq!(ledger.balance(ALICE), 500);
    assert_eq!(balance_of(&token, ALICE), 1000);
    assert_eq!(confidential_supply(&token), 1000);

    let enc = token.committee().encrypt(300, &mut rng).unwrap();
    token.transfer(ALICE, BOB, &enc, &mut rng).unwrap();
    assert_eq!(balance_of(&token, ALICE), 700);
    assert_eq!(balance_of(&token, BOB), 300);

    let amount = token.committee().encrypt(700, &mut rng).unwrap();
    let request = ledger.request_unwrap(ALICE, amount);
    assert_eq!(request.account(), ALICE);
    let revealed = ledger
        .finalize_unwrap(&mut token, request, &mut rng)
        .unwrap();
    assert_eq!(revealed, 700);
    assert_eq!(ledger.balance(ALICE), 1200);
    assert_eq!(balance_of(&token, ALICE), 0);
    assert_eq!(confidential_supply(&token), 300);
    // Wrapping is possible again after unwrap freed supply headroom.
    ledger.wrap(&mut token, ALICE, 100, &mut rng).unwrap();
    assert_eq!(balance_of(&token, ALICE), 100);
}

/// Conservation: public total + decrypted confidential supply is
/// constant across 20+ random wrap/transfer/unwrap operations.
#[test]
fn wrap_unwrap_conserves_combined_supply() {
    use rand::Rng;
    let mut rng = rng();
    let mut token = toy_token();
    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 10_000);
    ledger.credit(BOB, 10_000);
    let combined_total = 20_000;
    // Seed both confidential balances so transfers/unwraps have funds.
    ledger.wrap(&mut token, ALICE, 4_000, &mut rng).unwrap();
    ledger.wrap(&mut token, BOB, 4_000, &mut rng).unwrap();

    for i in 0..20 {
        let (a, b) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = rng.random_range(1..500u64);
        match i % 3 {
            0 => {
                // May Err if the public balance is short; conservation
                // must hold either way.
                let _ = ledger.wrap(&mut token, a, amount, &mut rng);
            }
            1 => {
                let enc = token.committee().encrypt(amount, &mut rng).unwrap();
                token.transfer(a, b, &enc, &mut rng).unwrap();
            }
            _ => {
                let enc = token.committee().encrypt(amount, &mut rng).unwrap();
                let request = ledger.request_unwrap(a, enc);
                let _ = ledger.finalize_unwrap(&mut token, request, &mut rng);
            }
        }
        assert_eq!(
            ledger.total() + confidential_supply(&token),
            combined_total,
            "conservation after operation {i}"
        );
    }
}

/// A finalize_unwrap whose account lacks the encrypted funds is an Err
/// and credits nothing — the documented failure semantics, pinned.
#[test]
fn finalize_unwrap_without_funds_errs_and_credits_nothing() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 1000);
    ledger.wrap(&mut token, ALICE, 400, &mut rng).unwrap();

    let enc = token.committee().encrypt(401, &mut rng).unwrap();
    let request = ledger.request_unwrap(ALICE, enc);
    assert!(
        ledger
            .finalize_unwrap(&mut token, request, &mut rng)
            .is_err()
    );
    // Nothing credited, nothing debited.
    assert_eq!(ledger.balance(ALICE), 600);
    assert_eq!(balance_of(&token, ALICE), 400);
    assert_eq!(confidential_supply(&token), 400);
    // The failed attempt still revealed its amount (the documented
    // leakage) and is in the audit log.
    assert_eq!(ledger.audit_log().len(), 1);
    assert_eq!(ledger.audit_log()[0].amount, 401);
    assert!(ledger.audit_log()[0].refreshes.is_empty());
}

/// The unwrap-reveals-amount leakage is asserted against the transcript:
/// the finalize step's decrypted value appears in the audit log, and the
/// funds-check transcript still hides the raw balance.
#[test]
fn unwrap_reveals_amount_in_audit_log() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 1000);
    ledger.wrap(&mut token, ALICE, 800, &mut rng).unwrap();

    let enc = token.committee().encrypt(150, &mut rng).unwrap();
    let request = ledger.request_unwrap(ALICE, enc);
    ledger
        .finalize_unwrap(&mut token, request, &mut rng)
        .unwrap();

    let audit = &ledger.audit_log()[0];
    // The decrypted unwrap amount is in the committee's transcript.
    assert_eq!(audit.amount, 150);
    assert_eq!(audit.refreshes.len(), 1);
    // The funds check still hides the raw balance from any single party.
    assert_ne!(audit.guard_compare.revealed, 800);
    assert_ne!(audit.guard_compare.revealed, 800 - 150);
    for blind in &audit.guard_compare.blinds {
        assert!(*blind >= 3);
        assert_ne!(audit.guard_compare.revealed / blind, 800 - 150);
    }
}

/// Public-side checks are public: wrapping more than the public balance
/// is a structural Err before any encrypted work.
#[test]
fn wrap_beyond_public_balance_errs() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 100);
    let handles_before = token.handles().len();
    assert!(ledger.wrap(&mut token, ALICE, 101, &mut rng).is_err());
    assert_eq!(token.handles().len(), handles_before);
    assert_eq!(ledger.balance(ALICE), 100);
    assert_eq!(ledger.total(), 100);
}

const AGENT: Account = 8;

/// Pause: transfers Err while paused and succeed after unpause; a
/// non-agent cannot pause.
#[test]
fn rwa_pause_blocks_transfers_publicly() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut rwa = Rwa::new(AGENT);
    token.mint(ALICE, 100, &mut rng).unwrap();

    assert!(rwa.pause(ALICE).is_err());
    assert!(!rwa.is_paused());
    rwa.pause(AGENT).unwrap();
    assert!(rwa.is_paused());

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    let handles_before = token.handles().len();
    assert!(
        rwa.transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    assert_eq!(token.handles().len(), handles_before);

    rwa.unpause(AGENT).unwrap();
    rwa.transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, BOB), 10);
}

/// Force transfer: succeeds from a blocked, frozen sender while paused —
/// but still cannot overdraw: forcing more than the balance silently
/// zeroes.
#[test]
fn rwa_force_transfer_bypasses_policy_but_not_balance() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut rwa = Rwa::new(AGENT);
    token.mint(ALICE, 100, &mut rng).unwrap();

    // Alice is blocked, fully frozen, and the token is paused.
    rwa.block_user(AGENT, ALICE).unwrap();
    let frozen = token.committee().encrypt(100, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, ALICE, frozen)
        .unwrap();
    rwa.pause(AGENT).unwrap();

    let amount = token.committee().encrypt(60, &mut rng).unwrap();
    // The policy transfer is blocked threefold...
    assert!(
        rwa.transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    // ...but the agent's force transfer goes through.
    let moved = rwa
        .force_transfer(&mut token, AGENT, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(moved, ALICE, &mut rng).unwrap(), 60);
    assert_eq!(balance_of(&token, ALICE), 40);
    assert_eq!(balance_of(&token, BOB), 60);

    // The balance guard stays: forcing 41 from the remaining 40 silently
    // zeroes (never-revert semantics, not an error).
    let amount = token.committee().encrypt(41, &mut rng).unwrap();
    let zeroed = rwa
        .force_transfer(&mut token, AGENT, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(zeroed, ALICE, &mut rng).unwrap(), 0);
    assert_eq!(balance_of(&token, ALICE), 40);
    assert_eq!(balance_of(&token, BOB), 60);
}

/// Recover: a wallet with balance 1000 of which 400 frozen recovers to a
/// new wallet holding balance 1000 with 400 still frozen — and the
/// frozen amount is never threshold-decrypted during recovery (asserted
/// over the audit log: only the blinded min comparison and masked
/// refreshes).
#[test]
fn rwa_recover_carries_frozen_amount_encrypted() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut rwa = Rwa::new(AGENT);
    const LOST: Account = 7;
    const NEW_WALLET: Account = 17;
    token.mint(LOST, 1000, &mut rng).unwrap();
    let frozen = token.committee().encrypt(400, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, LOST, frozen)
        .unwrap();

    rwa.recover(&mut token, AGENT, LOST, NEW_WALLET, &mut rng)
        .unwrap();

    // The full balance moved, frozen portion included.
    assert_eq!(balance_of(&token, LOST), 0);
    assert_eq!(balance_of(&token, NEW_WALLET), 1000);
    // The recovered wallet has 400 still frozen: 601 exceeds the
    // available 600 and silently zeroes, 600 succeeds.
    let frozen_handle = rwa.freezable().confidential_frozen(NEW_WALLET).unwrap();
    assert_eq!(
        token
            .decrypt_for(frozen_handle, NEW_WALLET, &mut rng)
            .unwrap(),
        400
    );
    assert_eq!(rwa.freezable().confidential_frozen(LOST), None);

    // The recovery's committee view: ONE blinded comparison (the
    // encrypted min) and masked refreshes — no decrypt of the frozen
    // value anywhere in the transcript.
    assert_eq!(rwa.recover_audits().len(), 1);
    let audit = &rwa.recover_audits()[0];
    assert_ne!(audit.min_compare.revealed, 400, "frozen value leaked");
    assert_ne!(audit.min_compare.revealed, 1000, "balance leaked");
    assert_ne!(
        audit.min_compare.revealed,
        1000 - 400,
        "true difference leaked"
    );
    for blind in &audit.min_compare.blinds {
        assert!(*blind >= 3);
        assert_ne!(audit.min_compare.revealed / blind, 1000 - 400);
    }
    assert_eq!(audit.refreshes.len(), 2);
    for refresh in &audit.refreshes {
        for mask in &refresh.masks {
            let view = refresh.revealed.wrapping_sub(*mask);
            assert_ne!(view, 400, "frozen value visible to a single party");
            assert_ne!(view, 1000, "balance visible to a single party");
        }
    }
}

/// Recover saturates: a frozen amount above the balance carries only the
/// balance (encrypted min), so the recovered wallet is fully frozen but
/// never over-frozen relative to what actually moved.
#[test]
fn rwa_recover_saturates_overfrozen_wallet() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut rwa = Rwa::new(AGENT);
    const LOST: Account = 7;
    const NEW_WALLET: Account = 17;
    token.mint(LOST, 300, &mut rng).unwrap();
    let frozen = token.committee().encrypt(900, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, LOST, frozen)
        .unwrap();

    rwa.recover(&mut token, AGENT, LOST, NEW_WALLET, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, NEW_WALLET), 300);
    let frozen_handle = rwa.freezable().confidential_frozen(NEW_WALLET).unwrap();
    assert_eq!(
        token
            .decrypt_for(frozen_handle, NEW_WALLET, &mut rng)
            .unwrap(),
        300
    );
}

/// Role enforcement: every agent-gated entry point Errs for non-agents.
#[test]
fn rwa_agent_gates_every_entry_point() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut rwa = Rwa::new(AGENT);
    token.mint(ALICE, 100, &mut rng).unwrap();
    assert!(rwa.is_agent(AGENT));
    assert!(!rwa.is_agent(ALICE));

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(rwa.pause(ALICE).is_err());
    assert!(rwa.unpause(ALICE).is_err());
    assert!(rwa.block_user(ALICE, BOB).is_err());
    assert!(rwa.unblock_user(ALICE, BOB).is_err());
    let frozen = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(
        rwa.set_confidential_frozen(&mut token, ALICE, ALICE, frozen)
            .is_err()
    );
    assert!(
        rwa.force_transfer(&mut token, ALICE, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    assert!(
        rwa.recover(&mut token, ALICE, ALICE, BOB, &mut rng)
            .is_err()
    );
    // None of the rejections did encrypted work or touched state.
    assert_eq!(balance_of(&token, ALICE), 100);
    assert!(!rwa.is_paused());
}
