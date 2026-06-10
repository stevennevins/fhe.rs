//! End-to-end validation of the ERC7984 extension suite — the master
//! verification for Goal E: one RWA lifecycle at the curated production
//! parameters exercising every extension (restrictions, identity checks,
//! observers, encrypted freezing, the public-ledger wrapper, and the Rwa
//! composition), with a plaintext reference model asserted after every
//! step, the supply-conservation invariant across the public ↔
//! confidential boundary, and the Goal D leakage/ACL invariants extended
//! to every new committee comparison.
//!
//! Runs at the curated production parameters (degree 16384, 291-bit q),
//! NOT toy parameters.

use std::collections::HashMap;

use fhe::gateway::{Committee, CompareTranscript, RefreshTranscript};
use fhe::token::extensions::freezable::Freezable;
use fhe::token::extensions::identity::{IdentityCheck, IdentityRegistry, InMemoryIdentityRegistry};
use fhe::token::extensions::observer::Observers;
use fhe::token::extensions::restricted::{Restriction, RestrictionMode, Restrictions};
use fhe::token::extensions::rwa::Rwa;
use fhe::token::extensions::wrapper::PublicLedger;
use fhe::token::{Account, ConfidentialToken};
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;
use rand::rngs::ThreadRng;

const AGENT: Account = 0;
const ALICE: Account = 1;
const BOB: Account = 2;
const CAROL: Account = 3;
const EVE: Account = 4;
const LOST: Account = 7;
const NEW_WALLET: Account = 8;
const FREEZER: Account = 9;
const INTRUDER: Account = 999;

/// The plaintext reference model: public balances, confidential
/// balances, and the confidential supply. `combined` is the
/// conservation target across the public ↔ confidential boundary —
/// only credits and mints move it; wrap/unwrap/transfers must not.
#[derive(Default)]
struct Reference {
    public: HashMap<Account, u64>,
    balances: HashMap<Account, u64>,
    supply: u64,
    combined: u64,
}

impl Reference {
    fn credit(&mut self, account: Account, amount: u64) {
        *self.public.entry(account).or_default() += amount;
        self.combined += amount;
    }

    fn mint(&mut self, to: Account, amount: u64) {
        *self.balances.entry(to).or_default() += amount;
        self.supply += amount;
        self.combined += amount;
    }

    fn wrap(&mut self, account: Account, amount: u64) {
        *self.public.entry(account).or_default() -= amount;
        *self.balances.entry(account).or_default() += amount;
        self.supply += amount;
    }

    fn unwrap(&mut self, account: Account, amount: u64) {
        *self.balances.entry(account).or_default() -= amount;
        self.supply -= amount;
        *self.public.entry(account).or_default() += amount;
    }

    fn transfer(&mut self, from: Account, to: Account, amount: u64) {
        *self.balances.entry(from).or_default() -= amount;
        *self.balances.entry(to).or_default() += amount;
    }
}

/// Asserts the full reference model and the per-step invariants: every
/// confidential balance and the supply decrypt to the reference, the
/// public ledger matches, the combined supply is conserved, and every
/// stored handle denies the intruder.
fn assert_state(
    token: &ConfidentialToken,
    ledger: &PublicLedger,
    reference: &Reference,
    rng: &mut ThreadRng,
) {
    for (account, expected) in &reference.balances {
        let handle = token.balance_handle(*account).unwrap();
        assert_eq!(
            token.decrypt_for(handle, *account, rng).unwrap(),
            *expected,
            "balance of account {account}"
        );
    }
    let supply = token
        .committee()
        .threshold_decrypt(token.total_supply(), rng)
        .unwrap();
    assert_eq!(supply, reference.supply, "confidential supply");
    for (account, expected) in &reference.public {
        assert_eq!(
            ledger.balance(*account),
            *expected,
            "public balance of account {account}"
        );
    }
    // Conservation across the public ↔ confidential boundary.
    assert_eq!(ledger.total() + supply, reference.combined, "conservation");
    // ACL: every stored handle denies an account never granted access.
    for handle in token.handles() {
        assert!(!token.is_allowed(handle, INTRUDER));
        assert!(token.ciphertext(handle, INTRUDER).is_err());
    }
}

/// The Goal D single-party-view assertions over one comparison
/// transcript, against the raw operands the reference model knows.
fn assert_compare_hides(compare: &CompareTranscript, lhs: u64, rhs: u64) {
    let true_difference = lhs.wrapping_sub(rhs);
    let revealed = compare.revealed;
    assert_ne!(revealed, lhs);
    assert_ne!(revealed, rhs);
    if true_difference != 0 {
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
}

/// Refresh transcripts reveal only masked values: removing any single
/// party's own mask never exposes a raw operand.
fn assert_refresh_hides(refresh: &RefreshTranscript, operands: &[u64]) {
    for mask in &refresh.masks {
        let view = refresh.revealed.wrapping_sub(*mask);
        for operand in operands {
            assert_ne!(view, *operand);
        }
    }
}

/// The full RWA lifecycle at production parameters. Every public item
/// added in G1-G6 is exercised here (see the PR description for the
/// item-by-item map).
#[test]
fn erc7984_extensions_e2e() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());

    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();
    let mut ledger = PublicLedger::new();
    let mut reference = Reference::default();
    // Raw operands of core-token comparisons (sender balance, amount),
    // in audit-log order, for the leakage sweep at the end.
    let mut raw_core: Vec<(u64, u64)> = Vec::new();
    // Raw operands of freezable comparisons (balance, frozen, amount).
    let mut raw_rwa: Vec<(u64, u64, u64)> = Vec::new();

    // Step 1: fund the public side and wrap into confidential balances.
    ledger.credit(ALICE, 1_000_000);
    reference.credit(ALICE, 1_000_000);
    ledger.credit(LOST, 50_000);
    reference.credit(LOST, 50_000);
    ledger.wrap(&mut token, ALICE, 600_000, &mut rng).unwrap();
    reference.wrap(ALICE, 600_000);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 2: identity checks — minting to an unverified recipient is a
    // public structural Err; verification restores mint and transfer.
    let mut identity = IdentityCheck::new(InMemoryIdentityRegistry::new());
    assert!(identity.mint(&mut token, BOB, 100_000, &mut rng).is_err());
    assert!(identity.check_recipient(BOB).is_err());
    identity.registry_mut().set_verified(BOB, true);
    assert!(identity.registry().is_verified(BOB));
    identity.mint(&mut token, BOB, 100_000, &mut rng).unwrap();
    reference.mint(BOB, 100_000);
    let enc = token.committee().encrypt(50_000, &mut rng).unwrap();
    raw_core.push((reference.balances[&ALICE], 50_000));
    identity
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    reference.transfer(ALICE, BOB, 50_000);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 3: observers — eve observes alice and carol; new handles are
    // granted, pre-observer handles stay denied, removal stops future
    // grants without revoking past ones.
    let mut observers = Observers::new();
    observers.set_observer(CAROL, EVE);
    let carol_minted = observers.mint(&mut token, CAROL, 10_000, &mut rng).unwrap();
    reference.mint(CAROL, 10_000);
    assert_eq!(
        token.decrypt_for(carol_minted, EVE, &mut rng).unwrap(),
        10_000
    );

    let pre_observer_handle = token.balance_handle(ALICE).unwrap();
    observers.set_observer(ALICE, EVE);
    assert_eq!(observers.observer(ALICE), Some(EVE));
    let enc = token.committee().encrypt(25_000, &mut rng).unwrap();
    raw_core.push((reference.balances[&ALICE], 25_000));
    let observed_amount = observers
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    reference.transfer(ALICE, BOB, 25_000);
    let alice_balance = token.balance_handle(ALICE).unwrap();
    assert_eq!(
        token.decrypt_for(alice_balance, EVE, &mut rng).unwrap(),
        reference.balances[&ALICE]
    );
    assert_eq!(
        token.decrypt_for(observed_amount, EVE, &mut rng).unwrap(),
        25_000
    );
    assert!(!token.is_allowed(pre_observer_handle, EVE));
    observers.remove_observer(ALICE);
    assert_eq!(observers.observer(ALICE), None);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 4: standalone restrictions in allowlist mode — default-deny,
    // explicit allowance restores transfers. (Blocklist mode is
    // exercised through the Rwa composition below.)
    let mut restrictions = Restrictions::new(RestrictionMode::Allowlist);
    assert_eq!(restrictions.mode(), RestrictionMode::Allowlist);
    assert_eq!(restrictions.restriction(ALICE), Restriction::Default);
    assert!(!restrictions.is_user_allowed(ALICE));
    assert!(restrictions.check_transfer(ALICE, CAROL).is_err());
    let enc = token.committee().encrypt(1_000, &mut rng).unwrap();
    assert!(
        restrictions
            .transfer(&mut token, ALICE, CAROL, &enc, &mut rng)
            .is_err()
    );
    restrictions.set_restriction(ALICE, Restriction::Allowed);
    restrictions.set_restriction(CAROL, Restriction::Allowed);
    raw_core.push((reference.balances[&ALICE], 1_000));
    restrictions
        .transfer(&mut token, ALICE, CAROL, &enc, &mut rng)
        .unwrap();
    reference.transfer(ALICE, CAROL, 1_000);
    // The observer was removed before this transfer: alice's newest
    // balance handle is NOT granted to eve, while the granted one from
    // step 3 still decrypts (no revocation).
    assert!(!token.is_allowed(token.balance_handle(ALICE).unwrap(), EVE));
    assert_eq!(
        token.decrypt_for(alice_balance, EVE, &mut rng).unwrap(),
        reference.balances[&ALICE] + 1_000
    );
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 5: wrap the lost wallet's public funds.
    ledger.wrap(&mut token, LOST, 50_000, &mut rng).unwrap();
    reference.wrap(LOST, 50_000);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 6: the Rwa policy — freeze part of alice's balance and prove
    // the double guard: one over the available amount silently zeroes,
    // one at it succeeds.
    let mut rwa = Rwa::new(AGENT);
    assert!(rwa.is_agent(AGENT) && !rwa.is_agent(ALICE));
    let frozen = token.committee().encrypt(300_000, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, ALICE, frozen)
        .unwrap();
    let alice_frozen = rwa.freezable().confidential_frozen(ALICE).unwrap();
    assert_eq!(
        token.decrypt_for(alice_frozen, ALICE, &mut rng).unwrap(),
        300_000
    );

    let available = reference.balances[&ALICE] - 300_000;
    let enc = token.committee().encrypt(available + 1, &mut rng).unwrap();
    raw_rwa.push((reference.balances[&ALICE], 300_000, available + 1));
    let zeroed = rwa
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(zeroed, ALICE, &mut rng).unwrap(), 0);
    assert_state(&token, &ledger, &reference, &mut rng); // unchanged

    let enc = token.committee().encrypt(available, &mut rng).unwrap();
    raw_rwa.push((reference.balances[&ALICE], 300_000, available));
    let moved = rwa
        .transfer(&mut token, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    assert_eq!(
        token.decrypt_for(moved, ALICE, &mut rng).unwrap(),
        available
    );
    reference.transfer(ALICE, BOB, available);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 7: block a user and prove the public revert — before any
    // encrypted work, so no handles and no audit growth.
    rwa.block_user(AGENT, BOB).unwrap();
    assert_eq!(rwa.restrictions().restriction(BOB), Restriction::Blocked);
    let handles_before = token.handles().len();
    let audits_before = rwa.freezable().audit_log().len();
    let enc = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(
        rwa.transfer(&mut token, ALICE, BOB, &enc, &mut rng)
            .is_err()
    );
    assert!(
        rwa.transfer(&mut token, BOB, ALICE, &enc, &mut rng)
            .is_err()
    );
    assert_eq!(token.handles().len(), handles_before);
    assert_eq!(rwa.freezable().audit_log().len(), audits_before);

    // Step 8: pause/unpause — paused transfers are public Errs; only
    // the agent may pause.
    assert!(rwa.pause(ALICE).is_err());
    rwa.pause(AGENT).unwrap();
    assert!(rwa.is_paused());
    assert!(
        rwa.transfer(&mut token, ALICE, CAROL, &enc, &mut rng)
            .is_err()
    );

    // Step 9: force-transfer from a blocked, fully-frozen sender while
    // paused (alice: balance 250k+24k? no — balance 300k, frozen 300k).
    rwa.block_user(AGENT, ALICE).unwrap();
    let enc = token.committee().encrypt(50_000, &mut rng).unwrap();
    assert!(
        rwa.force_transfer(&mut token, ALICE, ALICE, BOB, &enc, &mut rng)
            .is_err(),
        "non-agent cannot force-transfer"
    );
    raw_core.push((reference.balances[&ALICE], 50_000));
    rwa.force_transfer(&mut token, AGENT, ALICE, BOB, &enc, &mut rng)
        .unwrap();
    reference.transfer(ALICE, BOB, 50_000);
    rwa.unpause(AGENT).unwrap();
    assert!(!rwa.is_paused());
    rwa.unblock_user(AGENT, ALICE).unwrap();
    rwa.unblock_user(AGENT, BOB).unwrap();
    assert_eq!(rwa.restrictions().restriction(BOB), Restriction::Default);
    assert!(rwa.restrictions().is_user_allowed(BOB));
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 10: recover the lost wallet (balance 50k, 20k frozen) into a
    // new wallet — full balance moves, the frozen portion travels
    // encrypted and re-freezes at the recipient.
    let frozen = token.committee().encrypt(20_000, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, LOST, frozen)
        .unwrap();
    rwa.recover(&mut token, AGENT, LOST, NEW_WALLET, &mut rng)
        .unwrap();
    reference.transfer(LOST, NEW_WALLET, 50_000);
    let recovered_frozen = rwa.freezable().confidential_frozen(NEW_WALLET).unwrap();
    assert_eq!(
        token
            .decrypt_for(recovered_frozen, NEW_WALLET, &mut rng)
            .unwrap(),
        20_000
    );
    assert_eq!(rwa.freezable().confidential_frozen(LOST), None);
    // The recovery never threshold-decrypted the frozen value: its
    // committee view is one blinded comparison and masked refreshes.
    assert_eq!(rwa.recover_audits().len(), 1);
    let audit = &rwa.recover_audits()[0];
    assert_compare_hides(&audit.min_compare, 50_000, 20_000);
    assert_eq!(audit.refreshes.len(), 2);
    for refresh in &audit.refreshes {
        assert_refresh_hides(refresh, &[50_000, 20_000]);
    }
    // The recovered frozen amount binds: over available zeroes, at it
    // succeeds.
    let enc = token.committee().encrypt(30_001, &mut rng).unwrap();
    raw_rwa.push((reference.balances[&NEW_WALLET], 20_000, 30_001));
    let zeroed = rwa
        .transfer(&mut token, NEW_WALLET, ALICE, &enc, &mut rng)
        .unwrap();
    assert_eq!(token.decrypt_for(zeroed, NEW_WALLET, &mut rng).unwrap(), 0);
    let enc = token.committee().encrypt(30_000, &mut rng).unwrap();
    raw_rwa.push((reference.balances[&NEW_WALLET], 20_000, 30_000));
    rwa.transfer(&mut token, NEW_WALLET, ALICE, &enc, &mut rng)
        .unwrap();
    reference.transfer(NEW_WALLET, ALICE, 30_000);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 11: the standalone freezable extension — direct freezer-role
    // API and the available-amount query.
    let mut freezable = Freezable::new(FREEZER);
    assert_eq!(freezable.freezer(), FREEZER);
    let frozen = token.committee().encrypt(4_000, &mut rng).unwrap();
    assert!(
        freezable
            .set_confidential_frozen(&mut token, ALICE, CAROL, frozen.clone())
            .is_err(),
        "only the freezer may freeze"
    );
    freezable
        .set_confidential_frozen(&mut token, FREEZER, CAROL, frozen)
        .unwrap();
    let carol_frozen = freezable.confidential_frozen(CAROL).unwrap();
    assert_eq!(
        token.decrypt_for(carol_frozen, FREEZER, &mut rng).unwrap(),
        4_000
    );
    let carol_available = freezable
        .confidential_available(&mut token, CAROL, &mut rng)
        .unwrap();
    let expected_available = reference.balances[&CAROL] - 4_000;
    assert_eq!(
        token.decrypt_for(carol_available, CAROL, &mut rng).unwrap(),
        expected_available
    );
    assert_eq!(freezable.available_compares().len(), 1);
    assert_compare_hides(
        &freezable.available_compares()[0],
        reference.balances[&CAROL],
        4_000,
    );
    let enc = token
        .committee()
        .encrypt(expected_available, &mut rng)
        .unwrap();
    let frozen_before = (reference.balances[&CAROL], 4_000, expected_available);
    freezable
        .transfer(&mut token, CAROL, ALICE, &enc, &mut rng)
        .unwrap();
    reference.transfer(CAROL, ALICE, expected_available);
    assert_state(&token, &ledger, &reference, &mut rng);

    // Step 12: unwrap back to the public ledger — the two-phase flow
    // whose finalize step reveals the amount by design.
    let enc = token.committee().encrypt(200_000, &mut rng).unwrap();
    let request = ledger.request_unwrap(ALICE, enc);
    assert_eq!(request.account(), ALICE);
    let revealed = ledger
        .finalize_unwrap(&mut token, request, &mut rng)
        .unwrap();
    assert_eq!(revealed, 200_000);
    reference.unwrap(ALICE, 200_000);
    assert_state(&token, &ledger, &reference, &mut rng);
    // The revealed amount is in the unwrap audit log (the documented
    // leakage), and the funds check hid the raw balance.
    assert_eq!(ledger.audit_log().len(), 1);
    assert_eq!(ledger.audit_log()[0].amount, 200_000);
    assert_compare_hides(
        &ledger.audit_log()[0].guard_compare,
        reference.balances[&ALICE] + 200_000,
        200_000,
    );

    // Final leakage sweep: the Goal D single-party-view assertions over
    // EVERY comparison and refresh the lifecycle performed, core and
    // extension alike, against the reference model's raw operands.
    assert_eq!(token.audit_log().len(), raw_core.len());
    for (audit, (balance, amount)) in token.audit_log().iter().zip(&raw_core) {
        assert_compare_hides(&audit.compare, *balance, *amount);
        for refresh in &audit.refreshes {
            assert_refresh_hides(refresh, &[*balance, *amount]);
        }
    }
    let rwa_log = rwa.freezable().audit_log();
    assert_eq!(rwa_log.len(), raw_rwa.len());
    for (audit, (balance, frozen, amount)) in rwa_log.iter().zip(&raw_rwa) {
        let available = balance.saturating_sub(*frozen);
        assert_compare_hides(&audit.available_compare, *balance, *frozen);
        assert_compare_hides(&audit.guard_compare, available, *amount);
        for refresh in &audit.refreshes {
            assert_refresh_hides(refresh, &[*balance, *frozen, *amount]);
        }
    }
    let (balance, frozen, amount) = frozen_before;
    let standalone = &freezable.audit_log()[0];
    assert_compare_hides(&standalone.available_compare, balance, frozen);
    assert_compare_hides(&standalone.guard_compare, balance - frozen, amount);
}
