//! Wall-clock timing for the ERC7984 extension suite at the curated
//! 128-bit parameters (degree 16384, six moduli): the cost of each
//! extension's characteristic operation on top of the core token —
//! public policy rejections (restricted/identity), the observed
//! transfer, the freezable double-guard transfer and available-amount
//! query, wrap and the two-phase unwrap, and the Rwa policy transfer,
//! force-transfer, and recovery. Run with and without `--features cuda`
//! to compare backends.

use std::time::Instant;

use fhe::gateway::Committee;
use fhe::token::ConfidentialToken;
use fhe::token::extensions::freezable::Freezable;
use fhe::token::extensions::identity::{IdentityCheck, InMemoryIdentityRegistry};
use fhe::token::extensions::observer::Observers;
use fhe::token::extensions::restricted::{Restriction, RestrictionMode, Restrictions};
use fhe::token::extensions::rwa::Rwa;
use fhe::token::extensions::wrapper::PublicLedger;
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const AGENT: u64 = 0;
const ALICE: u64 = 1;
const BOB: u64 = 2;
const EVE: u64 = 4;
const LOST: u64 = 7;
const NEW_WALLET: u64 = 8;
const FREEZER: u64 = 9;

const ITERS: u32 = 5;

fn report(label: &str, elapsed: std::time::Duration) {
    println!(
        "{label:<29} {:>10.3} s",
        elapsed.as_secs_f64() / f64::from(ITERS)
    );
}

#[allow(clippy::too_many_lines)]
fn main() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();

    let mut ledger = PublicLedger::new();
    ledger.credit(ALICE, 2_000_000);
    ledger.credit(LOST, 200_000);

    // Warm-up: one wrap and one transfer (the first CUDA call pays
    // kernel compilation).
    ledger.wrap(&mut token, ALICE, 1_000_000, &mut rng).unwrap();
    let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
    token.transfer(ALICE, BOB, &amount, &mut rng).unwrap();

    // Restricted: a blocked party rejects publicly, BEFORE any
    // encrypted work — this is the "policy rejection is free" claim.
    let mut restrictions = Restrictions::new(RestrictionMode::Blocklist);
    restrictions.set_restriction(BOB, Restriction::Blocked);
    let start = Instant::now();
    for _ in 0..ITERS {
        assert!(
            restrictions
                .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
                .is_err()
        );
    }
    report("restricted reject (public)", start.elapsed());
    restrictions.set_restriction(BOB, Restriction::Default);

    // Restricted transfer on the allowed path: core transfer + map
    // lookups.
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        restrictions
            .transfer(&mut token, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("restricted transfer", start.elapsed());

    // IdentityCheck transfer: core transfer + a registry lookup.
    let mut registry = InMemoryIdentityRegistry::new();
    registry.set_verified(ALICE, true);
    registry.set_verified(BOB, true);
    let identity = IdentityCheck::new(registry);
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        identity
            .transfer(&mut token, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("identity-checked transfer", start.elapsed());

    // ObserverAccess transfer: core transfer + ACL grants on the new
    // handles.
    let mut observers = Observers::new();
    observers.set_observer(ALICE, EVE);
    observers.set_observer(BOB, EVE);
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        observers
            .transfer(&mut token, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("observed transfer", start.elapsed());

    // Freezable: the double-guard transfer (one extra comparison and
    // select over the core circuit) and the available-amount query.
    let mut freezable = Freezable::new(FREEZER);
    for account in [ALICE, BOB] {
        let frozen = token.committee().encrypt(100, &mut rng).unwrap();
        freezable
            .set_confidential_frozen(&mut token, FREEZER, account, frozen)
            .unwrap();
    }
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        freezable
            .transfer(&mut token, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("freezable transfer", start.elapsed());

    let start = Instant::now();
    for _ in 0..ITERS {
        freezable
            .confidential_available(&mut token, ALICE, &mut rng)
            .unwrap();
    }
    report("available query", start.elapsed());

    // Wrapper: wrap (public debit + confidential mint) and the
    // two-phase unwrap whose finalize step threshold-decrypts the
    // amount and the funds check.
    let start = Instant::now();
    for _ in 0..ITERS {
        ledger.wrap(&mut token, ALICE, 1_000, &mut rng).unwrap();
    }
    report("wrap", start.elapsed());

    let start = Instant::now();
    for _ in 0..ITERS {
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        let request = ledger.request_unwrap(ALICE, amount);
        ledger
            .finalize_unwrap(&mut token, request, &mut rng)
            .unwrap();
    }
    report("unwrap (request + finalize)", start.elapsed());

    // Rwa: the policy transfer (pause + restriction checks + the
    // freezable double guard), the force transfer (core circuit), and
    // the recovery (encrypted min + unguarded move + two refreshes).
    let mut rwa = Rwa::new(AGENT);
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        rwa.transfer(&mut token, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("rwa transfer", start.elapsed());

    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        rwa.force_transfer(&mut token, AGENT, from, to, &amount, &mut rng)
            .unwrap();
    }
    report("rwa force transfer", start.elapsed());

    ledger.wrap(&mut token, LOST, 200_000, &mut rng).unwrap();
    let frozen = token.committee().encrypt(50_000, &mut rng).unwrap();
    rwa.set_confidential_frozen(&mut token, AGENT, LOST, frozen)
        .unwrap();
    let start = Instant::now();
    for i in 0..ITERS {
        // Recovery moves the full balance; alternate it back and forth.
        let (lost, recipient) = if i % 2 == 0 {
            (LOST, NEW_WALLET)
        } else {
            (NEW_WALLET, LOST)
        };
        rwa.recover(&mut token, AGENT, lost, recipient, &mut rng)
            .unwrap();
    }
    report("rwa recover", start.elapsed());
}
