//! G5: the full Goal E lifecycle driven entirely through signed
//! transactions from distinct keys, at the curated production
//! parameters (degree 16384, 291-bit q) — wrap, observers (with the
//! authentication binding proven), freezing, over/under-available
//! transfers, blocking, pause/unpause, force transfer, recovery, and
//! unwrap — asserting after every fulfillment that
//!
//! (a) on-chain handles rotated exactly as the fulfillment events say,
//! (b) coprocessor decryptions match the plaintext reference model,
//! (c) supply is conserved across the public ↔ confidential boundary,
//! (d) the Goal D/E leakage sweeps pass over the coprocessor's audit
//!     logs (no single party's view contains a raw operand), and the
//!     ACL denies an account that was never granted anything.
//!
//! The harness also measures request-tx → fulfillment-tx latency for
//! the two transfer circuits (run with `--nocapture` to see them; the
//! BENCHMARKS.md table is produced by this output, CPU and CUDA).

mod common;

use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use fhe::gateway::{Committee, CompareTranscript, RefreshTranscript};
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway::{self, TransferFulfilled};
use fhe_coprocessor::{Coprocessor, Service, harness};
use fhe_traits::Serialize;
use rand::rng;
use std::collections::HashMap;

/// The plaintext reference model, as in the Goal E e2e: public and
/// confidential balances plus the conservation target `combined`
/// (only faucet credits move it).
#[derive(Default)]
struct Reference {
    public: HashMap<Address, u64>,
    balances: HashMap<Address, u64>,
    supply: u64,
    combined: u64,
}

impl Reference {
    fn faucet(&mut self, account: Address, amount: u64) {
        *self.public.entry(account).or_default() += amount;
        self.combined += amount;
    }
    fn wrap(&mut self, account: Address, amount: u64) {
        *self.public.entry(account).or_default() -= amount;
        *self.balances.entry(account).or_default() += amount;
        self.supply += amount;
    }
    fn unwrap(&mut self, account: Address, amount: u64) {
        *self.balances.entry(account).or_default() -= amount;
        self.supply -= amount;
        *self.public.entry(account).or_default() += amount;
    }
    fn transfer(&mut self, from: Address, to: Address, amount: u64) {
        *self.balances.entry(from).or_default() -= amount;
        *self.balances.entry(to).or_default() += amount;
    }
    fn balance(&self, account: Address) -> u64 {
        self.balances.get(&account).copied().unwrap_or_default()
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

#[tokio::test]
async fn onchain_e2e() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING onchain_e2e: anvil/forge not found on PATH");
        return;
    }
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();
    eprintln!("e2e: generating committee keys");
    let committee = Committee::new(3, &params, &mut rng).unwrap();

    eprintln!("e2e: committee ready, spawning devnet");
    let devnet = common::spawn_devnet(7).await;
    let [alice, bob, carol, eve, lost, wallet2, intruder] = match devnet.users.as_slice() {
        [a, b, c, d, e, f, g] => [a, b, c, d, e, f, g],
        _ => unreachable!("spawn_devnet(7) yields 7 users"),
    };
    let coprocessor = Coprocessor::new(committee, params, devnet.agent.address).unwrap();
    let mut service = Service::new(
        coprocessor,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );

    let as_alice = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let as_bob = IConfidentialTokenGateway::new(devnet.gateway, bob.provider.clone());
    let as_carol = IConfidentialTokenGateway::new(devnet.gateway, carol.provider.clone());
    let as_lost = IConfidentialTokenGateway::new(devnet.gateway, lost.provider.clone());
    let as_wallet2 = IConfidentialTokenGateway::new(devnet.gateway, wallet2.provider.clone());
    let as_intruder = IConfidentialTokenGateway::new(devnet.gateway, intruder.provider.clone());
    let as_agent = IConfidentialTokenGateway::new(devnet.gateway, devnet.agent.provider.clone());

    let mut reference = Reference::default();
    // Raw operands of the freezable double guard (balance, frozen,
    // amount) per regular transfer, and of the core guard (balance,
    // amount) per force transfer, for the final leakage sweep.
    let mut raw_rwa: Vec<(u64, u64, u64)> = Vec::new();
    let mut raw_core: Vec<(u64, u64)> = Vec::new();
    // (label, request-tx → fulfillment-receipt) latency samples.
    let mut latencies: Vec<(&str, Duration)> = Vec::new();

    macro_rules! exec {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    macro_rules! input {
        ($owner:expr, $value:expr) => {{
            let ct = service
                .coprocessor()
                .committee()
                .encrypt($value, &mut rng)
                .unwrap();
            let (handle, _) = service
                .register_and_anchor($owner, &ct.to_bytes())
                .await
                .unwrap();
            handle
        }};
    }
    macro_rules! decrypt {
        ($handle:expr, $caller:expr) => {
            service.coprocessor_mut().decrypt_for($handle, $caller)
        };
    }
    macro_rules! balance_handle {
        ($who:expr) => {
            as_agent.balanceHandle($who.address).call().await.unwrap()
        };
    }
    /// Sends a transfer request, fulfills it, records latency, and
    /// asserts the on-chain handles rotated exactly as evented.
    macro_rules! timed_transfer {
        ($label:expr, $call:expr, $from:expr, $to:expr) => {{
            let started = Instant::now();
            exec!($call);
            service.catch_up().await.unwrap();
            latencies.push(($label, started.elapsed()));
            // (a) Handles rotated as evented: the latest
            // TransferFulfilled event's handles ARE the current ones.
            let logs = alice
                .provider
                .get_logs(
                    &Filter::new()
                        .address(devnet.gateway)
                        .event_signature(TransferFulfilled::SIGNATURE_HASH),
                )
                .await
                .unwrap();
            let event = logs
                .last()
                .unwrap()
                .log_decode::<TransferFulfilled>()
                .unwrap()
                .inner
                .data;
            assert_eq!(event.from, $from.address);
            assert_eq!(event.to, $to.address);
            assert_eq!(event.newFromHandle, balance_handle!($from));
            assert_eq!(event.newToHandle, balance_handle!($to));
            event.transferredHandle
        }};
    }
    /// The full reference-model assertion: (b) decryptions match, (c)
    /// conservation across the boundary, ACL denies the intruder.
    macro_rules! assert_state {
        () => {{
            for (account, expected) in reference.balances.clone() {
                let handle = as_agent.balanceHandle(account).call().await.unwrap();
                assert_eq!(decrypt!(handle, account).unwrap(), expected);
            }
            let mut public_total = 0u64;
            for (account, expected) in reference.public.clone() {
                let on_chain = as_agent.publicBalance(account).call().await.unwrap();
                assert_eq!(on_chain, expected);
                public_total += on_chain;
            }
            let state = service.coprocessor_mut();
            let supply = state
                .committee()
                .threshold_decrypt(state.token().total_supply(), &mut rng)
                .unwrap();
            assert_eq!(supply, reference.supply, "confidential supply");
            assert_eq!(public_total + supply, reference.combined, "conservation");
            // ACL: every kit handle denies the never-granted intruder.
            let intruder_account = state.account_of(intruder.address);
            for handle in state.token().handles() {
                assert!(!state.token().is_allowed(handle, intruder_account));
            }
        }};
    }

    eprintln!("e2e: step 1");
    // Step 1: fund the public side and wrap into confidential balances.
    exec!(as_alice.faucet(1_000_000));
    exec!(as_lost.faucet(50_000));
    exec!(as_intruder.faucet(1));
    exec!(as_alice.wrap(600_000));
    service.catch_up().await.unwrap();
    reference.faucet(alice.address, 1_000_000);
    reference.faucet(lost.address, 50_000);
    reference.faucet(intruder.address, 1);
    reference.wrap(alice.address, 600_000);
    assert_state!();

    eprintln!("e2e: step 2");
    // Step 2: identity — an unverified recipient reverts on-chain
    // (public check, before any coprocessor work), verification
    // restores transfers.
    let to_bob_50k = input!(alice.address, 50_000);
    assert!(
        as_alice
            .transfer(bob.address, to_bob_50k)
            .from(alice.address)
            .call()
            .await
            .is_err()
    );
    exec!(as_agent.setVerified(alice.address, true));
    exec!(as_agent.setVerified(bob.address, true));
    exec!(as_agent.setVerified(carol.address, true));
    exec!(as_bob.faucet(100_000));
    exec!(as_bob.wrap(100_000));
    service.catch_up().await.unwrap();
    reference.faucet(bob.address, 100_000);
    reference.wrap(bob.address, 100_000);
    raw_rwa.push((reference.balance(alice.address), 0, 50_000));
    timed_transfer!(
        "freezable transfer",
        as_alice.transfer(bob.address, to_bob_50k),
        alice,
        bob
    );
    reference.transfer(alice.address, bob.address, 50_000);
    assert_state!();

    eprintln!("e2e: step 3");
    // Step 3: observers — set by the account itself; a different
    // sender's setObserver cannot touch it (the Goal E caveat, closed).
    exec!(as_carol.setObserver(eve.address));
    exec!(as_carol.faucet(10_000));
    exec!(as_carol.wrap(10_000));
    service.catch_up().await.unwrap();
    reference.faucet(carol.address, 10_000);
    reference.wrap(carol.address, 10_000);
    // Eve observes carol from the wrap (the wrapper's mint grant).
    assert_eq!(
        decrypt!(balance_handle!(carol), eve.address).unwrap(),
        10_000
    );

    let pre_observer_handle = balance_handle!(alice);
    exec!(as_alice.setObserver(eve.address));
    // Bob's transaction can only set BOB's observer.
    exec!(as_bob.setObserver(bob.address));
    assert_eq!(
        as_agent.observerOf(alice.address).call().await.unwrap(),
        eve.address
    );
    service.catch_up().await.unwrap();
    let to_bob_25k = input!(alice.address, 25_000);
    raw_rwa.push((reference.balance(alice.address), 0, 25_000));
    let observed_amount = timed_transfer!(
        "freezable transfer",
        as_alice.transfer(bob.address, to_bob_25k),
        alice,
        bob
    );
    reference.transfer(alice.address, bob.address, 25_000);
    let granted_handle = balance_handle!(alice);
    assert_eq!(
        decrypt!(granted_handle, eve.address).unwrap(),
        reference.balance(alice.address)
    );
    assert_eq!(decrypt!(observed_amount, eve.address).unwrap(), 25_000);
    // No retroactive grants.
    assert!(decrypt!(pre_observer_handle, eve.address).is_err());

    // Removing the observer stops future grants without revoking past
    // ones.
    exec!(as_alice.setObserver(Address::ZERO));
    service.catch_up().await.unwrap();
    let to_carol_1k = input!(alice.address, 1_000);
    raw_rwa.push((reference.balance(alice.address), 0, 1_000));
    timed_transfer!(
        "freezable transfer",
        as_alice.transfer(carol.address, to_carol_1k),
        alice,
        carol
    );
    reference.transfer(alice.address, carol.address, 1_000);
    assert!(decrypt!(balance_handle!(alice), eve.address).is_err());
    assert_eq!(
        decrypt!(granted_handle, eve.address).unwrap(),
        reference.balance(alice.address) + 1_000
    );
    assert_state!();

    eprintln!("e2e: step 4");
    // Step 4: wrap the lost wallet's public funds.
    exec!(as_lost.wrap(50_000));
    service.catch_up().await.unwrap();
    reference.wrap(lost.address, 50_000);
    assert_state!();

    eprintln!("e2e: step 5");
    // Step 5: freeze part of alice's balance and prove the double
    // guard: one over the available amount silently zeroes, one at it
    // succeeds.
    let frozen_300k = input!(devnet.agent.address, 300_000);
    exec!(as_agent.setConfidentialFrozen(alice.address, frozen_300k));
    service.catch_up().await.unwrap();
    let frozen_handle = as_agent.frozenHandle(alice.address).call().await.unwrap();
    assert_eq!(decrypt!(frozen_handle, alice.address).unwrap(), 300_000);

    let available = reference.balance(alice.address) - 300_000;
    let over = input!(alice.address, available + 1);
    raw_rwa.push((reference.balance(alice.address), 300_000, available + 1));
    let zeroed = timed_transfer!(
        "freezable transfer (silent zero)",
        as_alice.transfer(bob.address, over),
        alice,
        bob
    );
    assert_eq!(decrypt!(zeroed, alice.address).unwrap(), 0);
    assert_state!(); // unchanged

    let at = input!(alice.address, available);
    raw_rwa.push((reference.balance(alice.address), 300_000, available));
    let moved = timed_transfer!(
        "freezable transfer",
        as_alice.transfer(bob.address, at),
        alice,
        bob
    );
    assert_eq!(decrypt!(moved, alice.address).unwrap(), available);
    reference.transfer(alice.address, bob.address, available);
    assert_state!();

    eprintln!("e2e: step 6");
    // Step 6: block bob — both directions revert on-chain, with no new
    // handles and no audit growth (no encrypted work at all).
    exec!(as_agent.setBlocked(bob.address, true));
    service.catch_up().await.unwrap();
    let handles_before = service.coprocessor().token().handles().len();
    let audits_before = service.coprocessor().rwa().freezable().audit_log().len();
    let blocked_input = input!(alice.address, 10);
    assert!(
        as_alice
            .transfer(bob.address, blocked_input)
            .from(alice.address)
            .call()
            .await
            .is_err()
    );
    let blocked_input_bob = input!(bob.address, 10);
    assert!(
        as_bob
            .transfer(alice.address, blocked_input_bob)
            .from(bob.address)
            .call()
            .await
            .is_err()
    );
    assert_eq!(
        service.coprocessor().token().handles().len(),
        handles_before
    );
    assert_eq!(
        service.coprocessor().rwa().freezable().audit_log().len(),
        audits_before
    );

    eprintln!("e2e: step 7");
    // Step 7: pause — only the agent may pause; paused transfers
    // revert; the agent force-transfers from a blocked, fully-frozen
    // sender while paused (core circuit, balance guard only).
    assert!(
        as_alice
            .setPaused(true)
            .from(alice.address)
            .call()
            .await
            .is_err()
    );
    exec!(as_agent.setPaused(true));
    service.catch_up().await.unwrap();
    let paused_input = input!(alice.address, 10);
    assert!(
        as_alice
            .transfer(carol.address, paused_input)
            .from(alice.address)
            .call()
            .await
            .is_err()
    );
    exec!(as_agent.setBlocked(alice.address, true));
    service.catch_up().await.unwrap();
    let force_50k = input!(devnet.agent.address, 50_000);
    assert!(
        as_alice
            .forceTransfer(alice.address, bob.address, force_50k)
            .from(alice.address)
            .call()
            .await
            .is_err(),
        "non-agent cannot force-transfer"
    );
    raw_core.push((reference.balance(alice.address), 50_000));
    timed_transfer!(
        "force transfer (core circuit)",
        as_agent.forceTransfer(alice.address, bob.address, force_50k),
        alice,
        bob
    );
    reference.transfer(alice.address, bob.address, 50_000);
    exec!(as_agent.setPaused(false));
    exec!(as_agent.setBlocked(alice.address, false));
    exec!(as_agent.setBlocked(bob.address, false));
    service.catch_up().await.unwrap();
    assert_state!();

    eprintln!("e2e: step 8");
    // Step 8: recover the lost wallet (50k balance, 20k frozen) into a
    // new wallet: the full balance moves; the frozen portion travels
    // encrypted (min(frozen, balance)) and re-freezes at the recipient,
    // never threshold-decrypted.
    let frozen_20k = input!(devnet.agent.address, 20_000);
    exec!(as_agent.setConfidentialFrozen(lost.address, frozen_20k));
    exec!(as_agent.recover(lost.address, wallet2.address));
    service.catch_up().await.unwrap();
    reference.transfer(lost.address, wallet2.address, 50_000);
    assert_eq!(
        as_agent.frozenHandle(lost.address).call().await.unwrap(),
        B256::ZERO
    );
    let recovered_frozen = as_agent.frozenHandle(wallet2.address).call().await.unwrap();
    assert_eq!(decrypt!(recovered_frozen, wallet2.address).unwrap(), 20_000);
    {
        let audits = service.coprocessor().rwa().recover_audits();
        assert_eq!(audits.len(), 1);
        let audit = audits.first().unwrap();
        assert_compare_hides(&audit.min_compare, 50_000, 20_000);
        assert_eq!(audit.refreshes.len(), 2);
        for refresh in &audit.refreshes {
            assert_refresh_hides(refresh, &[50_000, 20_000]);
        }
    }
    // The recovered frozen amount binds: over available zeroes, at it
    // succeeds.
    exec!(as_agent.setVerified(wallet2.address, true));
    service.catch_up().await.unwrap();
    let over = input!(wallet2.address, 30_001);
    raw_rwa.push((reference.balance(wallet2.address), 20_000, 30_001));
    let zeroed = timed_transfer!(
        "freezable transfer (silent zero)",
        as_wallet2.transfer(alice.address, over),
        wallet2,
        alice
    );
    assert_eq!(decrypt!(zeroed, wallet2.address).unwrap(), 0);
    let at = input!(wallet2.address, 30_000);
    raw_rwa.push((reference.balance(wallet2.address), 20_000, 30_000));
    timed_transfer!(
        "freezable transfer",
        as_wallet2.transfer(alice.address, at),
        wallet2,
        alice
    );
    reference.transfer(wallet2.address, alice.address, 30_000);
    assert_state!();

    eprintln!("e2e: step 9");
    // Step 9: unwrap back to the public side — the amount is revealed
    // by design and credits publicBalance; a failed unwrap credits
    // nothing and leaves the balance handle untouched.
    let unwrap_guard_operands = (reference.balance(alice.address), 200_000);
    let unwrap_200k = input!(alice.address, 200_000);
    exec!(as_alice.requestUnwrap(unwrap_200k));
    service.catch_up().await.unwrap();
    reference.unwrap(alice.address, 200_000);
    assert_state!();

    let handle_before = balance_handle!(alice);
    let unwrap_too_much = input!(alice.address, 1_000_000);
    exec!(as_alice.requestUnwrap(unwrap_too_much));
    service.catch_up().await.unwrap();
    assert_eq!(balance_handle!(alice), handle_before);
    assert_state!(); // nothing credited, nothing debited
    {
        let audits = service.coprocessor().ledger().audit_log();
        assert_eq!(audits.len(), 2);
        let success = audits.first().unwrap();
        assert_eq!(success.amount, 200_000);
        assert_compare_hides(
            &success.guard_compare,
            unwrap_guard_operands.0,
            unwrap_guard_operands.1,
        );
        assert_eq!(audits.get(1).unwrap().amount, 1_000_000);
    }

    // Final leakage sweep (d): the Goal D/E single-party-view
    // assertions over EVERY comparison and refresh the lifecycle
    // performed, against the reference model's raw operands.
    let state = service.coprocessor();
    let core_log = state.token().audit_log();
    assert_eq!(core_log.len(), raw_core.len());
    for (audit, (balance, amount)) in core_log.iter().zip(&raw_core) {
        assert_compare_hides(&audit.compare, *balance, *amount);
        for refresh in &audit.refreshes {
            assert_refresh_hides(refresh, &[*balance, *amount]);
        }
    }
    let rwa_log = state.rwa().freezable().audit_log();
    assert_eq!(rwa_log.len(), raw_rwa.len());
    for (audit, (balance, frozen, amount)) in rwa_log.iter().zip(&raw_rwa) {
        let available = balance.saturating_sub(*frozen);
        assert_compare_hides(&audit.available_compare, *balance, *frozen);
        assert_compare_hides(&audit.guard_compare, available, *amount);
        for refresh in &audit.refreshes {
            assert_refresh_hides(refresh, &[*balance, *frozen, *amount]);
        }
    }

    // The latency table for BENCHMARKS.md.
    println!("request-tx → fulfillment-tx latency:");
    let mut by_label: HashMap<&str, Vec<Duration>> = HashMap::new();
    for (label, duration) in &latencies {
        by_label.entry(label).or_default().push(*duration);
    }
    for (label, samples) in &by_label {
        let total: Duration = samples.iter().sum();
        let mean = total / u32::try_from(samples.len()).unwrap();
        println!(
            "  {label}: {:.2} s mean over {} samples",
            mean.as_secs_f64(),
            samples.len()
        );
    }
}
