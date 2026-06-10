//! G4: every Goal E extension driven by signed transactions, with the
//! contract-side gating proven by reverts (the forge suite pins the
//! exact errors per role/policy) and the encrypted semantics proven by
//! decryption against a plaintext reference: freeze makes an
//! over-available transfer zero, recovery carries the frozen amount
//! encrypted, unwrap reveals its amount and credits the public
//! ERC20-side balance (`publicBalance` is the chosen public
//! representation), and a failed unwrap credits nothing.
//!
//! Toy FHE parameters; the G5 e2e re-runs the lifecycle at production
//! parameters.

mod common;

use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Coprocessor, Service, harness};
use fhe_traits::Serialize;
use rand::rng;

#[tokio::test]
async fn extensions_drive_by_transaction() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING: anvil/forge not found on PATH");
        return;
    }
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();

    let devnet = common::spawn_devnet(4).await;
    let alice = devnet.users.first().unwrap();
    let bob = devnet.users.get(1).unwrap();
    let eve = devnet.users.get(2).unwrap();
    let wallet2 = devnet.users.get(3).unwrap();
    let coprocessor = Coprocessor::new(committee, params, devnet.agent.address).unwrap();
    let mut service = Service::new(
        coprocessor,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );

    let as_alice = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let as_bob = IConfidentialTokenGateway::new(devnet.gateway, bob.provider.clone());
    let as_wallet2 = IConfidentialTokenGateway::new(devnet.gateway, wallet2.provider.clone());
    let as_agent = IConfidentialTokenGateway::new(devnet.gateway, devnet.agent.provider.clone());

    macro_rules! exec {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    /// Registers an encrypted amount for `$owner` and returns its handle.
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
    macro_rules! balance {
        ($who:expr) => {{
            let handle = as_agent.balanceHandle($who.address).call().await.unwrap();
            service
                .coprocessor_mut()
                .decrypt_for(handle, $who.address)
                .unwrap()
        }};
    }

    // Fund: alice wraps 1000.
    exec!(as_agent.setVerified(alice.address, true));
    exec!(as_agent.setVerified(bob.address, true));
    exec!(as_alice.faucet(1000));
    exec!(as_alice.wrap(1000));
    service.catch_up().await.unwrap();

    // --- setObserver: msg.sender IS the account (closes the Goal E
    // unauthenticated set_observer caveat). ---
    let pre_observer_handle = as_alice.balanceHandle(alice.address).call().await.unwrap();
    exec!(as_alice.setObserver(eve.address));
    // A different sender CANNOT touch alice's observer: bob's tx sets
    // bob's own observer only.
    exec!(as_bob.setObserver(bob.address));
    assert_eq!(
        as_alice.observerOf(alice.address).call().await.unwrap(),
        eve.address
    );
    service.catch_up().await.unwrap();

    let transfer_100 = input!(alice.address, 100);
    exec!(as_alice.transfer(bob.address, transfer_100));
    service.catch_up().await.unwrap();
    // Eve (the observer) decrypts alice's rotated balance; the
    // pre-observer handle stays denied (no retroactive grants).
    let alice_handle = as_alice.balanceHandle(alice.address).call().await.unwrap();
    assert_eq!(
        service
            .coprocessor_mut()
            .decrypt_for(alice_handle, eve.address)
            .unwrap(),
        900
    );
    assert!(
        service
            .coprocessor_mut()
            .decrypt_for(pre_observer_handle, eve.address)
            .is_err()
    );

    // --- Freeze: agent sets an encrypted frozen amount; the transfer
    // guard becomes available = balance - frozen. ---
    let frozen_700 = input!(devnet.agent.address, 700);
    exec!(as_agent.setConfidentialFrozen(alice.address, frozen_700));
    service.catch_up().await.unwrap();
    let frozen_handle = as_agent.frozenHandle(alice.address).call().await.unwrap();
    assert_ne!(frozen_handle, [0u8; 32]);
    // ACL: the frozen account reads its own frozen amount.
    assert_eq!(
        service
            .coprocessor_mut()
            .decrypt_for(frozen_handle, alice.address)
            .unwrap(),
        700
    );

    // Over the available 200 (balance 900 - frozen 700): silent zero.
    let transfer_201 = input!(alice.address, 201);
    exec!(as_alice.transfer(bob.address, transfer_201));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(alice), 900);
    assert_eq!(balance!(bob), 100);
    // At the available amount: succeeds.
    let transfer_200 = input!(alice.address, 200);
    exec!(as_alice.transfer(bob.address, transfer_200));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(alice), 700);
    assert_eq!(balance!(bob), 300);

    // --- Block: a blocked party reverts on-chain, before any
    // coprocessor work. ---
    exec!(as_agent.setBlocked(bob.address, true));
    service.catch_up().await.unwrap();
    let transfer_1 = input!(alice.address, 1);
    assert!(
        as_alice
            .transfer(bob.address, transfer_1)
            .send()
            .await
            .is_err()
    );
    exec!(as_agent.setBlocked(bob.address, false));

    // --- Pause + force transfer: paused transfers revert; the agent's
    // force transfer bypasses pause, block, identity, AND the frozen
    // guard (alice's available is 0 < 50 — only the balance guards). ---
    exec!(as_agent.setPaused(true));
    service.catch_up().await.unwrap();
    assert!(
        as_alice
            .transfer(bob.address, transfer_1)
            .send()
            .await
            .is_err()
    );
    let force_50 = input!(devnet.agent.address, 50);
    exec!(as_agent.forceTransfer(alice.address, bob.address, force_50));
    exec!(as_agent.setPaused(false));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(alice), 650);
    assert_eq!(balance!(bob), 350);

    // --- Recover: alice's FULL balance (650) moves to wallet2; the
    // frozen amount travels encrypted as min(frozen 700, balance 650)
    // and re-freezes there. Never decrypted during recovery. ---
    exec!(as_agent.recover(alice.address, wallet2.address));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(alice), 0);
    assert_eq!(balance!(wallet2), 650);
    assert_eq!(
        as_agent.frozenHandle(alice.address).call().await.unwrap(),
        [0u8; 32]
    );
    let recovered_frozen = as_agent.frozenHandle(wallet2.address).call().await.unwrap();
    assert_eq!(
        service
            .coprocessor_mut()
            .decrypt_for(recovered_frozen, wallet2.address)
            .unwrap(),
        650
    );
    // The carried freeze binds: wallet2's available is 0, so any
    // transfer silently zeroes.
    let transfer_1b = input!(wallet2.address, 1);
    exec!(as_wallet2.transfer(alice.address, transfer_1b));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(wallet2), 650);
    assert_eq!(balance!(alice), 0);
    // The recovery's committee view held no decryption of the frozen
    // value: one blinded min-comparison, masked refreshes.
    assert_eq!(service.coprocessor().rwa().recover_audits().len(), 1);

    // --- Unwrap: reveals the amount (by design) and credits the public
    // ERC20-side balance. ---
    let unwrap_150 = input!(bob.address, 150);
    exec!(as_bob.requestUnwrap(unwrap_150));
    service.catch_up().await.unwrap();
    assert_eq!(balance!(bob), 200);
    assert_eq!(as_bob.publicBalance(bob.address).call().await.unwrap(), 150);
    // A failed unwrap (10000 > 200): fulfills as a public failure,
    // credits nothing, leaves the balance handle untouched.
    let handle_before = as_bob.balanceHandle(bob.address).call().await.unwrap();
    let unwrap_10000 = input!(bob.address, 10_000);
    exec!(as_bob.requestUnwrap(unwrap_10000));
    service.catch_up().await.unwrap();
    assert_eq!(
        as_bob.balanceHandle(bob.address).call().await.unwrap(),
        handle_before
    );
    assert_eq!(as_bob.publicBalance(bob.address).call().await.unwrap(), 150);
    assert_eq!(balance!(bob), 200);
    // The revealed amounts (success and failure) are the wrapper's
    // documented leakage, present in its audit log.
    let audits = service.coprocessor().ledger().audit_log();
    assert_eq!(audits.len(), 2);
    assert_eq!(audits.first().unwrap().amount, 150);
    assert_eq!(audits.get(1).unwrap().amount, 10_000);
}
