//! Every Goal E extension driven through the user client, with the
//! contract-side gating proven by reverts (the forge suite pins the
//! exact errors per role/policy) and the encrypted semantics proven by
//! decryption against a plaintext reference: freeze makes an
//! over-available transfer zero, recovery carries the frozen amount
//! encrypted, unwrap reveals its amount and credits the public
//! ERC20-side balance (`publicBalance` is the chosen public
//! representation), and a failed unwrap credits nothing.
//!
//! Toy FHE parameters; the e2e re-runs the lifecycle at production
//! parameters.

mod common;

use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Operator, harness};
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
    let operator = Operator::new(
        committee,
        devnet.agent.address,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    )
    .unwrap();
    let as_alice = operator.client(alice.provider.clone(), alice.address).await;
    let as_bob = operator.client(bob.provider.clone(), bob.address).await;
    let as_eve = operator.client(eve.provider.clone(), eve.address).await;
    let as_wallet2 = operator
        .client(wallet2.provider.clone(), wallet2.address)
        .await;
    let as_agent = operator
        .client(devnet.agent.provider.clone(), devnet.agent.address)
        .await;
    let operator = operator.spawn();

    // Raw bindings for VIEW reads only (handle assertions).
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());

    // Fund: alice wraps 1000.
    as_agent.set_verified(alice.address, true).await.unwrap();
    as_agent.set_verified(bob.address, true).await.unwrap();
    as_alice.faucet(1000).await.unwrap();
    as_alice.wrap(1000).await.unwrap();

    // --- setObserver: msg.sender IS the account (closes the Goal E
    // unauthenticated set_observer caveat). ---
    let pre_observer_handle = gateway.balanceHandle(alice.address).call().await.unwrap();
    as_alice.set_observer(eve.address).await.unwrap();
    // A different sender CANNOT touch alice's observer: bob's call sets
    // bob's own observer only.
    as_bob.set_observer(bob.address).await.unwrap();
    assert_eq!(
        gateway.observerOf(alice.address).call().await.unwrap(),
        eve.address
    );

    let transfer_100 = as_alice.encrypt_input(100).await.unwrap();
    as_alice.transfer(bob.address, transfer_100).await.unwrap();
    // Eve (the observer) decrypts alice's rotated balance; the
    // pre-observer handle stays denied (no retroactive grants).
    assert_eq!(as_eve.balance(alice.address).await.unwrap(), 900);
    assert!(
        operator
            .state()
            .await
            .decrypt_for(pre_observer_handle, eve.address)
            .is_err()
    );

    // --- Freeze: agent sets an encrypted frozen amount; the transfer
    // guard becomes available = balance - frozen. ---
    let frozen_700 = as_agent.encrypt_input(700).await.unwrap();
    as_agent
        .set_frozen(alice.address, frozen_700)
        .await
        .unwrap();
    let frozen_handle = gateway.frozenHandle(alice.address).call().await.unwrap();
    assert_ne!(frozen_handle, [0u8; 32]);
    // ACL: the frozen account reads its own frozen amount.
    assert_eq!(as_alice.frozen(alice.address).await.unwrap(), 700);

    // Over the available 200 (balance 900 - frozen 700): silent zero.
    let transfer_201 = as_alice.encrypt_input(201).await.unwrap();
    as_alice.transfer(bob.address, transfer_201).await.unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 900);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 100);
    // At the available amount: succeeds.
    let transfer_200 = as_alice.encrypt_input(200).await.unwrap();
    as_alice.transfer(bob.address, transfer_200).await.unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 700);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 300);

    // --- Block: a blocked party reverts on-chain, before any
    // coprocessor work. ---
    as_agent.set_blocked(bob.address, true).await.unwrap();
    let transfer_1 = as_alice.encrypt_input(1).await.unwrap();
    assert!(as_alice.transfer(bob.address, transfer_1).await.is_err());
    as_agent.set_blocked(bob.address, false).await.unwrap();

    // --- Pause + force transfer: paused transfers revert; the agent's
    // force transfer bypasses pause, block, identity, AND the frozen
    // guard (alice's available is 0 < 50 — only the balance guards). ---
    as_agent.set_paused(true).await.unwrap();
    assert!(as_alice.transfer(bob.address, transfer_1).await.is_err());
    let force_50 = as_agent.encrypt_input(50).await.unwrap();
    as_agent
        .force_transfer(alice.address, bob.address, force_50)
        .await
        .unwrap();
    as_agent.set_paused(false).await.unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 650);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 350);

    // --- Recover: alice's FULL balance (650) moves to wallet2; the
    // frozen amount travels encrypted as min(frozen 700, balance 650)
    // and re-freezes there. Never decrypted during recovery. ---
    as_agent
        .recover(alice.address, wallet2.address)
        .await
        .unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 0);
    assert_eq!(as_wallet2.balance(wallet2.address).await.unwrap(), 650);
    assert_eq!(
        gateway.frozenHandle(alice.address).call().await.unwrap(),
        [0u8; 32]
    );
    assert_eq!(as_wallet2.frozen(wallet2.address).await.unwrap(), 650);
    // The carried freeze binds: wallet2's available is 0, so any
    // transfer silently zeroes.
    let transfer_1b = as_wallet2.encrypt_input(1).await.unwrap();
    as_wallet2
        .transfer(alice.address, transfer_1b)
        .await
        .unwrap();
    assert_eq!(as_wallet2.balance(wallet2.address).await.unwrap(), 650);
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 0);
    // The recovery's committee view held no decryption of the frozen
    // value: one blinded min-comparison, masked refreshes.
    assert_eq!(operator.state().await.rwa().recover_audits().len(), 1);

    // --- Unwrap: reveals the amount (by design) and credits the public
    // ERC20-side balance. ---
    let unwrap_150 = as_bob.encrypt_input(150).await.unwrap();
    assert_eq!(as_bob.unwrap(unwrap_150).await.unwrap(), (150, true));
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 200);
    assert_eq!(as_bob.public_balance(bob.address).await.unwrap(), 150);
    // A failed unwrap (10000 > 200): fulfills as a public failure,
    // credits nothing, leaves the balance handle untouched.
    let handle_before = gateway.balanceHandle(bob.address).call().await.unwrap();
    let unwrap_10000 = as_bob.encrypt_input(10_000).await.unwrap();
    assert_eq!(as_bob.unwrap(unwrap_10000).await.unwrap(), (10_000, false));
    assert_eq!(
        gateway.balanceHandle(bob.address).call().await.unwrap(),
        handle_before
    );
    assert_eq!(as_bob.public_balance(bob.address).await.unwrap(), 150);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 200);
    // The revealed amounts (success and failure) are the wrapper's
    // documented leakage, present in its audit log.
    {
        let state = operator.state().await;
        let audits = state.ledger().audit_log();
        assert_eq!(audits.len(), 2);
        assert_eq!(audits.first().unwrap().amount, 150);
        assert_eq!(audits.get(1).unwrap().amount, 10_000);
    }

    operator.shutdown().await.unwrap();
}
