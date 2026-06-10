//! G3: the core transfer driven entirely by signed transactions. A
//! `transfer(to, handle)` transaction is fulfilled by the coprocessor:
//! on-chain handles rotate, balances decrypt to the plaintext
//! reference, and an insufficient transfer is the same silent zero —
//! the fulfillment succeeds and nothing on-chain (including gas)
//! distinguishes it. Sender authentication binds: a transaction from a
//! key not bound to the input reverts.
//!
//! Toy FHE parameters: the transaction plumbing is under test, not the
//! circuits (the Goal D/E suites and the G5 e2e cover those at
//! production parameters).

mod common;

use alloy::consensus::Transaction as _;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionReceipt;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Coprocessor, Service, harness};
use fhe_traits::Serialize;
use rand::rng;

#[tokio::test]
async fn transfer_by_transaction_rotates_handles_and_hides_insufficiency() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING: anvil/forge not found on PATH");
        return;
    }
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();

    let devnet = common::spawn_devnet(3).await;
    let alice = devnet.users.first().unwrap();
    let bob = devnet.users.get(1).unwrap();
    let eve = devnet.users.get(2).unwrap();
    let coprocessor = Coprocessor::new(committee, params, devnet.agent.address).unwrap();
    let mut service = Service::new(
        coprocessor,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );

    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let as_agent = IConfidentialTokenGateway::new(devnet.gateway, devnet.agent.provider.clone());
    let as_bob = IConfidentialTokenGateway::new(devnet.gateway, bob.provider.clone());
    let as_eve = IConfidentialTokenGateway::new(devnet.gateway, eve.provider.clone());

    // Fund alice confidentially: verify bob (the recipient), faucet,
    // wrap — all by transaction, all fulfilled by the coprocessor.
    macro_rules! exec {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    exec!(as_agent.setVerified(bob.address, true));
    exec!(gateway.faucet(1000));
    exec!(gateway.wrap(600));
    service.catch_up().await.unwrap();

    let alice_handle_0 = gateway.balanceHandle(alice.address).call().await.unwrap();
    assert_ne!(alice_handle_0, [0u8; 32]);
    // The decryption read path is driven by on-chain state: alice owns
    // her balance handle, so the coprocessor decrypts it for her.
    assert_eq!(
        service
            .coprocessor_mut()
            .decrypt_for(alice_handle_0, alice.address)
            .unwrap(),
        600
    );
    // The on-chain commitment matches the stored ciphertext bytes.
    let stored = service
        .coprocessor()
        .stored_bytes(alice_handle_0)
        .unwrap()
        .to_vec();
    assert_eq!(
        gateway
            .handleCommitment(alice_handle_0)
            .call()
            .await
            .unwrap(),
        alloy::primitives::keccak256(&stored)
    );

    // A signed transfer of an encrypted 250.
    let amount = service
        .coprocessor()
        .committee()
        .encrypt(250, &mut rng)
        .unwrap();
    let (input_250, _) = service
        .register_and_anchor(alice.address, &amount.to_bytes())
        .await
        .unwrap();
    exec!(gateway.transfer(bob.address, input_250));
    service.catch_up().await.unwrap();

    // Handles rotated as evented; balances decrypt to the reference.
    let alice_handle_1 = gateway.balanceHandle(alice.address).call().await.unwrap();
    let bob_handle_1 = gateway.balanceHandle(bob.address).call().await.unwrap();
    assert_ne!(alice_handle_1, alice_handle_0);
    assert_ne!(bob_handle_1, [0u8; 32]);
    let state = service.coprocessor_mut();
    assert_eq!(
        state.decrypt_for(alice_handle_1, alice.address).unwrap(),
        350
    );
    assert_eq!(state.decrypt_for(bob_handle_1, bob.address).unwrap(), 250);

    // A second successful transfer (100), now with every storage slot
    // warm — the gas baseline the silent zero must be compared against
    // (the first transfer pays bob's first-touch storage costs).
    let amount = service
        .coprocessor()
        .committee()
        .encrypt(100, &mut rng)
        .unwrap();
    let (input_100, _) = service
        .register_and_anchor(alice.address, &amount.to_bytes())
        .await
        .unwrap();
    exec!(gateway.transfer(bob.address, input_100));
    let fulfillments = service.catch_up().await.unwrap();
    let success_tx = *fulfillments.last().unwrap();

    // An insufficient transfer (1000 > 250): the fulfillment SUCCEEDS,
    // handles rotate, balances are unchanged — the silent zero.
    let too_much = service
        .coprocessor()
        .committee()
        .encrypt(1000, &mut rng)
        .unwrap();
    let (input_1000, _) = service
        .register_and_anchor(alice.address, &too_much.to_bytes())
        .await
        .unwrap();
    exec!(gateway.transfer(bob.address, input_1000));
    let fulfillments = service.catch_up().await.unwrap();
    let silent_zero_tx = *fulfillments.last().unwrap();

    let alice_handle_2 = gateway.balanceHandle(alice.address).call().await.unwrap();
    let bob_handle_2 = gateway.balanceHandle(bob.address).call().await.unwrap();
    assert_ne!(alice_handle_2, alice_handle_1);
    assert_ne!(bob_handle_2, bob_handle_1);
    let state = service.coprocessor_mut();
    assert_eq!(
        state.decrypt_for(alice_handle_2, alice.address).unwrap(),
        250
    );
    assert_eq!(state.decrypt_for(bob_handle_2, bob.address).unwrap(), 350);

    // Gas-shape equality: the successful and the silently-zeroed
    // fulfillment execute identically. Only the EIP-2028 calldata
    // discount for zero BYTES in the (random) handles/commitments may
    // differ, so it is normalized out; execution gas must be equal.
    let exec_gas = |tx| async move {
        let receipt: TransactionReceipt = alice
            .provider
            .get_transaction_receipt(tx)
            .await
            .unwrap()
            .unwrap();
        let tx = alice
            .provider
            .get_transaction_by_hash(tx)
            .await
            .unwrap()
            .unwrap();
        let calldata: u64 = tx
            .input()
            .iter()
            .map(|b| if *b == 0 { 4u64 } else { 16 })
            .sum();
        receipt.gas_used - calldata
    };
    assert_eq!(exec_gas(success_tx).await, exec_gas(silent_zero_tx).await);

    // Sender authentication: bob's key is not bound to alice's input —
    // his transaction reverts in the contract, before any coprocessor
    // work.
    let amount = service
        .coprocessor()
        .committee()
        .encrypt(1, &mut rng)
        .unwrap();
    let (alices_input, _) = service
        .register_and_anchor(alice.address, &amount.to_bytes())
        .await
        .unwrap();
    exec!(as_agent.setVerified(alice.address, true));
    service.catch_up().await.unwrap();
    assert!(
        as_bob
            .transfer(alice.address, alices_input)
            .from(bob.address)
            .call()
            .await
            .is_err()
    );

    // The decryption ACL binds too: eve (bound to an account by her own
    // faucet, but on no handle's allow-list) cannot read alice's balance.
    exec!(as_eve.faucet(1));
    service.catch_up().await.unwrap();
    assert!(
        service
            .coprocessor_mut()
            .decrypt_for(alice_handle_2, eve.address)
            .is_err()
    );
}
