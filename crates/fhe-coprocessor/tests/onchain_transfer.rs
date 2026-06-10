//! G3 (Goal F), rewritten against the user client (Goal G): a
//! `transfer(to, input)` call is fulfilled by the spawned operator:
//! on-chain handles rotate, balances decrypt to the plaintext
//! reference, and an insufficient transfer is the same silent zero —
//! the fulfillment succeeds and nothing on-chain (including gas)
//! distinguishes it. Sender authentication binds: a transaction from a
//! key not bound to the input reverts.
//!
//! Toy FHE parameters: the transaction plumbing is under test, not the
//! circuits (the Goal D/E suites and the e2e cover those at production
//! parameters).

mod common;

use alloy::consensus::Transaction as _;
use alloy::primitives::keccak256;
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, TransactionReceipt};
use alloy::sol_types::SolEvent;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway::{self, TransferFulfilled};
use fhe_coprocessor::{Operator, harness};
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
    let as_agent = operator
        .client(devnet.agent.provider.clone(), devnet.agent.address)
        .await;
    let operator = operator.spawn();

    // Raw bindings for VIEW reads only (handle-rotation assertions).
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());

    // Fund alice confidentially: verify bob (the recipient), faucet,
    // wrap — each client call resolves on its fulfillment.
    as_agent.set_verified(bob.address, true).await.unwrap();
    as_alice.faucet(1000).await.unwrap();
    as_alice.wrap(600).await.unwrap();

    let alice_handle_0 = gateway.balanceHandle(alice.address).call().await.unwrap();
    assert_ne!(alice_handle_0, [0u8; 32]);
    // The decryption read path is driven by on-chain state: alice owns
    // her balance handle, so the coprocessor decrypts it for her.
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 600);
    // The on-chain commitment matches the stored ciphertext bytes.
    let stored = operator
        .state()
        .await
        .stored_bytes(alice_handle_0)
        .unwrap()
        .to_vec();
    assert_eq!(
        gateway
            .handleCommitment(alice_handle_0)
            .call()
            .await
            .unwrap(),
        keccak256(&stored)
    );

    // A signed transfer of an encrypted 250 — rng and serialization
    // live inside the client.
    let input_250 = as_alice.encrypt_input(250).await.unwrap();
    as_alice.transfer(bob.address, input_250).await.unwrap();

    // Handles rotated as evented; balances decrypt to the reference.
    let alice_handle_1 = gateway.balanceHandle(alice.address).call().await.unwrap();
    let bob_handle_1 = gateway.balanceHandle(bob.address).call().await.unwrap();
    assert_ne!(alice_handle_1, alice_handle_0);
    assert_ne!(bob_handle_1, [0u8; 32]);
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 350);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 250);

    // A second successful transfer (100), now with every storage slot
    // warm — the gas baseline the silent zero must be compared against
    // (the first transfer pays bob's first-touch storage costs).
    let input_100 = as_alice.encrypt_input(100).await.unwrap();
    as_alice.transfer(bob.address, input_100).await.unwrap();

    // An insufficient transfer (1000 > 250): the client call SUCCEEDS
    // and looks identical to the one above, handles rotate, balances
    // are unchanged — the silent zero.
    let input_1000 = as_alice.encrypt_input(1000).await.unwrap();
    as_alice.transfer(bob.address, input_1000).await.unwrap();

    let alice_handle_2 = gateway.balanceHandle(alice.address).call().await.unwrap();
    let bob_handle_2 = gateway.balanceHandle(bob.address).call().await.unwrap();
    assert_ne!(alice_handle_2, alice_handle_1);
    assert_ne!(bob_handle_2, bob_handle_1);
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 250);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 350);

    // Gas-shape equality: the successful and the silently-zeroed
    // fulfillment execute identically. The fulfillment transactions are
    // the last two TransferFulfilled emitters. Only the EIP-2028
    // calldata discount for zero BYTES in the (random)
    // handles/commitments may differ, so it is normalized out;
    // execution gas must be equal.
    let fulfillments = alice
        .provider
        .get_logs(
            &Filter::new()
                .address(devnet.gateway)
                .event_signature(TransferFulfilled::SIGNATURE_HASH)
                .from_block(0),
        )
        .await
        .unwrap();
    let success_tx = fulfillments
        .get(fulfillments.len() - 2)
        .unwrap()
        .transaction_hash
        .unwrap();
    let silent_zero_tx = fulfillments.last().unwrap().transaction_hash.unwrap();
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
    let alices_input = as_alice.encrypt_input(1).await.unwrap();
    as_agent.set_verified(alice.address, true).await.unwrap();
    assert!(as_bob.transfer(alice.address, alices_input).await.is_err());

    // The decryption ACL binds too: eve (bound to an account by her own
    // faucet, but on no handle's allow-list) cannot read alice's
    // balance.
    as_eve.faucet(1).await.unwrap();
    assert!(as_eve.balance(alice.address).await.is_err());

    operator.shutdown().await.unwrap();
}
