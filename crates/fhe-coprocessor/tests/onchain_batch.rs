//! Atomic symbolic batches (Goal H3): one transaction carrying an
//! ordered op list with intra-batch references, one request id, one
//! fulfillment posting every deferred commitment — plus the gas
//! measurement comparing batched vs sequential request/fulfillment
//! (the numbers quoted in the H3 commit message; run with
//! `--nocapture` to see them).
//!
//! Toy FHE parameters; the gas shape does not depend on them.

mod common;

use alloy::primitives::B256;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{OpSpec, Operator, harness, ops};
use rand::rng;

#[tokio::test]
async fn batches_compose_atomically_and_amortize_fulfillment_gas() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING: anvil/forge not found on PATH");
        return;
    }
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();

    let devnet = common::spawn_devnet(2).await;
    let alice = devnet.users.first().unwrap();
    let bob = devnet.users.get(1).unwrap();
    let operator = Operator::new(
        committee,
        devnet.agent.address,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    )
    .unwrap();
    let as_alice = operator.client(alice.provider.clone(), alice.address).await;
    let as_bob = operator.client(bob.provider.clone(), bob.address).await;
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());

    let x = as_alice.encrypt_input(70).await.unwrap();
    let y = as_alice.encrypt_input(50).await.unwrap();

    // ------------------------------------------------------------------
    // The atomic composition, driven through the client: a guarded
    // "pick the max, then add y" in ONE transaction, with intra-batch
    // references. Spawn the live operator for this half.
    // ------------------------------------------------------------------
    let handle = operator.spawn();
    let results = as_alice
        .batch(&[
            OpSpec::ge(x, y),
            OpSpec::select(OpSpec::result_of(0), x, y),
            OpSpec::add(OpSpec::result_of(1), y),
        ])
        .await
        .unwrap();
    assert_eq!(results.len(), 3);
    let expected = [1u64, 70, 120];
    for (&result, &value) in results.iter().zip(expected.iter()) {
        assert_eq!(as_alice.decrypt(result).await.unwrap(), value);
    }
    // Every deferred commitment landed in the one fulfillment, and the
    // leakage sweep covers the batch's comparison.
    for &result in &results {
        assert_ne!(
            gateway.handleCommitment(result).call().await.unwrap(),
            B256::ZERO
        );
    }
    {
        let state = handle.state().await;
        assert_eq!(state.op_compares().len(), 1);
        common::assert_compare_hides(state.op_compares().first().unwrap(), 70, 50);
    }
    // Authorization: bob is not allowed on alice's inputs, and a batch
    // is rejected as a whole (public check, nothing executes).
    assert!(as_bob.batch(&[OpSpec::add(x, y)]).await.is_err());
    let operator = handle.shutdown().await.unwrap();

    // ------------------------------------------------------------------
    // Gas: N ops as one batch (1 request tx + 1 fulfillBatch) vs N
    // sequential requestOp (N request txs + N fulfillOp). Driven raw so
    // the receipts are in hand; the operator runs deterministically.
    // ------------------------------------------------------------------
    const N: usize = 8;
    let raw = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let gas = |label: &'static str, request: u64, fulfill: u64| {
        println!(
            "{label}: request {request} gas + fulfillment {fulfill} gas = {} total",
            request + fulfill
        );
    };

    // Sequential: N independent ge ops.
    let mut sequential_request = 0u64;
    for _ in 0..N {
        let pending = raw
            .requestOp(ops::GE, x, y, B256::ZERO)
            .send()
            .await
            .unwrap();
        let receipt = harness::wait_receipt(&alice.provider, *pending.tx_hash())
            .await
            .unwrap();
        assert!(receipt.status());
        sequential_request += receipt.gas_used;
    }
    let mut sequential_fulfill = 0u64;
    for hash in operator.run_until_idle().await.unwrap() {
        let receipt = harness::wait_receipt(&devnet.coprocessor.provider, hash)
            .await
            .unwrap();
        sequential_fulfill += receipt.gas_used;
    }

    // Batched: the same N ge ops in one batch.
    let batch: Vec<_> = (0..N).map(|_| (&OpSpec::ge(x, y)).into()).collect();
    let pending = raw.requestBatch(batch).send().await.unwrap();
    let receipt = harness::wait_receipt(&alice.provider, *pending.tx_hash())
        .await
        .unwrap();
    assert!(receipt.status());
    let batch_request = receipt.gas_used;
    let fulfill_hashes = operator.run_until_idle().await.unwrap();
    assert_eq!(fulfill_hashes.len(), 1, "one fulfillment for the batch");
    let batch_fulfill = harness::wait_receipt(
        &devnet.coprocessor.provider,
        *fulfill_hashes.first().unwrap(),
    )
    .await
    .unwrap()
    .gas_used;

    gas("sequential (8 ops)", sequential_request, sequential_fulfill);
    gas("batched    (8 ops)", batch_request, batch_fulfill);
    // The amortization claim, pinned: one batch fulfillment costs less
    // than the sequential fulfillments it replaces.
    assert!(batch_fulfill < sequential_fulfill);
    assert!(batch_request < sequential_request);
}
