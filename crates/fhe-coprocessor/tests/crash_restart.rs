//! Coprocessor crash-and-restart. The contract's `lastFulfilledId` is
//! the durable cursor; an operator whose loop dies mid-lifecycle hands
//! its durable state over, and the resumed operator replays the event
//! log, skips everything already fulfilled (idempotency per request
//! id), and resumes in order. Toy FHE parameters.

mod common;

use alloy::primitives::B256;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{OpSpec, Operator, harness, ops, symbolic_handle, types};
use rand::rng;

#[tokio::test]
async fn crash_and_restart_resumes_from_the_last_fulfilled_request() {
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

    // Raw bindings: the pre-crash requests are sent WITHOUT waiting for
    // fulfillment (the loop is about to die mid-batch), which a client
    // call would block on.
    let raw_alice = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let raw_agent = IConfidentialTokenGateway::new(devnet.gateway, devnet.agent.provider.clone());

    // Receipts by direct lookup: the ws get_receipt watcher can miss
    // an automined block and hang (see harness::wait_receipt).
    macro_rules! request {
        ($call:expr) => {{
            let pending = $call.send().await.unwrap();
            let provider = alice.provider.clone();
            harness::wait_receipt(&provider, *pending.tx_hash())
                .await
                .unwrap()
        }};
    }
    request!(raw_agent.setVerified(bob.address, true));
    request!(raw_alice.faucet(1000));
    request!(raw_alice.wrap(800));
    operator.run_until_idle().await.unwrap();

    // Two transfers and an observer change are requested...
    let transfer_a = as_alice.encrypt_input(100).await.unwrap();
    let transfer_b = as_alice.encrypt_input(50).await.unwrap();
    request!(raw_alice.confidentialTransfer(bob.address, transfer_a));
    request!(raw_alice.setObserver(bob.address));
    request!(raw_alice.confidentialTransfer(bob.address, transfer_b));

    // ...but the loop dies after fulfilling only the FIRST of them.
    let crash_after = raw_agent.lastFulfilledId().call().await.unwrap() + 1;
    operator.run_until(crash_after).await.unwrap();
    assert_eq!(
        raw_agent.lastFulfilledId().call().await.unwrap(),
        crash_after
    );
    let durable_state = operator.into_state();

    // A restarted operator takes over the durable state, replays the
    // log, skips what the cursor says is done, and resumes in order.
    let restarted = Operator::resume(
        durable_state,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );
    restarted.run_until_idle().await.unwrap();

    // Every request fulfilled exactly once: the cursor reached the last
    // request and the balances reflect each transfer applied once.
    let next_request = raw_agent.nextRequestId().call().await.unwrap();
    assert_eq!(
        raw_agent.lastFulfilledId().call().await.unwrap(),
        next_request - 1
    );
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 650);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 150);
    // The observer change requested before the crash was applied by the
    // restarted operator (bob observes alice's post-restart handles).
    assert_eq!(as_bob.balance(alice.address).await.unwrap(), 650);

    // Idempotency holds for a second catch-up too: nothing re-applies.
    restarted.run_until_idle().await.unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 650);

    // --- Goal H3: the crash boundary crosses a BATCH. One batch (one
    // request id, intra-batch reference included) is requested, the
    // loop dies before fulfilling any of it, and the restarted
    // operator materializes the whole batch exactly once.
    let x = as_alice.encrypt_input(30).await.unwrap();
    let y = as_alice.encrypt_input(20).await.unwrap();
    let batch_id = raw_agent.nextRequestId().call().await.unwrap();
    let batch_ops = vec![
        (&OpSpec::ge(x, y)).into(),
        (&OpSpec::select(OpSpec::result_of(0), x, y)).into(),
    ];
    request!(raw_alice.requestBatch(batch_ops));

    // The crash: state handed over before the batch is touched.
    let second = Operator::resume(
        restarted.into_state(),
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );
    second.run_until_idle().await.unwrap();

    // The contract-derived result handles (refs resolved before
    // hashing), materialized once and decryptable through the ACL.
    let won = symbolic_handle(ops::GE, x, y, B256::ZERO, batch_id, 0, types::EBOOL);
    let max = symbolic_handle(ops::SELECT, x, y, won, batch_id, 1, types::EUINT64);
    assert_eq!(
        second
            .state()
            .await
            .decrypt_for(won, alice.address)
            .unwrap(),
        1
    );
    assert_eq!(
        second
            .state()
            .await
            .decrypt_for(max, alice.address)
            .unwrap(),
        30
    );
    assert_eq!(
        raw_agent.lastFulfilledId().call().await.unwrap(),
        raw_agent.nextRequestId().call().await.unwrap() - 1
    );
    // Exactly one ge executed; a second catch-up re-executes nothing.
    assert_eq!(second.state().await.op_compares().len(), 1);
    second.run_until_idle().await.unwrap();
    assert_eq!(second.state().await.op_compares().len(), 1);
}
