//! Coprocessor crash-and-restart. The contract's `lastFulfilledId` is
//! the durable cursor; an operator whose loop dies mid-lifecycle hands
//! its durable state over, and the resumed operator replays the event
//! log, skips everything already fulfilled (idempotency per request
//! id), and resumes in order. Toy FHE parameters.

mod common;

use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Operator, harness};
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

    macro_rules! request {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
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
}
