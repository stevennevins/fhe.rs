//! G5: coprocessor crash-and-restart. The contract's `lastFulfilledId`
//! is the durable cursor; a service that dies mid-lifecycle is rebuilt
//! over the surviving durable state, replays the event log, skips
//! everything already fulfilled (idempotency per request id), and
//! resumes in order. Toy FHE parameters.

mod common;

use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Coprocessor, Service, harness};
use fhe_traits::Serialize;
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
    let coprocessor = Coprocessor::new(committee, params, devnet.agent.address).unwrap();
    let mut service = Service::new(
        coprocessor,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );

    let as_alice = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());
    let as_agent = IConfidentialTokenGateway::new(devnet.gateway, devnet.agent.provider.clone());

    macro_rules! exec {
        ($call:expr) => {
            $call.send().await.unwrap().get_receipt().await.unwrap()
        };
    }
    exec!(as_agent.setVerified(bob.address, true));
    exec!(as_alice.faucet(1000));
    exec!(as_alice.wrap(800));
    service.catch_up().await.unwrap();

    // Two transfers and an observer change are requested...
    let ct = service
        .coprocessor()
        .committee()
        .encrypt(100, &mut rng)
        .unwrap();
    let (transfer_a, _) = service
        .register_and_anchor(alice.address, &ct.to_bytes())
        .await
        .unwrap();
    let ct = service
        .coprocessor()
        .committee()
        .encrypt(50, &mut rng)
        .unwrap();
    let (transfer_b, _) = service
        .register_and_anchor(alice.address, &ct.to_bytes())
        .await
        .unwrap();
    exec!(as_alice.transfer(bob.address, transfer_a));
    exec!(as_alice.setObserver(bob.address));
    exec!(as_alice.transfer(bob.address, transfer_b));

    // ...but the service dies after fulfilling only the FIRST of them.
    let crash_after = as_agent.lastFulfilledId().call().await.unwrap() + 1;
    service.run_until(crash_after).await.unwrap();
    assert_eq!(
        as_agent.lastFulfilledId().call().await.unwrap(),
        crash_after
    );
    let durable_state = service.into_coprocessor();

    // A restarted service takes over the durable state, replays the
    // log, skips what the cursor says is done, and resumes in order.
    let mut restarted = Service::new(
        durable_state,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    );
    restarted.catch_up().await.unwrap();

    // Every request fulfilled exactly once: the cursor reached the last
    // request and the balances reflect each transfer applied once.
    let next_request = as_agent.nextRequestId().call().await.unwrap();
    assert_eq!(
        as_agent.lastFulfilledId().call().await.unwrap(),
        next_request - 1
    );
    let alice_handle = as_agent.balanceHandle(alice.address).call().await.unwrap();
    let bob_handle = as_agent.balanceHandle(bob.address).call().await.unwrap();
    let state = restarted.coprocessor_mut();
    assert_eq!(state.decrypt_for(alice_handle, alice.address).unwrap(), 650);
    assert_eq!(state.decrypt_for(bob_handle, bob.address).unwrap(), 150);
    // The observer change requested before the crash was applied by the
    // restarted service (bob observes alice's post-restart handles).
    assert_eq!(state.decrypt_for(alice_handle, bob.address).unwrap(), 650);

    // Idempotency holds for a second catch-up too: nothing re-applies.
    restarted.catch_up().await.unwrap();
    let state = restarted.coprocessor_mut();
    assert_eq!(state.decrypt_for(alice_handle, alice.address).unwrap(), 650);
}
