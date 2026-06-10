//! G1 round trip: deploy the gateway on anvil via `alloy`, emit one
//! request event from a user transaction, decode it in Rust, post the
//! fulfillment transaction from the coprocessor key, and read the
//! state back. No FHE yet.

use alloy::node_bindings::Anvil;
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use fhe_coprocessor::abi::IConfidentialTokenGateway::{self, FaucetRequested};
use fhe_coprocessor::harness;
use futures_util::StreamExt;

#[tokio::test]
async fn gateway_event_roundtrip() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING gateway_event_roundtrip: anvil/forge not found on PATH");
        return;
    }
    let anvil = Anvil::new().spawn();
    let keys = anvil.keys();
    let user_key: PrivateKeySigner = keys.first().unwrap().clone().into();
    let coprocessor_key: PrivateKeySigner = keys.get(1).unwrap().clone().into();
    let agent_key: PrivateKeySigner = keys.get(2).unwrap().clone().into();
    let user_address = user_key.address();
    let coprocessor_address = coprocessor_key.address();
    let agent_address = agent_key.address();

    let user = harness::connect(&anvil.ws_endpoint(), user_key)
        .await
        .unwrap();
    let coprocessor = harness::connect(&anvil.ws_endpoint(), coprocessor_key)
        .await
        .unwrap();

    let address = harness::deploy_gateway(&user, agent_address, coprocessor_address)
        .await
        .unwrap();

    // Subscribe before sending so the event cannot be missed.
    let mut events = user
        .subscribe_logs(&Filter::new().address(address))
        .await
        .unwrap()
        .into_stream();

    // Request: a user transaction emits FaucetRequested.
    let gateway = IConfidentialTokenGateway::new(address, user.clone());
    gateway
        .faucet(42)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Decode in Rust.
    let log = events.next().await.unwrap();
    assert_eq!(log.topic0(), Some(&FaucetRequested::SIGNATURE_HASH));
    let event = log.log_decode::<FaucetRequested>().unwrap().inner.data;
    assert_eq!(event.id, 1);
    assert_eq!(event.account, user_address);
    assert_eq!(event.amount, 42);

    // Fulfill from the coprocessor key, then read state back.
    let as_coprocessor = IConfidentialTokenGateway::new(address, coprocessor.clone());
    as_coprocessor
        .fulfillAck(event.id)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    assert_eq!(gateway.lastFulfilledId().call().await.unwrap(), 1);
    assert_eq!(
        gateway.publicBalance(user_address).call().await.unwrap(),
        42
    );
}
