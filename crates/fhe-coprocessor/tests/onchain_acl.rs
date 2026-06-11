//! The on-chain ACL drives the coprocessor's decryption read path
//! (Goal H1): `allow` extends read access by transaction with fhEVM's
//! chain-of-custody rule, denial is the default, and grants written at
//! handle rotation (ownership, observers) reproduce the Goal E/F
//! semantics exactly — `onchain_extensions.rs` and `onchain_e2e.rs`
//! remain the observer regression suite; this file covers what is new.
//!
//! Toy FHE parameters; the transport and authorization are under test,
//! not the circuits.

mod common;

use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Operator, harness};
use rand::rng;

#[tokio::test]
async fn onchain_acl_drives_the_read_path() {
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
    let carol = devnet.users.get(2).unwrap();
    let operator = Operator::new(
        committee,
        devnet.agent.address,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    )
    .unwrap();
    let as_alice = operator.client(alice.provider.clone(), alice.address).await;
    let as_bob = operator.client(bob.provider.clone(), bob.address).await;
    let as_carol = operator.client(carol.provider.clone(), carol.address).await;
    let as_agent = operator
        .client(devnet.agent.provider.clone(), devnet.agent.address)
        .await;
    let operator = operator.spawn();
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());

    as_agent.set_verified(bob.address, true).await.unwrap();
    as_alice.faucet(1000).await.unwrap();
    as_alice.wrap(1000).await.unwrap();

    // An anchored input is readable by its owner (the registerInput
    // grant) and by no one else.
    let input = as_alice.encrypt_input(123).await.unwrap();
    assert!(
        gateway
            .isAllowed(input, alice.address)
            .call()
            .await
            .unwrap()
    );
    assert_eq!(
        operator
            .state()
            .await
            .decrypt_for(input, alice.address)
            .unwrap(),
        123
    );
    assert!(
        operator
            .state()
            .await
            .decrypt_for(input, carol.address)
            .is_err()
    );

    // Chain of custody: carol (never granted) cannot grant herself.
    assert!(as_carol.allow(input, carol.address).await.is_err());

    // The owner grants carol BY TRANSACTION; the coprocessor's read
    // path honors exactly that on-chain grant once the request is
    // mirrored (client.allow resolves on the ack).
    as_alice.allow(input, carol.address).await.unwrap();
    assert!(
        gateway
            .isAllowed(input, carol.address)
            .call()
            .await
            .unwrap()
    );
    assert_eq!(
        operator
            .state()
            .await
            .decrypt_for(input, carol.address)
            .unwrap(),
        123
    );

    // Rotation grants: after a transfer, each party reads its own new
    // balance handle, both read the transferred amount, and a
    // never-granted account is denied on all three.
    let amount = as_alice.encrypt_input(400).await.unwrap();
    as_alice.transfer(bob.address, amount).await.unwrap();
    let alice_balance = gateway
        .confidentialBalanceOf(alice.address)
        .call()
        .await
        .unwrap();
    let bob_balance = gateway
        .confidentialBalanceOf(bob.address)
        .call()
        .await
        .unwrap();
    assert_eq!(as_alice.balance(alice.address).await.unwrap(), 600);
    assert_eq!(as_bob.balance(bob.address).await.unwrap(), 400);
    assert!(as_carol.balance(alice.address).await.is_err());
    assert!(
        operator
            .state()
            .await
            .decrypt_for(bob_balance, alice.address)
            .is_err()
    );

    // A balance handle's owner can extend read access onward — the
    // composability primitive third parties build on.
    as_alice.allow(alice_balance, carol.address).await.unwrap();
    assert_eq!(as_carol.balance(alice.address).await.unwrap(), 600);

    operator.shutdown().await.unwrap();
}
