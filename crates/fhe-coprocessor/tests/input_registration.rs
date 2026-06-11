//! Input registration and handle anchoring. A registered ciphertext
//! becomes `(handle, commitment)` anchored on-chain; the contract
//! accepts only anchored handles (and only from their owner); the
//! commitment recomputes from the stored bytes; tampered bytes are
//! detected. Toy FHE parameters: the transport split is what is under
//! test, not the circuits.

mod common;

use alloy::primitives::{B256, keccak256};
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Coprocessor, Operator, harness};
use fhe_traits::Serialize;
use rand::rng;

#[tokio::test]
async fn registered_input_anchors_and_unregistered_inputs_revert() {
    if !harness::foundry_available() {
        eprintln!("SKIPPING: anvil/forge not found on PATH");
        return;
    }
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();

    let devnet = common::spawn_devnet(1).await;
    let user = devnet.users.first().unwrap();
    let operator = Operator::new(
        committee,
        devnet.agent.address,
        devnet.coprocessor.provider.clone(),
        devnet.gateway,
    )
    .unwrap();
    let as_user = operator.client(user.provider.clone(), user.address).await;
    let as_agent = operator
        .client(devnet.agent.provider.clone(), devnet.agent.address)
        .await;
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, user.provider.clone());

    // One client call: encrypt, register off-chain, anchor on-chain.
    // The ciphertext bytes never touch the chain — it learns 64 bytes,
    // not megabytes.
    let handle = as_user.encrypt_input(250).await.unwrap();
    assert_eq!(
        gateway.inputOwner(handle).call().await.unwrap(),
        user.address
    );

    // The commitment recomputes from the coprocessor's stored bytes and
    // matches what the chain anchored.
    {
        let state = operator.state().await;
        let stored = state.stored_bytes(handle).unwrap();
        let commitment = gateway.handleCommitment(handle).call().await.unwrap();
        assert_eq!(keccak256(stored), commitment);
        assert!(state.verify_stored(handle));
        assert_eq!(
            state
                .committee()
                .threshold_decrypt(state.input_ciphertext(handle).unwrap(), &mut rng)
                .unwrap(),
            250
        );
    }

    // An unregistered handle reverts on-chain (UnknownInput; the forge
    // suite pins the exact error selector).
    let bogus = B256::from([0xAB; 32]);
    assert!(as_agent.set_frozen(user.address, bogus).await.is_err());
    // A registered handle spent by a non-owner reverts (NotInputOwner):
    // the input belongs to the user, not the agent.
    assert!(as_agent.set_frozen(user.address, handle).await.is_err());
}

#[test]
fn tampered_stored_bytes_are_detected() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    let agent_address = alloy::primitives::Address::from([0xA9; 20]);
    let mut coprocessor = Coprocessor::new(committee, agent_address).unwrap();

    let amount = coprocessor.committee().encrypt(7, &mut rng).unwrap();
    let bytes = amount.to_bytes();
    let (handle, commitment) = coprocessor.register_input(&bytes, agent_address).unwrap();
    assert_eq!(commitment, keccak256(&bytes));
    assert!(coprocessor.verify_stored(handle));
    assert!(coprocessor.input_ciphertext(handle).is_ok());

    // Flip one byte through the persistence seam: detected before use.
    let mut tampered = bytes.clone();
    let last = tampered.last_mut().unwrap();
    *last ^= 0x01;
    coprocessor.replace_stored_bytes(handle, tampered).unwrap();
    assert!(!coprocessor.verify_stored(handle));
    assert!(coprocessor.input_ciphertext(handle).is_err());
}
