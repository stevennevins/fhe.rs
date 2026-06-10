//! G2: input registration and handle anchoring. A registered ciphertext
//! becomes `(handle, commitment)` anchored on-chain; the contract
//! accepts only anchored handles (and only from their owner); the
//! commitment recomputes from the stored bytes; tampered bytes are
//! detected. Toy FHE parameters: the transport split is what is under
//! test, not the circuits.

use alloy::node_bindings::Anvil;
use alloy::primitives::{B256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Coprocessor, harness};
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

    let anvil = Anvil::new().spawn();
    let keys = anvil.keys();
    let user_key: PrivateKeySigner = keys.first().unwrap().clone().into();
    let coprocessor_key: PrivateKeySigner = keys.get(1).unwrap().clone().into();
    let agent_key: PrivateKeySigner = keys.get(2).unwrap().clone().into();
    let user_address = user_key.address();
    let agent_address = agent_key.address();

    let user = harness::connect(&anvil.ws_endpoint(), user_key)
        .await
        .unwrap();
    let coprocessor_wallet = harness::connect(&anvil.ws_endpoint(), coprocessor_key.clone())
        .await
        .unwrap();
    let agent = harness::connect(&anvil.ws_endpoint(), agent_key)
        .await
        .unwrap();
    let address = harness::deploy_gateway(&user, agent_address, coprocessor_key.address())
        .await
        .unwrap();
    let gateway = IConfidentialTokenGateway::new(address, user.clone());
    let as_coprocessor = IConfidentialTokenGateway::new(address, coprocessor_wallet);
    let as_agent = IConfidentialTokenGateway::new(address, agent);

    let mut coprocessor = Coprocessor::new(committee, params, agent_address).unwrap();

    // Off-chain registration: serialized ciphertext in, (handle,
    // commitment) out; the ciphertext bytes never touch the chain.
    let amount = coprocessor.committee().encrypt(250, &mut rng).unwrap();
    let bytes = amount.to_bytes();
    let (handle, commitment) = coprocessor.register_input(user_address, &bytes).unwrap();
    assert_eq!(commitment, keccak256(&bytes));
    assert_eq!(coprocessor.input_owner(handle), Some(user_address));

    // Anchor on-chain; the chain learns 64 bytes, not megabytes.
    as_coprocessor
        .registerInput(handle, commitment, user_address)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(
        gateway.handleCommitment(handle).call().await.unwrap(),
        commitment
    );
    assert_eq!(
        gateway.inputOwner(handle).call().await.unwrap(),
        user_address
    );

    // The commitment recomputes from the coprocessor's stored bytes and
    // matches what the chain anchored.
    let stored = coprocessor.stored_bytes(handle).unwrap();
    assert_eq!(keccak256(stored), commitment);
    assert!(coprocessor.verify_stored(handle));
    assert_eq!(
        coprocessor
            .committee()
            .threshold_decrypt(coprocessor.input_ciphertext(handle).unwrap(), &mut rng)
            .unwrap(),
        250
    );

    // An unregistered handle reverts on-chain (UnknownInput; the forge
    // suite pins the exact error selector).
    let bogus = B256::from([0xAB; 32]);
    assert!(
        as_agent
            .setConfidentialFrozen(user_address, bogus)
            .send()
            .await
            .is_err()
    );
    // A registered handle spent by a non-owner reverts (NotInputOwner):
    // the input belongs to the user, not the agent.
    assert!(
        as_agent
            .setConfidentialFrozen(user_address, handle)
            .send()
            .await
            .is_err()
    );
}

#[test]
fn tampered_stored_bytes_are_detected() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    let agent_address = alloy::primitives::Address::from([0xA9; 20]);
    let mut coprocessor = Coprocessor::new(committee, params, agent_address).unwrap();

    let amount = coprocessor.committee().encrypt(7, &mut rng).unwrap();
    let bytes = amount.to_bytes();
    let (handle, _) = coprocessor.register_input(agent_address, &bytes).unwrap();
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
