//! Symbolic encrypted ops (Goal H2): the fixed alphabet driven through
//! the client, with the contract-derived result handles, the deferred
//! commitment binding, reference-model decryptions, and the Goal D
//! leakage sweep over the `ge` transcripts.
//!
//! Toy FHE parameters; the e2e re-runs a symbolic composition at
//! production parameters.

mod common;

use alloy::primitives::B256;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Operator, harness, ops, symbolic_handle, types};
use rand::rng;

#[tokio::test]
async fn symbolic_ops_compose_and_pass_the_leakage_sweep() {
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
    let operator = operator.spawn();
    let gateway = IConfidentialTokenGateway::new(devnet.gateway, alice.provider.clone());

    // The composition a guarded transfer needs: ge + select, plus the
    // arithmetic pair. Reference model: x = 70, y = 50.
    let x = as_alice.encrypt_input(70).await.unwrap();
    let y = as_alice.encrypt_input(50).await.unwrap();

    // ge: 70 >= 50 — an ebool whose handle the chain derived before
    // the ciphertext existed.
    let won = as_alice.ge(x, y).await.unwrap();
    assert_eq!(as_alice.decrypt(won).await.unwrap(), 1);
    // The trailing bytes are the documented fhEVM-style structure, and
    // the Rust derivation matches the contract's.
    assert_eq!(won.0[21], 0xff);
    assert_eq!(won.0[30], types::EBOOL);
    assert_eq!(won.0[31], 0);

    // select picks the max; the composition decrypts to the reference.
    let max = as_alice.select(won, x, y).await.unwrap();
    assert_eq!(as_alice.decrypt(max).await.unwrap(), 70);
    assert_eq!(max.0[30], types::EUINT64);

    // add and sub against the reference model.
    let sum = as_alice.add(x, y).await.unwrap();
    assert_eq!(as_alice.decrypt(sum).await.unwrap(), 120);
    let difference = as_alice.sub(x, y).await.unwrap();
    assert_eq!(as_alice.decrypt(difference).await.unwrap(), 20);

    // A failed guard composes with the SAME shape: ge(y, x) is an
    // encrypted 0 and the select still fulfills, yielding the other
    // branch — nothing reverts, nothing on-chain distinguishes it.
    let lost = as_alice.ge(y, x).await.unwrap();
    let min = as_alice.select(lost, x, y).await.unwrap();
    assert_eq!(as_alice.decrypt(lost).await.unwrap(), 0);
    assert_eq!(as_alice.decrypt(min).await.unwrap(), 50);

    // Deferred binding, now posted: every materialized result handle
    // has a commitment matching the coprocessor's stored bytes.
    for handle in [won, max, sum, difference, lost, min] {
        let commitment = gateway.handleCommitment(handle).call().await.unwrap();
        assert_ne!(commitment, B256::ZERO);
        let state = operator.state().await;
        assert_eq!(
            alloy::primitives::keccak256(state.stored_bytes(handle).unwrap()),
            commitment
        );
    }

    // Authorization: bob is not allowed on alice's handles — the op
    // request reverts (a public check) and the result stays his to
    // never read.
    assert!(as_bob.ge(x, y).await.is_err());
    assert!(as_bob.decrypt(max).await.is_err());
    // Alice extends read access to the result by transaction; bob can
    // then decrypt the max but still cannot operate on her inputs.
    as_alice.allow(max, bob.address).await.unwrap();
    assert_eq!(as_bob.decrypt(max).await.unwrap(), 70);
    assert!(as_bob.add(x, y).await.is_err());

    // The Goal D sweep over the symbolic comparisons: two `ge` ops,
    // transcripts in request order, no single party's view contains a
    // raw operand.
    {
        let state = operator.state().await;
        let compares = state.op_compares();
        assert_eq!(compares.len(), 2);
        common::assert_compare_hides(compares.first().unwrap(), 70, 50);
        common::assert_compare_hides(compares.get(1).unwrap(), 50, 70);
    }

    // The derivation is pinned: recompute the first ge's handle from
    // its request id. (Request ids: 2 inputs are anchors, not
    // requests; the ge was request id 1.)
    assert_eq!(
        won,
        symbolic_handle(ops::GE, x, y, B256::ZERO, 1, 0, types::EBOOL)
    );

    operator.shutdown().await.unwrap();
}
