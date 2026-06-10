//! Quickstart: the whole kit in one file — spin a devnet, deploy the
//! gateway, start the operator, then drive the fhEVM-shaped user flow:
//! wrap → confidential transfer → read back.
//!
//! ```bash
//! cargo run --release -p fhe-coprocessor --example quickstart                  # CPU
//! cargo run --release -p fhe-coprocessor --example quickstart --features cuda  # GPU
//! ```
//!
//! Requires Foundry (`anvil`, `forge`) on PATH; exits loudly otherwise.

use alloy::node_bindings::Anvil;
use alloy::signers::local::PrivateKeySigner;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::{Operator, harness};
use rand::rng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !harness::foundry_available() {
        eprintln!("SKIPPING quickstart: anvil/forge not found on PATH (install Foundry)");
        return Ok(());
    }

    // --- Deployment (operator side) -------------------------------------
    println!("1. generating a 3-party threshold committee (production parameters)");
    let mut rng = rng();
    let params = FheUint64::default_parameters_128()?;
    let committee = Committee::new(3, &params, &mut rng)?;

    println!("2. spawning anvil and deploying the gateway");
    let anvil = Anvil::new().spawn();
    let key = |i: usize| -> Result<PrivateKeySigner, String> {
        anvil
            .keys()
            .get(i)
            .cloned()
            .map(Into::into)
            .ok_or_else(|| "anvil starts with 10 funded keys".to_string())
    };
    let coprocessor_key = key(0)?;
    let agent_key = key(1)?;
    let alice_key = key(2)?;
    let bob_key = key(3)?;
    let agent_address = agent_key.address();
    let alice_address = alice_key.address();
    let bob_address = bob_key.address();

    let ws = anvil.ws_endpoint();
    let coprocessor_provider = harness::connect(&ws, coprocessor_key.clone()).await?;
    let gateway = harness::deploy_gateway(
        &coprocessor_provider,
        agent_address,
        coprocessor_key.address(),
    )
    .await?;

    println!("3. starting the operator (event loop + durable state)");
    let operator = Operator::new(committee, agent_address, coprocessor_provider, gateway)?;
    let alice = operator
        .client(harness::connect(&ws, alice_key).await?, alice_address)
        .await;
    let bob = operator
        .client(harness::connect(&ws, bob_key).await?, bob_address)
        .await;
    let agent = operator
        .client(harness::connect(&ws, agent_key).await?, agent_address)
        .await;
    let operator = operator.spawn();

    // --- The user flow (client side) ------------------------------------
    println!("4. alice funds and wraps 1000 into her confidential balance");
    agent.set_verified(bob_address, true).await?;
    alice.faucet(1000).await?;
    alice.wrap(1000).await?;

    println!("5. alice confidentially transfers an encrypted 250 to bob");
    let input = alice.encrypt_input(250).await?;
    alice.transfer(bob_address, input).await?;

    println!("6. each party reads back what the ACL allows");
    println!(
        "   alice's balance: {}",
        alice.balance(alice_address).await?
    );
    println!("   bob's balance:   {}", bob.balance(bob_address).await?);
    match bob.balance(alice_address).await {
        Ok(value) => return Err(format!("the ACL must deny bob, but read {value}").into()),
        Err(e) => println!("   bob reading alice's balance is denied: {e}"),
    }

    operator.shutdown().await?;
    println!("done.");
    Ok(())
}
