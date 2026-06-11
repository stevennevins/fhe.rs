//! The Goal H third-party proof, driven end to end: a sealed-bid
//! auction (`contracts/src/examples/SealedBidAuction.sol`) built ONLY
//! on the gateway's public primitives — the on-chain ACL and the
//! symbolic-op alphabet. The coprocessor executes nothing
//! auction-specific and the gateway gained no entry points; the
//! auction is just another caller composing `ge` + `select`.
//!
//! ```bash
//! cargo run --release -p fhe-coprocessor --example auction                  # CPU
//! cargo run --release -p fhe-coprocessor --example auction --features cuda  # GPU
//! ```
//!
//! Requires Foundry (`anvil`, `forge`) on PATH; exits loudly otherwise.

use alloy::network::TransactionBuilder;
use alloy::node_bindings::Anvil;
use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use fhe::gateway::Committee;
use fhe::typed::FheUint64;
use fhe_coprocessor::abi::IConfidentialTokenGateway;
use fhe_coprocessor::{Operator, harness};
use rand::rng;

sol! {
    /// The auction's own surface; nothing here is gateway plumbing.
    #[sol(rpc)]
    interface ISealedBidAuction {
        function submitBid(bytes32 bid) external;
        function settle() external;
        function aWins() external view returns (bytes32);
        function winningBid() external view returns (bytes32);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !harness::foundry_available() {
        eprintln!("SKIPPING auction: anvil/forge not found on PATH (install Foundry)");
        return Ok(());
    }

    // --- Deployment (operator side, exactly as in the quickstart) -------
    println!("1. generating a 3-party threshold committee (production parameters)");
    let mut rng = rng();
    let params = FheUint64::default_parameters_128()?;
    let committee = Committee::new(3, &params, &mut rng)?;

    println!("2. spawning anvil, deploying the gateway and the auction");
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
    let seller_key = key(2)?;
    let ann_key = key(3)?;
    let ben_key = key(4)?;
    let seller_address = seller_key.address();
    let ann_address = ann_key.address();
    let ben_address = ben_key.address();

    let ws = anvil.ws_endpoint();
    let coprocessor_provider = harness::connect(&ws, coprocessor_key.clone()).await?;
    let gateway = harness::deploy_gateway(
        &coprocessor_provider,
        agent_key.address(),
        coprocessor_key.address(),
    )
    .await?;

    // The auction is a THIRD-PARTY contract: deployed from its own
    // forge artifact, constructed over the gateway address + seller.
    let mut code = harness::contract_bytecode("SealedBidAuction")?;
    for address in [gateway, seller_address] {
        code.extend_from_slice(&[0u8; 12]);
        code.extend_from_slice(address.as_slice());
    }
    let seller_provider = harness::connect(&ws, seller_key).await?;
    let receipt = seller_provider
        .send_transaction(TransactionRequest::default().with_deploy_code(code))
        .await?
        .get_receipt()
        .await?;
    let auction: Address = receipt
        .contract_address
        .ok_or("auction deployment has no contract address")?;

    println!("3. starting the operator");
    let operator = Operator::new(
        committee,
        agent_key.address(),
        coprocessor_provider,
        gateway,
    )?;
    let ann = operator
        .client(harness::connect(&ws, ann_key.clone()).await?, ann_address)
        .await;
    let ben = operator
        .client(harness::connect(&ws, ben_key.clone()).await?, ben_address)
        .await;
    let seller = operator
        .client(seller_provider.clone(), seller_address)
        .await;
    let operator = operator.spawn();

    // --- The auction (user side) -----------------------------------------
    println!("4. ann and ben register encrypted bids and allow the auction on them");
    let ann_bid = ann.encrypt_input(7_000).await?;
    ann.allow(ann_bid, auction).await?;
    let ben_bid = ben.encrypt_input(9_500).await?;
    ben.allow(ben_bid, auction).await?;

    println!("5. bids are submitted; the auction settles in one atomic batch");
    let as_ann = ISealedBidAuction::new(auction, harness::connect(&ws, ann_key).await?);
    as_ann
        .submitBid(ann_bid)
        .send()
        .await?
        .get_receipt()
        .await?;
    let as_ben = ISealedBidAuction::new(auction, harness::connect(&ws, ben_key).await?);
    as_ben
        .submitBid(ben_bid)
        .send()
        .await?
        .get_receipt()
        .await?;
    let as_seller = ISealedBidAuction::new(auction, seller_provider.clone());
    as_seller.settle().send().await?.get_receipt().await?;

    // The auction's calls are raw transactions (unlike Client methods,
    // they do not resolve on fulfillment), so wait for the operator to
    // catch up: the batch and the two ACL grants are fulfilled when
    // the cursor reaches the last request.
    let gateway_view = IConfidentialTokenGateway::new(gateway, seller_provider.clone());
    let mut waited = 0;
    loop {
        let next = gateway_view.nextRequestId().call().await?;
        if gateway_view.lastFulfilledId().call().await? == next - 1 {
            break;
        }
        waited += 1;
        if waited > 600 {
            return Err("the operator did not fulfill the settlement within 60s".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    println!("6. the seller reads the outcome through the ACL");
    let a_wins = as_seller.aWins().call().await?;
    let winning_bid = as_seller.winningBid().call().await?;
    let won = seller.decrypt(a_wins).await?;
    let amount = seller.decrypt(winning_bid).await?;
    println!("   ann won: {} (expected 0)", won);
    println!("   winning bid: {} (expected 9500)", amount);
    if (won, amount) != (0, 9_500) {
        return Err("the settled auction must match the reference outcome".into());
    }
    // The bidders cannot read each other's bids or the outcome the
    // seller was granted; the ACL is the boundary.
    match ann.decrypt(winning_bid).await {
        Ok(value) => return Err(format!("the ACL must deny ann, but read {value}").into()),
        Err(e) => println!("   ann reading the winning bid is denied: {e}"),
    }

    operator.shutdown().await?;
    println!("done: encrypted third-party logic, zero coprocessor changes.");
    Ok(())
}
