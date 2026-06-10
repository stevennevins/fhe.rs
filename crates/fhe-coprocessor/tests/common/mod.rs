//! Shared devnet setup for the on-chain tests: spawn anvil, connect
//! wallet-backed websocket providers, deploy the gateway.

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::Address;
use alloy::providers::DynProvider;
use alloy::signers::local::PrivateKeySigner;
use fhe_coprocessor::harness;

/// One devnet account: a wallet-backed provider and its address.
pub struct Wallet {
    pub provider: DynProvider,
    pub address: Address,
}

/// A running devnet with the gateway deployed.
pub struct Devnet {
    /// Kept alive for the test's duration; dropping it kills anvil.
    _anvil: AnvilInstance,
    pub gateway: Address,
    /// The coprocessor's wallet (the only one allowed to fulfill).
    pub coprocessor: Wallet,
    /// The agent (and freezer) wallet.
    pub agent: Wallet,
    /// Plain user wallets.
    pub users: Vec<Wallet>,
}

/// Spawns anvil and deploys the gateway: key 0 is the coprocessor, key
/// 1 the agent, keys 2.. the `n_users` user wallets.
pub async fn spawn_devnet(n_users: usize) -> Devnet {
    let anvil = Anvil::new().spawn();
    let ws = anvil.ws_endpoint();
    let mut wallets = Vec::new();
    for key in anvil.keys().iter().take(n_users + 2) {
        let signer: PrivateKeySigner = key.clone().into();
        let address = signer.address();
        let provider = harness::connect(&ws, signer).await.unwrap();
        wallets.push(Wallet { provider, address });
    }
    let mut wallets = wallets.into_iter();
    let coprocessor = wallets.next().unwrap();
    let agent = wallets.next().unwrap();
    let gateway =
        harness::deploy_gateway(&coprocessor.provider, agent.address, coprocessor.address)
            .await
            .unwrap();
    Devnet {
        _anvil: anvil,
        gateway,
        coprocessor,
        agent,
        users: wallets.collect(),
    }
}
