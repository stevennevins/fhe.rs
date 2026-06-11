//! Shared devnet setup for the on-chain tests: spawn anvil, connect
//! wallet-backed websocket providers, deploy the gateway. Also the
//! Goal D single-party-view leakage assertion, shared by the tests
//! that sweep audit transcripts.

use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::Address;
use alloy::providers::DynProvider;
use alloy::signers::local::PrivateKeySigner;
use fhe::gateway::CompareTranscript;
use fhe_coprocessor::harness;

/// The Goal D single-party-view assertions over one comparison
/// transcript, against the raw operands the reference model knows
/// (the same sweep `onchain_e2e.rs` runs over the token audit logs).
#[allow(dead_code)] // not every test in the suite sweeps transcripts
pub fn assert_compare_hides(compare: &CompareTranscript, lhs: u64, rhs: u64) {
    let true_difference = lhs.wrapping_sub(rhs);
    let revealed = compare.revealed;
    assert_ne!(revealed, lhs);
    assert_ne!(revealed, rhs);
    if true_difference != 0 {
        assert_ne!(revealed, true_difference);
        for blind in &compare.blinds {
            assert!(*blind >= 3);
            let partially_unblinded = (revealed as i64).unsigned_abs() / blind;
            let residual = if (revealed as i64) < 0 {
                (partially_unblinded as i64).wrapping_neg() as u64
            } else {
                partially_unblinded
            };
            assert_ne!(residual, true_difference);
        }
    }
}

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
