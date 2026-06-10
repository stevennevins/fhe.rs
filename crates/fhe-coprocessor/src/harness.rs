//! Devnet test harness: Foundry detection, contract build, and gateway
//! deployment over `alloy`. Chain tests self-skip (loudly) when Foundry
//! is not installed — detected, not hardcoded.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::Address;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, GasFiller, NonceFiller, SimpleNonceManager,
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;

use crate::{Error, Result, chain_err};

/// Connects a wallet-backed websocket provider to the devnet, type-erased
/// so tests and the coprocessor loop need no provider generics.
///
/// Nonces are fetched fresh per transaction (`SimpleNonceManager`)
/// instead of the default cached manager: the fillers prepare jointly,
/// so a send that fails gas estimation (an expected revert — public
/// policy checks) would still burn a cached nonce and strand every
/// later transaction from that wallet behind the gap.
pub async fn connect(ws_url: &str, signer: PrivateKeySigner) -> Result<DynProvider> {
    let provider = ProviderBuilder::default()
        .filler(GasFiller)
        .filler(BlobGasFiller::default())
        .filler(NonceFiller::new(SimpleNonceManager::default()))
        .filler(ChainIdFiller::default())
        .wallet(EthereumWallet::from(signer))
        .connect_ws(WsConnect::new(ws_url))
        .await
        .map_err(chain_err)?;
    Ok(provider.erased())
}

/// Whether `anvil` and `forge` are runnable on this machine. Tests that
/// need a devnet should return early (with a loud message) when false:
///
/// ```rust
/// if !fhe_coprocessor::harness::foundry_available() {
///     eprintln!("SKIPPING: anvil/forge not found on PATH");
///     return;
/// }
/// ```
#[must_use]
pub fn foundry_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let runs = |bin: &str| {
            Command::new(bin)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        };
        runs("anvil") && runs("forge")
    })
}

/// The repo's `contracts/` Foundry project root.
fn contracts_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

/// Runs `forge build` on the repo's contracts (cached by forge, cheap
/// when up to date) and returns the gateway's creation bytecode.
pub fn gateway_bytecode() -> Result<Vec<u8>> {
    let root = contracts_root();
    let output = Command::new("forge")
        .arg("build")
        .current_dir(&root)
        .output()
        .map_err(chain_err)?;
    if !output.status.success() {
        return Err(Error::Chain(format!(
            "forge build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let artifact = root.join("out/ConfidentialTokenGateway.sol/ConfidentialTokenGateway.json");
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&artifact).map_err(chain_err)?).map_err(chain_err)?;
    let hex = json
        .pointer("/bytecode/object")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Chain(format!("no bytecode in {}", artifact.display())))?;
    alloy::hex::decode(hex).map_err(chain_err)
}

/// Deploys the gateway with the given `agent` and `coprocessor` roles,
/// returning its address. The provider's default signer pays.
pub async fn deploy_gateway(
    provider: &DynProvider,
    agent: Address,
    coprocessor: Address,
) -> Result<Address> {
    let mut code = gateway_bytecode()?;
    // Constructor args: two addresses, ABI-encoded as 32-byte words.
    for address in [agent, coprocessor] {
        code.extend_from_slice(&[0u8; 12]);
        code.extend_from_slice(address.as_slice());
    }
    let tx = TransactionRequest::default().with_deploy_code(code);
    let receipt = provider
        .send_transaction(tx)
        .await
        .map_err(chain_err)?
        .get_receipt()
        .await
        .map_err(chain_err)?;
    receipt
        .contract_address
        .ok_or_else(|| Error::Chain("deployment receipt has no contract address".to_string()))
}
