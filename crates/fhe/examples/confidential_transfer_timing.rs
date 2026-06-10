//! Wall-clock timing for the confidential token kit at the curated
//! 128-bit parameters (degree 16384, six moduli): committee keygen and
//! the cost of a single confidential transfer (balance-guard comparison,
//! cmux balance updates, and the two gateway refreshes). Run with and
//! without `--features cuda` to compare backends. The extension suite's
//! per-operation costs are measured by the companion
//! `erc7984_extensions_timing` example.

use std::time::Instant;

use fhe::gateway::Committee;
use fhe::token::ConfidentialToken;
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const ALICE: u64 = 1;
const BOB: u64 = 2;

fn main() {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128().unwrap();

    let start = Instant::now();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    println!(
        "committee keygen (N=3)       {:>10.3} s",
        start.elapsed().as_secs_f64()
    );
    set_server_key(committee.server_key());

    let mut token = ConfidentialToken::new(committee, &mut rng).unwrap();
    token.mint(ALICE, 1_000_000, &mut rng).unwrap();
    token.mint(BOB, 500_000, &mut rng).unwrap();

    // Warm-up transfer (the first CUDA call pays kernel compilation).
    let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
    token.transfer(ALICE, BOB, &amount, &mut rng).unwrap();

    const ITERS: u32 = 5;
    let start = Instant::now();
    for i in 0..ITERS {
        let (from, to) = if i % 2 == 0 {
            (ALICE, BOB)
        } else {
            (BOB, ALICE)
        };
        let amount = token.committee().encrypt(1_000, &mut rng).unwrap();
        token.transfer(from, to, &amount, &mut rng).unwrap();
    }
    println!(
        "confidential transfer        {:>10.3} s",
        start.elapsed().as_secs_f64() / f64::from(ITERS)
    );
}
