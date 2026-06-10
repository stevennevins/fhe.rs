//! Wall-clock timing for the typed `FheGoldilocks` SIMD operations at the
//! curated 128-bit parameters (degree 16384, six moduli). Source of the
//! numbers in BENCHMARKS.md ("Typed FheGoldilocks SIMD operations"); run
//! with and without `--features cuda` to compare backends.

use fhe::typed::{FheGoldilocks, GOLDILOCKS_MODULUS, ServerKey, set_server_key};
use rand::{Rng, rng};
use std::time::Instant;

fn time<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) {
    // Warm-up once (the first CUDA call pays NVRTC kernel compilation).
    let _ = f();
    let start = Instant::now();
    for _ in 0..iters {
        let _ = f();
    }
    println!(
        "{label:<28} {:>10.3} ms",
        start.elapsed().as_secs_f64() * 1e3 / f64::from(iters)
    );
}

fn main() {
    let mut r = rng();
    let params = FheGoldilocks::default_parameters_128().unwrap();
    let sk = fhe::bfv::SecretKey::random(&params, &mut r);
    set_server_key(ServerKey::new(&sk, &mut r).unwrap());

    let slots: Vec<u64> = (0..params.degree())
        .map(|_| r.random_range(0..GOLDILOCKS_MODULUS))
        .collect();

    let ca = FheGoldilocks::encrypt_slots(&slots, &sk, &mut r).unwrap();
    let cb = FheGoldilocks::encrypt_slots(&slots, &sk, &mut r).unwrap();

    println!("degree 16384, 6 moduli (291-bit q), 16384 slots/op");
    let mut rng2 = rng();
    time("encrypt_slots", 10, || {
        FheGoldilocks::encrypt_slots(&slots, &sk, &mut rng2).unwrap()
    });
    time("add (slot-wise)", 50, || &ca + &cb);
    time("mul + relin (slot-wise)", 10, || &ca * &cb);
    let prod = &ca * &cb;
    time("decrypt_slots", 10, || prod.decrypt_slots(&sk).unwrap());
}
