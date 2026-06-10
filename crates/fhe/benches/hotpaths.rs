//! Benchmark grid for the GPU-offload hot paths: NTT, ciphertext add,
//! multiply + relinearize, and rotation, across ring degrees and RNS sizes.
#![expect(missing_docs, reason = "examples/benches/tests omit docs by design")]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKeyBuilder, Multiplicator,
    Plaintext, RelinearizationKey, SecretKey,
};
use fhe_math::rq::{Context, Ntt, Poly, PowerBasis};
use fhe_traits::{FheEncoder, FheEncrypter};
use itertools::Itertools;
use rand::rng;
use std::sync::Arc;
use std::time::Duration;

static DEGREES: &[usize] = &[1 << 12, 1 << 13, 1 << 14, 1 << 15];
static NMODULI: &[usize] = &[2, 6, 15];
const NTT_BATCH_SIZE: usize = 64;

fn params(degree: usize, nmoduli: usize) -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(1153)
        .set_moduli_sizes(&vec![62usize; nmoduli])
        .build_arc()
        .unwrap()
}

pub fn ntt_grid_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotpaths_ntt");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(2));
    let mut rng = rng();

    for &degree in DEGREES {
        for &nmoduli in NMODULI {
            let par = params(degree, nmoduli);
            let ctx = Arc::new(Context::new(par.moduli(), degree).unwrap());

            let p_pb = Poly::<PowerBasis>::random(&ctx, &mut rng);
            group.bench_function(
                BenchmarkId::new("forward", format!("n={degree}/k={nmoduli}")),
                |b| {
                    b.iter(|| {
                        let _ = p_pb.clone().into_ntt();
                    })
                },
            );

            let p_ntt = Poly::<Ntt>::random(&ctx, &mut rng);
            group.bench_function(
                BenchmarkId::new("backward", format!("n={degree}/k={nmoduli}")),
                |b| {
                    b.iter(|| {
                        let _ = p_ntt.clone().into_power_basis();
                    })
                },
            );

            // Batched NTT throughput (G4 target needs >= 64 polynomials);
            // only measured at one RNS size to keep the grid small.
            if nmoduli == 6 {
                let batch = (0..NTT_BATCH_SIZE)
                    .map(|_| Poly::<PowerBasis>::random(&ctx, &mut rng))
                    .collect_vec();
                group.bench_function(
                    BenchmarkId::new("forward_batch64", format!("n={degree}/k={nmoduli}")),
                    |b| {
                        b.iter(|| {
                            for p in &batch {
                                let _ = p.clone().into_ntt();
                            }
                        })
                    },
                );
            }
        }
    }
    group.finish();
}

pub fn ciphertext_grid_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotpaths_bfv");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(2));
    let mut rng = rng();

    for &degree in DEGREES {
        for &nmoduli in NMODULI {
            let par = params(degree, nmoduli);
            let sk = SecretKey::random(&par, &mut rng);
            let rk = RelinearizationKey::new(&sk, &mut rng).unwrap();
            let ek = EvaluationKeyBuilder::new(&sk)
                .unwrap()
                .enable_column_rotation(1)
                .unwrap()
                .build(&mut rng)
                .unwrap();

            let pt1 =
                Plaintext::try_encode(&(1..16u64).collect_vec(), Encoding::poly(), &par).unwrap();
            let pt2 =
                Plaintext::try_encode(&(3..39u64).collect_vec(), Encoding::poly(), &par).unwrap();
            let c1: Ciphertext = sk.try_encrypt(&pt1, &mut rng).unwrap();
            let c2: Ciphertext = sk.try_encrypt(&pt2, &mut rng).unwrap();

            let id = format!("n={degree}/k={nmoduli}");

            group.bench_function(BenchmarkId::new("add_ct", &id), |b| b.iter(|| &c1 + &c2));

            let multiplicator = Multiplicator::default(&rk).unwrap();
            group.bench_function(BenchmarkId::new("mul_relin", &id), |b| {
                b.iter(|| multiplicator.multiply(&c1, &c2).unwrap())
            });

            group.bench_function(BenchmarkId::new("rotate_columns", &id), |b| {
                b.iter(|| ek.rotates_columns_by(&c1, 1).unwrap())
            });
        }
    }
    group.finish();
}

criterion_group!(hotpaths, ntt_grid_benchmark, ciphertext_grid_benchmark);
criterion_main!(hotpaths);
