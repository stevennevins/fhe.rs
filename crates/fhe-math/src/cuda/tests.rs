#![expect(clippy::indexing_slicing, reason = "tests rely on validated indices")]

//! Differential tests: every GPU kernel result must be bit-exact equal to
//! the CPU implementation, across ring degrees, moduli counts and sizes,
//! random inputs, and edge cases.
//!
//! These tests require a CUDA device; they panic if none is available so
//! that a CI machine without GPU doesn't silently "pass" them. (Gate G2 is
//! evaluated on a CUDA machine.)

use super::{EwOp, backend, ew_force_gpu, ntt_force_gpu};
use crate::rq::{Context, Ntt, NttShoup, Poly, PowerBasis};
use crate::zq::primes::generate_prime;
use rand::RngCore;
use std::sync::Arc;

/// Builds a context with k NTT-friendly primes of mixed sizes.
fn test_ctx(n: usize, k: usize) -> Arc<Context> {
    let sizes = [62usize, 50, 30];
    let mut moduli: Vec<u64> = Vec::with_capacity(k);
    for i in 0..k {
        let bits = sizes[i % sizes.len()];
        let mut upper = 1u64 << bits;
        loop {
            let p = generate_prime(bits, 2 * n as u64, upper).unwrap();
            if !moduli.contains(&p) {
                moduli.push(p);
                break;
            }
            upper = p;
        }
    }
    Arc::new(Context::new(&moduli, n).unwrap())
}

fn require_gpu() {
    assert!(
        backend().is_some(),
        "differential tests require a CUDA device (or unset FHE_CUDA_DISABLE)"
    );
}

/// CPU reference forward/backward NTT, bypassing the GPU dispatch.
fn cpu_ntt(ctx: &Context, coeffs: &mut [u64], forward: bool) {
    let n = ctx.degree;
    for (row, op) in coeffs.chunks_exact_mut(n).zip(ctx.ops.iter()) {
        if forward {
            op.forward(row);
        } else {
            op.backward(row);
        }
    }
}

fn random_coeffs(ctx: &Context) -> Vec<u64> {
    let mut rng = rand::rng();
    let p = Poly::<PowerBasis>::random(&ctx.clone().into(), &mut rng);
    p.coefficients().as_slice().unwrap().to_vec()
}

fn check_ntt_case(n: usize, k: usize, iterations: usize) {
    require_gpu();
    let ctx = test_ctx(n, k);
    for _ in 0..iterations {
        let original = random_coeffs(&ctx);

        // Forward: GPU == CPU.
        let mut gpu = original.clone();
        assert!(ntt_force_gpu(&ctx, &mut gpu, true), "GPU forward failed");
        let mut cpu = original.clone();
        cpu_ntt(&ctx, &mut cpu, true);
        assert_eq!(gpu, cpu, "forward NTT mismatch (n={n}, k={k})");

        // Backward: GPU == CPU (on the NTT-domain values).
        let mut gpu_b = cpu.clone();
        assert!(
            ntt_force_gpu(&ctx, &mut gpu_b, false),
            "GPU backward failed"
        );
        let mut cpu_b = cpu.clone();
        cpu_ntt(&ctx, &mut cpu_b, false);
        assert_eq!(gpu_b, cpu_b, "backward NTT mismatch (n={n}, k={k})");

        // Round trip on GPU: INTT(NTT(x)) == x.
        assert_eq!(gpu_b, original, "GPU NTT round trip is not the identity");
    }
}

macro_rules! ntt_diff_tests {
    ($($name:ident: ($n:expr, $k:expr),)*) => {$(
        #[test]
        fn $name() {
            check_ntt_case($n, $k, 5);
        }
    )*};
}

ntt_diff_tests! {
    ntt_diff_8_1: (8, 1),
    ntt_diff_8_3: (8, 3),
    ntt_diff_16_2: (16, 2),
    ntt_diff_32_1: (32, 1),
    ntt_diff_256_2: (256, 2),
    ntt_diff_1024_3: (1024, 3),
    ntt_diff_2048_1: (2048, 1),
    ntt_diff_4096_2: (4096, 2),
    ntt_diff_4096_6: (4096, 6),
    ntt_diff_8192_3: (8192, 3),
    ntt_diff_8192_15: (8192, 15),
    ntt_diff_16384_2: (16384, 2),
    ntt_diff_16384_6: (16384, 6),
    ntt_diff_32768_3: (32768, 3),
    ntt_diff_32768_15: (32768, 15),
}

/// 1000 randomized GPU round trips (goal requirement) at a realistic size.
#[test]
fn ntt_roundtrip_1000() {
    require_gpu();
    let ctx = test_ctx(4096, 2);
    for _ in 0..1000 {
        let original = random_coeffs(&ctx);
        let mut a = original.clone();
        assert!(ntt_force_gpu(&ctx, &mut a, true));
        assert!(ntt_force_gpu(&ctx, &mut a, false));
        assert_eq!(a, original);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

fn check_edge_case(n: usize, k: usize, make: impl Fn(&Context) -> Vec<u64>) {
    require_gpu();
    let ctx = test_ctx(n, k);
    let original = make(&ctx);
    for forward in [true, false] {
        let mut gpu = original.clone();
        assert!(ntt_force_gpu(&ctx, &mut gpu, forward));
        let mut cpu = original.clone();
        cpu_ntt(&ctx, &mut cpu, forward);
        assert_eq!(gpu, cpu, "edge case mismatch (n={n}, k={k}, fwd={forward})");
    }
}

fn zero_poly(ctx: &Context) -> Vec<u64> {
    vec![0u64; ctx.moduli.len() * ctx.degree]
}

fn qminus1_poly(ctx: &Context) -> Vec<u64> {
    let mut v = Vec::with_capacity(ctx.moduli.len() * ctx.degree);
    for p in ctx.moduli.iter() {
        v.extend(std::iter::repeat_n(p - 1, ctx.degree));
    }
    v
}

fn single_coeff_poly(ctx: &Context) -> Vec<u64> {
    let n = ctx.degree;
    let mut v = vec![0u64; ctx.moduli.len() * n];
    let idx = (rand::rng().next_u64() as usize) % n;
    for (row, p) in ctx.moduli.iter().enumerate() {
        v[row * n + idx] = p - 1;
    }
    v
}

macro_rules! edge_tests {
    ($($name:ident: ($n:expr, $k:expr, $make:expr),)*) => {$(
        #[test]
        fn $name() {
            check_edge_case($n, $k, $make);
        }
    )*};
}

edge_tests! {
    edge_zero_8_2: (8, 2, zero_poly),
    edge_zero_1024_3: (1024, 3, zero_poly),
    edge_zero_4096_6: (4096, 6, zero_poly),
    edge_zero_32768_2: (32768, 2, zero_poly),
    edge_qminus1_8_2: (8, 2, qminus1_poly),
    edge_qminus1_1024_3: (1024, 3, qminus1_poly),
    edge_qminus1_4096_6: (4096, 6, qminus1_poly),
    edge_qminus1_32768_2: (32768, 2, qminus1_poly),
    edge_single_8_2: (8, 2, single_coeff_poly),
    edge_single_1024_3: (1024, 3, single_coeff_poly),
    edge_single_4096_6: (4096, 6, single_coeff_poly),
    edge_single_32768_2: (32768, 2, single_coeff_poly),
}

// ---------------------------------------------------------------------------
// Element-wise operations
// ---------------------------------------------------------------------------

/// CPU reference for an element-wise op, using zq::Modulus directly.
fn cpu_ew(ctx: &Context, op: EwOp, a: &mut [u64], b: &[u64], b_shoup: &[u64]) {
    let n = ctx.degree;
    for (i, q) in ctx.q.iter().enumerate() {
        let arow = &mut a[i * n..(i + 1) * n];
        let brow = &b[i * n..(i + 1) * n];
        match op {
            EwOp::Add => q.add_vec(arow, brow),
            EwOp::Sub => q.sub_vec(arow, brow),
            EwOp::Neg => q.neg_vec(arow),
            EwOp::Mul => q.mul_vec(arow, brow),
            EwOp::MulShoup => q.mul_shoup_vec(arow, brow, &b_shoup[i * n..(i + 1) * n]),
        }
    }
}

fn check_ew_case(n: usize, k: usize, op: EwOp) {
    require_gpu();
    let ctx = test_ctx(n, k);
    for _ in 0..5 {
        let a = random_coeffs(&ctx);
        let b = random_coeffs(&ctx);
        let mut b_shoup = Vec::with_capacity(k * n);
        for (i, q) in ctx.q.iter().enumerate() {
            b_shoup.extend(q.shoup_vec(&b[i * n..(i + 1) * n]));
        }

        let mut gpu = a.clone();
        assert!(
            ew_force_gpu(&ctx, op, &mut gpu, Some(&b), Some(&b_shoup)),
            "GPU element-wise op failed"
        );
        let mut cpu = a.clone();
        cpu_ew(&ctx, op, &mut cpu, &b, &b_shoup);
        assert_eq!(gpu, cpu, "element-wise mismatch (n={n}, k={k})");
    }
}

macro_rules! ew_tests {
    ($($name:ident: ($n:expr, $k:expr, $op:expr),)*) => {$(
        #[test]
        fn $name() {
            check_ew_case($n, $k, $op);
        }
    )*};
}

ew_tests! {
    ew_add_8_3: (8, 3, EwOp::Add),
    ew_add_1024_2: (1024, 2, EwOp::Add),
    ew_add_4096_6: (4096, 6, EwOp::Add),
    ew_add_32768_15: (32768, 15, EwOp::Add),
    ew_sub_8_3: (8, 3, EwOp::Sub),
    ew_sub_1024_2: (1024, 2, EwOp::Sub),
    ew_sub_4096_6: (4096, 6, EwOp::Sub),
    ew_sub_32768_15: (32768, 15, EwOp::Sub),
    ew_neg_8_3: (8, 3, EwOp::Neg),
    ew_neg_1024_2: (1024, 2, EwOp::Neg),
    ew_neg_4096_6: (4096, 6, EwOp::Neg),
    ew_neg_32768_15: (32768, 15, EwOp::Neg),
    ew_mul_8_3: (8, 3, EwOp::Mul),
    ew_mul_1024_2: (1024, 2, EwOp::Mul),
    ew_mul_4096_6: (4096, 6, EwOp::Mul),
    ew_mul_32768_15: (32768, 15, EwOp::Mul),
    ew_mul_shoup_8_3: (8, 3, EwOp::MulShoup),
    ew_mul_shoup_1024_2: (1024, 2, EwOp::MulShoup),
    ew_mul_shoup_4096_6: (4096, 6, EwOp::MulShoup),
    ew_mul_shoup_32768_15: (32768, 15, EwOp::MulShoup),
}

/// The public dispatch path (Poly::into_ntt with the heuristic) must agree
/// with a pure-CPU reference too.
#[test]
fn dispatched_into_ntt_matches_cpu() {
    require_gpu();
    let mut rng = rand::rng();
    for (n, k) in [(4096, 2), (8192, 6), (16384, 3)] {
        let ctx = test_ctx(n, k);
        let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
        let mut cpu = p.coefficients().as_slice().unwrap().to_vec();
        cpu_ntt(&ctx, &mut cpu, true);
        let q = p.into_ntt();
        assert_eq!(q.coefficients().as_slice().unwrap(), &cpu[..]);
    }
}

// ---------------------------------------------------------------------------
// RNS scaling (Scaler::scale)
// ---------------------------------------------------------------------------

/// CPU reference replicating the CPU body of `rq::scaler::Scaler::scale`,
/// bypassing the GPU dispatch.
fn cpu_scale(
    scaler: &crate::rq::scaler::Scaler,
    coeffs: &ndarray::Array2<u64>,
    needs_transform: bool,
) -> ndarray::Array2<u64> {
    use ndarray::{Axis, s};
    let common = scaler.number_common_moduli;
    let k_to = scaler.to.q.len();
    let n = scaler.to.degree;
    let mut new_coefficients = ndarray::Array2::<u64>::zeros((k_to, n));

    if common > 0 {
        new_coefficients
            .slice_mut(s![..common, ..])
            .assign(&coeffs.slice(s![..common, ..]));
    }
    if common < k_to {
        let mut pb = coeffs.clone();
        if needs_transform {
            for (mut row, op) in pb.outer_iter_mut().zip(scaler.from.ops.iter()) {
                op.backward(row.as_slice_mut().unwrap());
            }
        }
        for (new_column, column) in new_coefficients
            .slice_mut(s![common.., ..])
            .axis_iter_mut(Axis(1))
            .zip(pb.axis_iter(Axis(1)))
        {
            scaler.scaler.scale(column, new_column, common);
        }
        if needs_transform {
            for (mut row, op) in new_coefficients
                .slice_mut(s![common.., ..])
                .outer_iter_mut()
                .zip(scaler.to.ops[common..].iter())
            {
                op.forward(row.as_slice_mut().unwrap());
            }
        }
    }
    new_coefficients
}

fn check_scale_case(n: usize, k_from: usize, k_to: usize, extend: bool) {
    use crate::rns::ScalingFactor;
    use crate::rq::scaler::Scaler;
    use num_bigint::BigUint;

    require_gpu();
    let from = test_ctx(n, k_from);
    let to = if extend {
        // The `to` context extends `from` (same prefix), factor one — the
        // basis-extension case of BFV multiplication.
        let mut moduli = from.moduli.to_vec();
        let big = test_ctx(n, k_to + k_from);
        for m in big.moduli.iter() {
            if !moduli.contains(m) && moduli.len() < k_to {
                moduli.push(*m);
            }
        }
        Arc::new(Context::new(&moduli, n).unwrap())
    } else {
        test_ctx(n, k_to)
    };
    let factor = if extend {
        ScalingFactor::one()
    } else {
        // The down-scaling case: t/Q.
        ScalingFactor::new(&BigUint::from(1153u64), from.modulus())
    };
    let scaler = Scaler::new(&from, &to, factor).unwrap();

    let mut rng = rand::rng();
    for _ in 0..3 {
        for needs_transform in [false, true] {
            let p = Poly::<PowerBasis>::random(&from, &mut rng);
            let coeffs = p.coefficients().to_owned();
            let gpu = super::scale_coeffs(&scaler, &coeffs.view(), needs_transform).unwrap();
            let cpu = cpu_scale(&scaler, &coeffs, needs_transform);
            assert_eq!(
                gpu, cpu,
                "scale mismatch (n={n}, {k_from}->{k_to}, extend={extend}, ntt={needs_transform})"
            );
        }
    }
}

macro_rules! scale_tests {
    ($($name:ident: ($n:expr, $kf:expr, $kt:expr, $extend:expr),)*) => {$(
        #[test]
        fn $name() {
            check_scale_case($n, $kf, $kt, $extend);
        }
    )*};
}

scale_tests! {
    scale_extend_1024_4_8: (1024, 4, 8, true),
    scale_extend_4096_3_6: (4096, 3, 6, true),
    scale_extend_8192_6_12: (8192, 6, 12, true),
    scale_extend_16384_15_30: (16384, 15, 30, true),
    scale_down_4096_6_3: (4096, 6, 3, false),
    scale_down_8192_12_6: (8192, 12, 6, false),
    scale_down_16384_8_4: (16384, 8, 4, false),
    scale_down_32768_15_8: (32768, 15, 8, false),
}

// ---------------------------------------------------------------------------
// Fused key switching (cuda::key_switch)
// ---------------------------------------------------------------------------

/// CPU reference replicating the CPU body of `KeySwitchingKey::key_switch`
/// in the `fhe` crate, bypassing the GPU dispatch.
fn cpu_key_switch(
    p: &Poly<PowerBasis>,
    c0s: &[Poly<NttShoup>],
    c1s: &[Poly<NttShoup>],
    ctx_ksk: &Arc<Context>,
) -> (Poly<Ntt>, Poly<Ntt>) {
    let mut c0 = Poly::<Ntt>::zero(ctx_ksk);
    let mut c1 = Poly::<Ntt>::zero(ctx_ksk);
    let p_coefficients = p.coefficients();
    for ((row, c0_i), c1_i) in p_coefficients.outer_iter().zip(c0s).zip(c1s) {
        let mut c2_i = unsafe {
            Poly::<Ntt>::create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
                row.as_slice().unwrap(),
                ctx_ksk,
            )
        };
        c0 += &(&c2_i * c0_i);
        c2_i *= c1_i;
        c1 += &c2_i;
    }
    (c0, c1)
}

/// The fused GPU key switch must be bit-exact with the CPU loop it replaces,
/// both when the input shares the ksk context and in the BFV shape where the
/// ciphertext context is a strict prefix of the ksk context.
#[test]
fn key_switch_matches_cpu() {
    require_gpu();
    let n = 4096;
    let ctx_ksk = test_ctx(n, 3); // n * k = 12288 >= MIN_NTT_ELEMS
    let ctx_cipher = Arc::new(Context::new(&ctx_ksk.moduli[..2], n).unwrap());
    let mut rng = rand::rng();
    for ctx_p in [&ctx_ksk, &ctx_cipher] {
        for _ in 0..5 {
            let p = Poly::<PowerBasis>::random(ctx_p, &mut rng);
            let c0s: Vec<_> = (0..3)
                .map(|_| Poly::<NttShoup>::random(&ctx_ksk, &mut rng))
                .collect();
            let c1s: Vec<_> = (0..3)
                .map(|_| Poly::<NttShoup>::random(&ctx_ksk, &mut rng))
                .collect();
            let (g0, g1) = super::key_switch(&p, &c0s, &c1s, &ctx_ksk).unwrap();
            let (e0, e1) = cpu_key_switch(&p, &c0s, &c1s, &ctx_ksk);
            assert_eq!(g0.coefficients(), e0.coefficients(), "c0 mismatch");
            assert_eq!(g1.coefficients(), e1.coefficients(), "c1 mismatch");
        }
    }
}

/// Concurrent GPU use from many threads must be safe and bit-exact
/// (per-thread streams + shared table caches).
#[test]
fn thread_stress() {
    require_gpu();
    let ctx = test_ctx(8192, 6);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let original = random_coeffs(&ctx);
                    let mut gpu = original.clone();
                    assert!(ntt_force_gpu(&ctx, &mut gpu, true));
                    let mut cpu = original.clone();
                    cpu_ntt(&ctx, &mut cpu, true);
                    assert_eq!(gpu, cpu);
                    assert!(ntt_force_gpu(&ctx, &mut gpu, false));
                    assert_eq!(gpu, original);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// The dispatcher must keep small operations on the CPU (G4): below the
/// size threshold the GPU entry points decline and leave data untouched.
#[test]
fn small_params_stay_on_cpu() {
    require_gpu();
    // n = 2^12 with one modulus is below MIN_NTT_ELEMS.
    let ctx = test_ctx(4096, 1);
    const { assert!(4096 < super::MIN_NTT_ELEMS) };
    let original = random_coeffs(&ctx);
    let mut a = original.clone();
    assert!(!super::ntt_forward(&ctx, &mut a));
    assert_eq!(a, original, "declined dispatch must not modify data");
}
