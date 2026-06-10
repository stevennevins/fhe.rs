//! The single unsafe boundary of the CUDA backend: kernel launches.
//!
//! Every function here wraps exactly one kernel launch from `kernels.cu` in
//! a safe signature. The safety argument is the same for all of them: the
//! kernels index `a` only at indices derived from a global thread id that is
//! bounds-checked against `k * n` (or `k * n / 2` butterflies), and index the
//! table buffers at indices `< k * n` (twiddles) or `< k` (per-modulus
//! scalars); the callers in `mod.rs` always pass buffers of exactly those
//! sizes, built from a `rq::Context` with `k` moduli and degree `n`.

#![expect(
    clippy::too_many_arguments,
    reason = "kernel launches mirror the kernel parameter lists"
)]

use cudarc::driver::{
    CudaFunction, CudaSlice, CudaStream, DriverError, LaunchConfig, PushKernelArg,
};

const BLOCK: u32 = 256;

fn cfg(threads: u32) -> LaunchConfig {
    LaunchConfig {
        grid_dim: (threads.div_ceil(BLOCK), 1, 1),
        block_dim: (BLOCK, 1, 1),
        shared_mem_bytes: 0,
    }
}

/// One forward NTT butterfly stage over all k rows.
pub(super) fn ntt_fwd_stage(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    omegas: &CudaSlice<u64>,
    omegas_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
    tab_off: u32,
    l: u32,
    reduce_out: i32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(omegas)
        .arg(omegas_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k)
        .arg(&tab_off)
        .arg(&l)
        .arg(&reduce_out);
    // SAFETY: see module docs; `a` has k*n elements, the twiddle tables have
    // k*n elements, `moduli` has k elements, and the kernel bounds-checks
    // its thread id against k*n/2 butterflies.
    unsafe { b.launch(cfg(k * (n >> 1))) }?;
    Ok(())
}

/// One backward NTT butterfly stage over all k rows.
pub(super) fn ntt_inv_stage(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    zetas_inv: &CudaSlice<u64>,
    zetas_inv_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
    tab_off: u32,
    l: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(zetas_inv)
        .arg(zetas_inv_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k)
        .arg(&tab_off)
        .arg(&l);
    // SAFETY: see module docs; buffer sizes as in `ntt_fwd_stage`.
    unsafe { b.launch(cfg(k * (n >> 1))) }?;
    Ok(())
}

/// Final scaling by n^-1 of the backward NTT, all k rows.
pub(super) fn ntt_inv_final(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    size_inv: &CudaSlice<u64>,
    size_inv_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
    tab_off: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(size_inv)
        .arg(size_inv_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k)
        .arg(&tab_off);
    // SAFETY: see module docs; `a` has k*n elements, the per-modulus tables
    // have k elements, and the kernel bounds-checks against k*n.
    unsafe { b.launch(cfg(k * n)) }?;
    Ok(())
}

/// Element-wise binary operation (`ew_add` / `ew_sub`) on k×n matrices.
pub(super) fn ew_binary(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    b: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert_eq!(b.len() as u32, k * n);
    let mut lb = stream.launch_builder(f);
    lb.arg(a).arg(b).arg(moduli).arg(&n).arg(&k);
    // SAFETY: see module docs; both operands have k*n elements and the
    // kernel bounds-checks against k*n.
    unsafe { lb.launch(cfg(k * n)) }?;
    Ok(())
}

/// Element-wise negation on a k×n matrix.
pub(super) fn ew_neg(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    let mut b = stream.launch_builder(f);
    b.arg(a).arg(moduli).arg(&n).arg(&k);
    // SAFETY: see module docs.
    unsafe { b.launch(cfg(k * n)) }?;
    Ok(())
}

/// Element-wise Barrett multiplication on k×n matrices.
pub(super) fn ew_mul(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    b: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    barrett_hi: &CudaSlice<u64>,
    barrett_lo: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert_eq!(b.len() as u32, k * n);
    let mut lb = stream.launch_builder(f);
    lb.arg(a)
        .arg(b)
        .arg(moduli)
        .arg(barrett_hi)
        .arg(barrett_lo)
        .arg(&n)
        .arg(&k);
    // SAFETY: see module docs; per-modulus tables have k elements.
    unsafe { lb.launch(cfg(k * n)) }?;
    Ok(())
}

/// Element-wise Shoup multiplication on k×n matrices (b with precomputed
/// Shoup representation b_shoup).
pub(super) fn ew_mul_shoup(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    b: &CudaSlice<u64>,
    b_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert_eq!(b.len() as u32, k * n);
    debug_assert_eq!(b_shoup.len() as u32, k * n);
    let mut lb = stream.launch_builder(f);
    lb.arg(a).arg(b).arg(b_shoup).arg(moduli).arg(&n).arg(&k);
    // SAFETY: see module docs.
    unsafe { lb.launch(cfg(k * n)) }?;
    Ok(())
}

/// Launch parameters for the RNS scaling kernel (one thread per coefficient).
pub(super) struct RnsScaleArgs<'a> {
    pub input: &'a CudaSlice<u64>,
    pub out: &'a mut CudaSlice<u64>,
    pub to_moduli: &'a CudaSlice<u64>,
    pub to_barrett_hi: &'a CudaSlice<u64>,
    pub to_barrett_lo: &'a CudaSlice<u64>,
    pub gamma: &'a CudaSlice<u64>,
    pub gamma_shoup: &'a CudaSlice<u64>,
    pub omega: &'a CudaSlice<u64>,
    pub omega_shoup: &'a CudaSlice<u64>,
    pub theta_omega_lo: &'a CudaSlice<u64>,
    pub theta_omega_hi: &'a CudaSlice<u64>,
    pub theta_omega_sign: &'a CudaSlice<u64>,
    pub theta_garner_lo: &'a CudaSlice<u64>,
    pub theta_garner_hi: &'a CudaSlice<u64>,
    pub theta_gamma_lo: u64,
    pub theta_gamma_hi: u64,
    pub theta_gamma_sign: u32,
    pub theta_garner_shift: u32,
    pub is_one: u32,
    pub n: u32,
    pub k_from: u32,
    pub k_write: u32,
    pub start: u32,
}

/// RNS scaling of all coefficients (rns::scaler::RnsScaler::scale).
pub(super) fn rns_scale(
    stream: &CudaStream,
    f: &CudaFunction,
    args: RnsScaleArgs<'_>,
) -> Result<(), DriverError> {
    debug_assert_eq!(args.input.len() as u32, args.k_from * args.n);
    debug_assert_eq!(args.out.len() as u32, args.k_write * args.n);
    let mut b = stream.launch_builder(f);
    b.arg(args.input)
        .arg(args.out)
        .arg(args.to_moduli)
        .arg(args.to_barrett_hi)
        .arg(args.to_barrett_lo)
        .arg(args.gamma)
        .arg(args.gamma_shoup)
        .arg(args.omega)
        .arg(args.omega_shoup)
        .arg(args.theta_omega_lo)
        .arg(args.theta_omega_hi)
        .arg(args.theta_omega_sign)
        .arg(args.theta_garner_lo)
        .arg(args.theta_garner_hi)
        .arg(&args.theta_gamma_lo)
        .arg(&args.theta_gamma_hi)
        .arg(&args.theta_gamma_sign)
        .arg(&args.theta_garner_shift)
        .arg(&args.is_one)
        .arg(&args.n)
        .arg(&args.k_from)
        .arg(&args.k_write)
        .arg(&args.start);
    // SAFETY: see module docs; `input` is k_from*n, `out` is k_write*n, the
    // per-to-modulus tables have at least start + k_write elements, omega
    // tables are k_to*k_from, per-from tables are k_from, and the kernel
    // bounds-checks its thread id against n coefficients.
    unsafe { b.launch(cfg(args.n)) }?;
    Ok(())
}

/// Broadcast one row into k lazily-reduced rows (key-switch input).
pub(super) fn broadcast_lazy_reduce(
    stream: &CudaStream,
    f: &CudaFunction,
    out: &mut CudaSlice<u64>,
    input: &cudarc::driver::CudaView<'_, u64>,
    moduli: &CudaSlice<u64>,
    barrett_hi: &CudaSlice<u64>,
    barrett_lo: &CudaSlice<u64>,
    supports_opt: &CudaSlice<u64>,
    leading_zeros: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(out.len() as u32, k * n);
    debug_assert!(input.len() as u32 >= n);
    let mut b = stream.launch_builder(f);
    b.arg(out)
        .arg(input)
        .arg(moduli)
        .arg(barrett_hi)
        .arg(barrett_lo)
        .arg(supports_opt)
        .arg(leading_zeros)
        .arg(&n)
        .arg(&k);
    // SAFETY: see module docs; `out` has k*n elements, `input` at least n,
    // per-modulus tables k elements; the kernel bounds-checks against k*n.
    unsafe { b.launch(cfg(k * n)) }?;
    Ok(())
}

/// Key-switch accumulation: acc += mul_shoup(a, b) element-wise.
pub(super) fn ew_mul_shoup_acc(
    stream: &CudaStream,
    f: &CudaFunction,
    acc: &mut CudaSlice<u64>,
    a: &CudaSlice<u64>,
    b: &cudarc::driver::CudaView<'_, u64>,
    b_shoup: &cudarc::driver::CudaView<'_, u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(acc.len() as u32, k * n);
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert_eq!(b.len() as u32, k * n);
    debug_assert_eq!(b_shoup.len() as u32, k * n);
    let mut lb = stream.launch_builder(f);
    lb.arg(acc)
        .arg(a)
        .arg(b)
        .arg(b_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k);
    // SAFETY: see module docs; all operands have k*n elements and the kernel
    // bounds-checks against k*n.
    unsafe { lb.launch(cfg(k * n)) }?;
    Ok(())
}

/// Fused forward NTT stages l = 256..1 in shared memory (one launch).
pub(super) fn ntt_fwd_fused_tail(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    omegas: &CudaSlice<u64>,
    omegas_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
    tab_off: u32,
    reduce_out: i32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert!(n >= 512);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(omegas)
        .arg(omegas_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k)
        .arg(&tab_off)
        .arg(&reduce_out);
    let blocks = k * (n / 512);
    // SAFETY: see module docs; one block per 512-element tile, k*(n/512)
    // blocks, each accessing only its own tile and the k*n twiddle tables.
    unsafe {
        b.launch(LaunchConfig {
            grid_dim: (blocks, 1, 1),
            block_dim: (256, 1, 1),
            shared_mem_bytes: 0,
        })
    }?;
    Ok(())
}

/// Fused backward NTT stages l = 1..256 in shared memory (one launch).
pub(super) fn ntt_inv_fused_head(
    stream: &CudaStream,
    f: &CudaFunction,
    a: &mut CudaSlice<u64>,
    zetas_inv: &CudaSlice<u64>,
    zetas_inv_shoup: &CudaSlice<u64>,
    moduli: &CudaSlice<u64>,
    n: u32,
    k: u32,
    tab_off: u32,
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    debug_assert!(n >= 512);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(zetas_inv)
        .arg(zetas_inv_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k)
        .arg(&tab_off);
    let blocks = k * (n / 512);
    // SAFETY: as in `ntt_fwd_fused_tail`.
    unsafe {
        b.launch(LaunchConfig {
            grid_dim: (blocks, 1, 1),
            block_dim: (256, 1, 1),
            shared_mem_bytes: 0,
        })
    }?;
    Ok(())
}
