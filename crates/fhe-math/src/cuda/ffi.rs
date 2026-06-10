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
) -> Result<(), DriverError> {
    debug_assert_eq!(a.len() as u32, k * n);
    let mut b = stream.launch_builder(f);
    b.arg(a)
        .arg(size_inv)
        .arg(size_inv_shoup)
        .arg(moduli)
        .arg(&n)
        .arg(&k);
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
