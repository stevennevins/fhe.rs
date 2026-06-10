//! CUDA backend for the polynomial arithmetic hot paths.
//!
//! Everything in this module is internal: the public API of the crate is
//! unchanged, and every entry point falls back to the CPU implementation
//! when no usable CUDA device is present (or `FHE_CUDA_DISABLE=1` is set).
//!
//! Bit-exactness: kernels in `kernels.cu` mirror the arithmetic of
//! `zq::Modulus` and `ntt::native::NttOperator` exactly, and reuse the
//! host-precomputed twiddle/Shoup tables, so GPU results are identical to
//! CPU results for every operation.

mod ffi;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use cudarc::driver::{CudaContext, CudaFunction, CudaSlice, CudaStream};
use cudarc::nvrtc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::rq::Context;

/// Borrowed view of the NTT precomputed tables of one modulus
/// (see `ntt::native::NttOperator::cuda_tables`).
pub(crate) struct NttTables<'a> {
    pub omegas: &'a [u64],
    pub omegas_shoup: &'a [u64],
    pub zetas_inv: &'a [u64],
    pub zetas_inv_shoup: &'a [u64],
    pub size_inv: u64,
    pub size_inv_shoup: u64,
}

/// Minimum number of u64 elements (rows × degree) for which offloading an
/// NTT to the GPU beats the CPU, determined with the `hotpaths` benchmark
/// grid (see BENCHMARKS.md). Below this, the CPU path is used.
const MIN_NTT_ELEMS: usize = 1 << 13;

/// Per-(moduli, degree) tables resident on the device.
struct DeviceTables {
    moduli: CudaSlice<u64>,
    barrett_hi: CudaSlice<u64>,
    barrett_lo: CudaSlice<u64>,
    omegas: CudaSlice<u64>,
    omegas_shoup: CudaSlice<u64>,
    zetas_inv: CudaSlice<u64>,
    zetas_inv_shoup: CudaSlice<u64>,
    size_inv: CudaSlice<u64>,
    size_inv_shoup: CudaSlice<u64>,
}

/// Compiled kernels.
struct Kernels {
    ntt_fwd_stage: CudaFunction,
    ntt_inv_stage: CudaFunction,
    ntt_inv_final: CudaFunction,
    ew_add: CudaFunction,
    ew_sub: CudaFunction,
    ew_neg: CudaFunction,
    ew_mul: CudaFunction,
    ew_mul_shoup: CudaFunction,
}

/// Cache of device tables, keyed by (moduli, degree).
type TableCache = HashMap<(Box<[u64]>, usize), Arc<DeviceTables>>;

/// Global CUDA state: device context, compiled module, table cache.
pub(crate) struct CudaBackend {
    ctx: Arc<CudaContext>,
    kernels: Kernels,
    tables: Mutex<TableCache>,
}

/// Returns the global CUDA backend, or None if no usable device exists.
pub(crate) fn backend() -> Option<&'static CudaBackend> {
    static BACKEND: OnceLock<Option<CudaBackend>> = OnceLock::new();
    BACKEND.get_or_init(CudaBackend::init).as_ref()
}

thread_local! {
    /// One stream per host thread so concurrent operations don't serialize.
    static STREAM: std::cell::OnceCell<Option<Arc<CudaStream>>> =
        const { std::cell::OnceCell::new() };
}

/// Returns this thread's CUDA stream.
fn stream(backend: &CudaBackend) -> Option<Arc<CudaStream>> {
    STREAM.with(|s| {
        s.get_or_init(|| backend.ctx.new_stream().ok().map(|s| s as Arc<CudaStream>))
            .clone()
    })
}

impl CudaBackend {
    fn init() -> Option<Self> {
        if std::env::var_os("FHE_CUDA_DISABLE").is_some_and(|v| v != "0") {
            return None;
        }
        let ctx = CudaContext::new(0).ok()?;
        let (major, minor) = ctx.compute_capability().ok()?;
        let opts = nvrtc::CompileOptions {
            options: vec![
                format!("--gpu-architecture=compute_{major}{minor}"),
                // The Barrett reduction mirrors the CPU's u128 arithmetic.
                "--device-int128".to_string(),
            ],
            ..Default::default()
        };
        let ptx = nvrtc::compile_ptx_with_opts(include_str!("kernels.cu"), opts).ok()?;
        let module = ctx.load_module(ptx).ok()?;
        let kernels = Kernels {
            ntt_fwd_stage: module.load_function("ntt_fwd_stage").ok()?,
            ntt_inv_stage: module.load_function("ntt_inv_stage").ok()?,
            ntt_inv_final: module.load_function("ntt_inv_final").ok()?,
            ew_add: module.load_function("ew_add").ok()?,
            ew_sub: module.load_function("ew_sub").ok()?,
            ew_neg: module.load_function("ew_neg").ok()?,
            ew_mul: module.load_function("ew_mul").ok()?,
            ew_mul_shoup: module.load_function("ew_mul_shoup").ok()?,
        };
        Some(Self {
            ctx,
            kernels,
            tables: Mutex::new(HashMap::new()),
        })
    }

    /// Returns (uploading on first use) the device tables for a context.
    fn tables(&self, ctx: &Context, stream: &Arc<CudaStream>) -> Option<Arc<DeviceTables>> {
        let key = (ctx.moduli.clone(), ctx.degree);
        let mut cache = self.tables.lock().ok()?;
        if let Some(t) = cache.get(&key) {
            return Some(t.clone());
        }

        let k = ctx.moduli.len();
        let n = ctx.degree;
        let mut barrett_hi = Vec::with_capacity(k);
        let mut barrett_lo = Vec::with_capacity(k);
        for p in ctx.moduli.iter() {
            // Same value as zq::Modulus::new: barrett = floor(2^128 / p).
            let barrett = ((BigUint::from(1u8) << 128u32) / p).to_u128()?;
            barrett_hi.push((barrett >> 64) as u64);
            barrett_lo.push(barrett as u64);
        }

        let mut omegas = Vec::with_capacity(k * n);
        let mut omegas_shoup = Vec::with_capacity(k * n);
        let mut zetas_inv = Vec::with_capacity(k * n);
        let mut zetas_inv_shoup = Vec::with_capacity(k * n);
        let mut size_inv = Vec::with_capacity(k);
        let mut size_inv_shoup = Vec::with_capacity(k);
        for op in ctx.ops.iter() {
            let t = op.cuda_tables();
            omegas.extend_from_slice(t.omegas);
            omegas_shoup.extend_from_slice(t.omegas_shoup);
            zetas_inv.extend_from_slice(t.zetas_inv);
            zetas_inv_shoup.extend_from_slice(t.zetas_inv_shoup);
            size_inv.push(t.size_inv);
            size_inv_shoup.push(t.size_inv_shoup);
        }

        let tables = Arc::new(DeviceTables {
            moduli: stream.clone_htod(&ctx.moduli[..]).ok()?,
            barrett_hi: stream.clone_htod(&barrett_hi).ok()?,
            barrett_lo: stream.clone_htod(&barrett_lo).ok()?,
            omegas: stream.clone_htod(&omegas).ok()?,
            omegas_shoup: stream.clone_htod(&omegas_shoup).ok()?,
            zetas_inv: stream.clone_htod(&zetas_inv).ok()?,
            zetas_inv_shoup: stream.clone_htod(&zetas_inv_shoup).ok()?,
            size_inv: stream.clone_htod(&size_inv).ok()?,
            size_inv_shoup: stream.clone_htod(&size_inv_shoup).ok()?,
        });
        cache.insert(key, tables.clone());
        Some(tables)
    }
}

/// Runs the forward NTT of all `k` rows of `coeffs` (a contiguous k×n
/// matrix) on the GPU. Returns false (leaving `coeffs` untouched) if the
/// GPU is unavailable, the operation is too small to win, or any CUDA call
/// fails — the caller then runs the CPU path.
pub(crate) fn ntt_forward(ctx: &Context, coeffs: &mut [u64]) -> bool {
    ntt(ctx, coeffs, true, false)
}

/// Backward (inverse) NTT counterpart of [`ntt_forward`].
pub(crate) fn ntt_backward(ctx: &Context, coeffs: &mut [u64]) -> bool {
    ntt(ctx, coeffs, false, false)
}

/// Like [`ntt_forward`]/[`ntt_backward`] but ignores the size heuristic;
/// used by the differential tests to force the GPU path.
#[cfg(test)]
pub(crate) fn ntt_force_gpu(ctx: &Context, coeffs: &mut [u64], forward: bool) -> bool {
    ntt(ctx, coeffs, forward, true)
}

fn ntt(ctx: &Context, coeffs: &mut [u64], forward: bool, force: bool) -> bool {
    let k = ctx.moduli.len();
    let n = ctx.degree;
    if coeffs.len() != k * n || (!force && k * n < MIN_NTT_ELEMS) {
        return false;
    }
    let Some(b) = backend() else { return false };
    let Some(stream) = stream(b) else {
        return false;
    };
    let Some(tables) = b.tables(ctx, &stream) else {
        return false;
    };

    let run = || -> Result<Vec<u64>, cudarc::driver::DriverError> {
        let mut a = stream.clone_htod(&*coeffs)?;
        if forward {
            let mut l = n >> 1;
            while l > 0 {
                ffi::ntt_fwd_stage(
                    &stream,
                    &b.kernels.ntt_fwd_stage,
                    &mut a,
                    &tables.omegas,
                    &tables.omegas_shoup,
                    &tables.moduli,
                    n as u32,
                    k as u32,
                    l as u32,
                    (l == 1) as i32,
                )?;
                l >>= 1;
            }
        } else {
            let mut l = 1;
            while l < n {
                ffi::ntt_inv_stage(
                    &stream,
                    &b.kernels.ntt_inv_stage,
                    &mut a,
                    &tables.zetas_inv,
                    &tables.zetas_inv_shoup,
                    &tables.moduli,
                    n as u32,
                    k as u32,
                    l as u32,
                )?;
                l <<= 1;
            }
            ffi::ntt_inv_final(
                &stream,
                &b.kernels.ntt_inv_final,
                &mut a,
                &tables.size_inv,
                &tables.size_inv_shoup,
                &tables.moduli,
                n as u32,
                k as u32,
            )?;
        }
        stream.clone_dtoh(&a)
    };

    match run() {
        Ok(result) if result.len() == coeffs.len() => {
            coeffs.copy_from_slice(&result);
            true
        }
        _ => false,
    }
}

/// Element-wise operation selector for [`ew_force_gpu`].
#[derive(Clone, Copy)]
#[allow(
    dead_code,
    reason = "exercised by the differential tests; device-resident ops use it in phase 3"
)]
pub(crate) enum EwOp {
    Add,
    Sub,
    Neg,
    Mul,
    MulShoup,
}

/// Runs one element-wise operation on the GPU over the k×n matrix `a`
/// (`a op= b`), for the differential tests. Returns false on any failure,
/// leaving `a` untouched.
#[allow(
    dead_code,
    reason = "exercised by the differential tests; device-resident ops use it in phase 3"
)]
pub(crate) fn ew_force_gpu(
    ctx: &Context,
    op: EwOp,
    a: &mut [u64],
    b: Option<&[u64]>,
    b_shoup: Option<&[u64]>,
) -> bool {
    let k = ctx.moduli.len();
    let n = ctx.degree;
    if a.len() != k * n {
        return false;
    }
    let Some(back) = backend() else { return false };
    let Some(stream) = stream(back) else {
        return false;
    };
    let Some(tables) = back.tables(ctx, &stream) else {
        return false;
    };

    let run = || -> Result<Vec<u64>, cudarc::driver::DriverError> {
        let mut a_dev = stream.clone_htod(&*a)?;
        let b_dev = match b {
            Some(b) => Some(stream.clone_htod(b)?),
            None => None,
        };
        let bs_dev = match b_shoup {
            Some(bs) => Some(stream.clone_htod(bs)?),
            None => None,
        };
        let (n, k) = (n as u32, k as u32);
        match (op, &b_dev, &bs_dev) {
            (EwOp::Add, Some(b_dev), _) => ffi::ew_binary(
                &stream,
                &back.kernels.ew_add,
                &mut a_dev,
                b_dev,
                &tables.moduli,
                n,
                k,
            )?,
            (EwOp::Sub, Some(b_dev), _) => ffi::ew_binary(
                &stream,
                &back.kernels.ew_sub,
                &mut a_dev,
                b_dev,
                &tables.moduli,
                n,
                k,
            )?,
            (EwOp::Neg, _, _) => ffi::ew_neg(
                &stream,
                &back.kernels.ew_neg,
                &mut a_dev,
                &tables.moduli,
                n,
                k,
            )?,
            (EwOp::Mul, Some(b_dev), _) => ffi::ew_mul(
                &stream,
                &back.kernels.ew_mul,
                &mut a_dev,
                b_dev,
                &tables.moduli,
                &tables.barrett_hi,
                &tables.barrett_lo,
                n,
                k,
            )?,
            (EwOp::MulShoup, Some(b_dev), Some(bs_dev)) => ffi::ew_mul_shoup(
                &stream,
                &back.kernels.ew_mul_shoup,
                &mut a_dev,
                b_dev,
                bs_dev,
                &tables.moduli,
                n,
                k,
            )?,
            (EwOp::Add | EwOp::Sub | EwOp::Mul | EwOp::MulShoup, _, _) => {
                return Err(cudarc::driver::DriverError(
                    cudarc::driver::sys::CUresult::CUDA_ERROR_INVALID_VALUE,
                ));
            }
        }
        stream.clone_dtoh(&a_dev)
    };

    match run() {
        Ok(result) if result.len() == a.len() => {
            a.copy_from_slice(&result);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
