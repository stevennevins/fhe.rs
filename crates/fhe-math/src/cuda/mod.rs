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

use crate::rq::{Context, Ntt, NttShoup, Poly, PowerBasis};
use ndarray::{Array2, ArrayView2};

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
    supports_opt: CudaSlice<u64>,
    leading_zeros: CudaSlice<u64>,
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
    rns_scale: CudaFunction,
    broadcast_lazy_reduce: CudaFunction,
    ew_mul_shoup_acc: CudaFunction,
    ntt_fwd_fused_tail: CudaFunction,
    ntt_inv_fused_head: CudaFunction,
}

/// Cache of device tables, keyed by (moduli, degree).
type TableCache = HashMap<(Box<[u64]>, usize), Arc<DeviceTables>>;

/// Device-resident tables of one `rns::scaler::RnsScaler`.
struct ScalerTables {
    gamma: CudaSlice<u64>,
    gamma_shoup: CudaSlice<u64>,
    omega: CudaSlice<u64>,
    omega_shoup: CudaSlice<u64>,
    theta_omega_lo: CudaSlice<u64>,
    theta_omega_hi: CudaSlice<u64>,
    theta_omega_sign: CudaSlice<u64>,
    theta_garner_lo: CudaSlice<u64>,
    theta_garner_hi: CudaSlice<u64>,
}

/// Cache of scaler tables, keyed by a fingerprint of the scaler constants.
type ScalerCache = HashMap<Box<[u64]>, Arc<ScalerTables>>;

/// Device-resident key-switching key material: the c0/c1 polynomials (and
/// their Shoup representations) of one `KeySwitchingKey`, flattened to
/// k_cipher consecutive (k_ksk x n) matrices. Owned by the key's
/// [`crate::CudaKskCache`] handle, so its lifetime is tied to the key.
pub(crate) struct KskTables {
    c0: CudaSlice<u64>,
    c0_shoup: CudaSlice<u64>,
    c1: CudaSlice<u64>,
    c1_shoup: CudaSlice<u64>,
}

/// Global CUDA state: device context, compiled module, table cache.
pub(crate) struct CudaBackend {
    ctx: Arc<CudaContext>,
    kernels: Kernels,
    tables: Mutex<TableCache>,
    scaler_tables: Mutex<ScalerCache>,
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

type DriverResult<T> = Result<T, cudarc::driver::DriverError>;

thread_local! {
    /// Per-thread device buffer pool (buffers belong to the thread's
    /// stream); keyed by length. Eliminates cuMemAlloc from the hot path.
    static POOL: std::cell::RefCell<HashMap<usize, Vec<CudaSlice<u64>>>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Takes a buffer of exactly `len` elements from the pool (contents
/// undefined) or allocates one.
fn acquire(stream: &Arc<CudaStream>, len: usize) -> DriverResult<CudaSlice<u64>> {
    if let Some(buf) = POOL.with(|p| p.borrow_mut().get_mut(&len).and_then(Vec::pop)) {
        return Ok(buf);
    }
    stream.alloc_zeros::<u64>(len)
}

/// Returns a buffer to this thread's pool.
fn release(buf: CudaSlice<u64>) {
    POOL.with(|p| p.borrow_mut().entry(buf.len()).or_default().push(buf));
}

/// Uploads a host slice into a pooled device buffer.
fn upload(stream: &Arc<CudaStream>, src: &[u64]) -> DriverResult<CudaSlice<u64>> {
    let mut buf = acquire(stream, src.len())?;
    stream.memcpy_htod(src, &mut buf)?;
    Ok(buf)
}

/// Device-side forward NTT of k rows (per-stage kernels for large strides,
/// one fused shared-memory kernel for the last 9 stages). `reduce_out`
/// false gives the lazy variant (coefficients < 4p), mirroring
/// `forward_vt_lazy`.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the kernel parameter list"
)]
fn dev_ntt_forward(
    b: &CudaBackend,
    stream: &Arc<CudaStream>,
    a: &mut CudaSlice<u64>,
    t: &DeviceTables,
    n: usize,
    k: usize,
    tab_off: usize,
    reduce_out: bool,
) -> DriverResult<()> {
    let mut l = n >> 1;
    while l > 0 {
        if l <= 256 && n >= 512 {
            return ffi::ntt_fwd_fused_tail(
                stream,
                &b.kernels.ntt_fwd_fused_tail,
                a,
                &t.omegas,
                &t.omegas_shoup,
                &t.moduli,
                n as u32,
                k as u32,
                tab_off as u32,
                reduce_out as i32,
            );
        }
        ffi::ntt_fwd_stage(
            stream,
            &b.kernels.ntt_fwd_stage,
            a,
            &t.omegas,
            &t.omegas_shoup,
            &t.moduli,
            n as u32,
            k as u32,
            tab_off as u32,
            l as u32,
            (l == 1 && reduce_out) as i32,
        )?;
        l >>= 1;
    }
    Ok(())
}

/// Device-side backward NTT of k rows, including the final n^-1 scaling.
fn dev_ntt_backward(
    b: &CudaBackend,
    stream: &Arc<CudaStream>,
    a: &mut CudaSlice<u64>,
    t: &DeviceTables,
    n: usize,
    k: usize,
    tab_off: usize,
) -> DriverResult<()> {
    let mut l = 1;
    if n >= 512 {
        ffi::ntt_inv_fused_head(
            stream,
            &b.kernels.ntt_inv_fused_head,
            a,
            &t.zetas_inv,
            &t.zetas_inv_shoup,
            &t.moduli,
            n as u32,
            k as u32,
            tab_off as u32,
        )?;
        l = 512;
    }
    while l < n {
        ffi::ntt_inv_stage(
            stream,
            &b.kernels.ntt_inv_stage,
            a,
            &t.zetas_inv,
            &t.zetas_inv_shoup,
            &t.moduli,
            n as u32,
            k as u32,
            tab_off as u32,
            l as u32,
        )?;
        l <<= 1;
    }
    ffi::ntt_inv_final(
        stream,
        &b.kernels.ntt_inv_final,
        a,
        &t.size_inv,
        &t.size_inv_shoup,
        &t.moduli,
        n as u32,
        k as u32,
        tab_off as u32,
    )
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
        let ptx = match nvrtc::compile_ptx_with_opts(include_str!("kernels.cu"), opts) {
            Ok(ptx) => ptx,
            Err(e) => {
                log::warn!(
                    "CUDA backend disabled, falling back to CPU: NVRTC compilation failed: {e}"
                );
                return None;
            }
        };
        let module = match ctx.load_module(ptx) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("CUDA backend disabled, falling back to CPU: module load failed: {e}");
                return None;
            }
        };
        let kernels = Kernels {
            ntt_fwd_stage: module.load_function("ntt_fwd_stage").ok()?,
            ntt_inv_stage: module.load_function("ntt_inv_stage").ok()?,
            ntt_inv_final: module.load_function("ntt_inv_final").ok()?,
            ew_add: module.load_function("ew_add").ok()?,
            ew_sub: module.load_function("ew_sub").ok()?,
            ew_neg: module.load_function("ew_neg").ok()?,
            ew_mul: module.load_function("ew_mul").ok()?,
            ew_mul_shoup: module.load_function("ew_mul_shoup").ok()?,
            rns_scale: module.load_function("rns_scale").ok()?,
            broadcast_lazy_reduce: module.load_function("broadcast_lazy_reduce").ok()?,
            ew_mul_shoup_acc: module.load_function("ew_mul_shoup_acc").ok()?,
            ntt_fwd_fused_tail: module.load_function("ntt_fwd_fused_tail").ok()?,
            ntt_inv_fused_head: module.load_function("ntt_inv_fused_head").ok()?,
        };
        Some(Self {
            ctx,
            kernels,
            tables: Mutex::new(HashMap::new()),
            scaler_tables: Mutex::new(HashMap::new()),
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
            supports_opt: stream
                .clone_htod(
                    &ctx.moduli
                        .iter()
                        .map(|p| crate::zq::primes::supports_opt(*p) as u64)
                        .collect::<Vec<_>>(),
                )
                .ok()?,
            leading_zeros: stream
                .clone_htod(
                    &ctx.moduli
                        .iter()
                        .map(|p| p.leading_zeros() as u64)
                        .collect::<Vec<_>>(),
                )
                .ok()?,
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

    let run = || -> DriverResult<CudaSlice<u64>> {
        let mut a = upload(&stream, coeffs)?;
        if forward {
            dev_ntt_forward(b, &stream, &mut a, &tables, n, k, 0, true)?;
        } else {
            dev_ntt_backward(b, &stream, &mut a, &tables, n, k, 0)?;
        }
        Ok(a)
    };

    match run() {
        Ok(a) => {
            // Download straight into the caller's buffer (the extra staging
            // copy costs more than the whole kernel pipeline). A failed
            // download may leave the buffer partially written, in which case
            // falling back to the CPU would silently corrupt the result, so
            // it is retried; both attempts only fail when the CUDA context
            // itself is broken (device loss), where no recovery exists.
            let ok = stream
                .memcpy_dtoh(&a, &mut *coeffs)
                .or_else(|_| stream.memcpy_dtoh(&a, &mut *coeffs))
                .and_then(|()| stream.synchronize())
                .is_ok();
            release(a);
            ok
        }
        _ => false,
    }
}

impl CudaBackend {
    /// Returns (uploading on first use) the device tables of an RNS scaler.
    fn scaler_tables(
        &self,
        s: &crate::rns::RnsScaler,
        stream: &Arc<CudaStream>,
    ) -> Option<Arc<ScalerTables>> {
        // Fingerprint: the constants below uniquely determine the scaler.
        let mut key = Vec::with_capacity(s.gamma.len() + s.theta_garner_lo.len() + 3);
        key.extend_from_slice(&s.gamma);
        key.extend_from_slice(&s.theta_garner_lo);
        key.push(s.theta_gamma_lo);
        key.push(s.theta_gamma_hi);
        key.push(s.omega.len() as u64);
        let key = key.into_boxed_slice();

        let mut cache = self.scaler_tables.lock().ok()?;
        if let Some(t) = cache.get(&key) {
            return Some(t.clone());
        }

        let omega: Vec<u64> = s.omega.iter().flat_map(|r| r.iter().copied()).collect();
        let omega_shoup: Vec<u64> = s
            .omega_shoup
            .iter()
            .flat_map(|r| r.iter().copied())
            .collect();
        let theta_omega_sign: Vec<u64> = s.theta_omega_sign.iter().map(|b| *b as u64).collect();

        let tables = Arc::new(ScalerTables {
            gamma: stream.clone_htod(&s.gamma[..]).ok()?,
            gamma_shoup: stream.clone_htod(&s.gamma_shoup[..]).ok()?,
            omega: stream.clone_htod(&omega).ok()?,
            omega_shoup: stream.clone_htod(&omega_shoup).ok()?,
            theta_omega_lo: stream.clone_htod(&s.theta_omega_lo[..]).ok()?,
            theta_omega_hi: stream.clone_htod(&s.theta_omega_hi[..]).ok()?,
            theta_omega_sign: stream.clone_htod(&theta_omega_sign).ok()?,
            theta_garner_lo: stream.clone_htod(&s.theta_garner_lo[..]).ok()?,
            theta_garner_hi: stream.clone_htod(&s.theta_garner_hi[..]).ok()?,
        });
        cache.insert(key, tables.clone());
        Some(tables)
    }
}

/// Runs a whole `Scaler::scale` on the GPU: backward NTT of the source rows
/// (when the polynomial is in NTT representation), RNS scaling of every
/// coefficient, and forward NTT of the freshly scaled rows — all
/// device-resident. Rows shared between the two contexts (`common`) are
/// copied through on the host exactly like the CPU path.
///
/// Returns None (and leaves no side effects) if the GPU is unavailable, the
/// operation is too small, or any CUDA call fails; the caller then runs the
/// CPU path.
pub(crate) fn scale_coeffs(
    scaler: &crate::rq::scaler::Scaler,
    coeffs: &ArrayView2<'_, u64>,
    needs_transform: bool,
) -> Option<Array2<u64>> {
    let n = scaler.from.degree;
    let k_from = scaler.from.q.len();
    let k_to = scaler.to.q.len();
    let common = scaler.number_common_moduli;
    let k_write = k_to - common;
    if k_write == 0 || n * k_to < MIN_NTT_ELEMS {
        return None;
    }
    let in_slice = coeffs.as_slice()?;
    if in_slice.len() != k_from * n {
        return None;
    }

    let b = backend()?;
    let stream = stream(b)?;
    let from_tables = b.tables(&scaler.from, &stream)?;
    let to_tables = b.tables(&scaler.to, &stream)?;
    let s_tables = b.scaler_tables(&scaler.scaler, &stream)?;

    let run = || -> DriverResult<(Vec<u64>, CudaSlice<u64>, CudaSlice<u64>)> {
        let mut work = upload(&stream, in_slice)?;
        if needs_transform {
            // Backward NTT of the source (all k_from rows).
            dev_ntt_backward(b, &stream, &mut work, &from_tables, n, k_from, 0)?;
        }

        // Fully overwritten by the rns_scale kernel below.
        let mut out = acquire(&stream, k_write * n)?;
        ffi::rns_scale(
            &stream,
            &b.kernels.rns_scale,
            ffi::RnsScaleArgs {
                input: &work,
                out: &mut out,
                to_moduli: &to_tables.moduli,
                to_barrett_hi: &to_tables.barrett_hi,
                to_barrett_lo: &to_tables.barrett_lo,
                gamma: &s_tables.gamma,
                gamma_shoup: &s_tables.gamma_shoup,
                omega: &s_tables.omega,
                omega_shoup: &s_tables.omega_shoup,
                theta_omega_lo: &s_tables.theta_omega_lo,
                theta_omega_hi: &s_tables.theta_omega_hi,
                theta_omega_sign: &s_tables.theta_omega_sign,
                theta_garner_lo: &s_tables.theta_garner_lo,
                theta_garner_hi: &s_tables.theta_garner_hi,
                theta_gamma_lo: scaler.scaler.theta_gamma_lo,
                theta_gamma_hi: scaler.scaler.theta_gamma_hi,
                theta_gamma_sign: scaler.scaler.theta_gamma_sign as u32,
                theta_garner_shift: scaler.scaler.theta_garner_shift as u32,
                is_one: scaler.scaler.scaling_factor.is_one as u32,
                n: n as u32,
                k_from: k_from as u32,
                k_write: k_write as u32,
                start: common as u32,
            },
        )?;

        if needs_transform {
            // Forward NTT of the scaled rows, with `to`-context tables
            // starting at row `common`.
            dev_ntt_forward(b, &stream, &mut out, &to_tables, n, k_write, common, true)?;
        }

        Ok((stream.clone_dtoh(&out)?, work, out))
    };

    match run() {
        Ok((scaled, work, out)) if scaled.len() == k_write * n => {
            release(work);
            release(out);
            let mut data = Vec::with_capacity(k_to * n);
            data.extend_from_slice(in_slice.get(..common * n)?);
            data.extend_from_slice(&scaled);
            Array2::from_shape_vec((k_to, n), data).ok()
        }
        _ => None,
    }
}

/// Uploads the device-resident key material of one key-switching key.
fn upload_ksk_tables(
    c0s: &[Poly<NttShoup>],
    c1s: &[Poly<NttShoup>],
    stream: &Arc<CudaStream>,
) -> Option<Arc<KskTables>> {
    let mut c0 = vec![];
    let mut c0_shoup = vec![];
    let mut c1 = vec![];
    let mut c1_shoup = vec![];
    for p in c0s {
        c0.extend_from_slice(p.coefficients().as_slice()?);
        c0_shoup.extend_from_slice(p.coefficients_shoup()?.as_slice()?);
    }
    for p in c1s {
        c1.extend_from_slice(p.coefficients().as_slice()?);
        c1_shoup.extend_from_slice(p.coefficients_shoup()?.as_slice()?);
    }

    Some(Arc::new(KskTables {
        c0: stream.clone_htod(&c0).ok()?,
        c0_shoup: stream.clone_htod(&c0_shoup).ok()?,
        c1: stream.clone_htod(&c1).ok()?,
        c1_shoup: stream.clone_htod(&c1_shoup).ok()?,
    }))
}

/// Fused GPU key switch: for every row i of `p`, broadcast it to the ksk
/// context with lazy reduction, run a lazy forward NTT, and accumulate
/// c0 += ntt(p_i) * c0s[i], c1 += ntt(p_i) * c1s[i] — entirely
/// device-resident, with the key material cached on the GPU.
///
/// This mirrors `KeySwitchingKey::key_switch` in the `fhe` crate exactly
/// (same lazy reductions, same Shoup multiplications) and is therefore
/// bit-exact with the CPU path. Returns None if the GPU is unavailable, the
/// operation is too small, or any CUDA call fails.
///
/// `cache` is the key's device-cache handle: the key material is uploaded
/// into it on first use and reused afterwards. The caller must pass the
/// handle owned by the same key as `c0s`/`c1s`.
///
/// Not public API: this is an internal hook consumed by the `fhe` crate
/// when the `cuda` feature is enabled.
#[doc(hidden)]
#[must_use]
pub fn key_switch(
    p: &Poly<PowerBasis>,
    c0s: &[Poly<NttShoup>],
    c1s: &[Poly<NttShoup>],
    ctx_ksk: &Arc<Context>,
    cache: &crate::CudaKskCache,
) -> Option<(Poly<Ntt>, Poly<Ntt>)> {
    let n = ctx_ksk.degree;
    let k_ksk = ctx_ksk.q.len();
    let k_c = p.ctx().q.len();
    if c0s.len() < k_c || c1s.len() < k_c || n * k_ksk < MIN_NTT_ELEMS {
        return None;
    }
    // All key polynomials must live in the ksk context.
    if c0s.iter().chain(c1s.iter()).any(|c| c.ctx() != ctx_ksk) {
        return None;
    }
    let p_slice = p.coefficients();
    let p_slice = p_slice.as_slice()?;

    let b = backend()?;
    let stream = stream(b)?;
    let ksk_tables = b.tables(ctx_ksk, &stream)?;
    // Upload the key material into the key's own handle on first use; a
    // failed upload is not cached, so it is retried on the next call. (If
    // two threads race, one upload wins and the other is dropped.)
    let keys = match cache.tables.get() {
        Some(t) => t.clone(),
        None => {
            let t = upload_ksk_tables(c0s, c1s, &stream)?;
            cache.tables.get_or_init(|| t).clone()
        }
    };

    #[expect(clippy::type_complexity, reason = "internal buffer plumbing")]
    let run = || -> DriverResult<(Vec<u64>, Vec<u64>, [CudaSlice<u64>; 4])> {
        let p_dev = upload(&stream, p_slice)?;
        // c2 is fully overwritten by broadcast_lazy_reduce each iteration;
        // the accumulators must start at zero.
        let mut c2 = acquire(&stream, k_ksk * n)?;
        let mut acc0 = acquire(&stream, k_ksk * n)?;
        let mut acc1 = acquire(&stream, k_ksk * n)?;
        stream.memset_zeros(&mut acc0)?;
        stream.memset_zeros(&mut acc1)?;

        for i in 0..k_c {
            // c2 = lazy NTT of row i broadcast to all ksk rows.
            let row = p_dev.slice(i * n..(i + 1) * n);
            ffi::broadcast_lazy_reduce(
                &stream,
                &b.kernels.broadcast_lazy_reduce,
                &mut c2,
                &row,
                &ksk_tables.moduli,
                &ksk_tables.barrett_hi,
                &ksk_tables.barrett_lo,
                &ksk_tables.supports_opt,
                &ksk_tables.leading_zeros,
                n as u32,
                k_ksk as u32,
            )?;
            // Lazy forward NTT: no final reduction, like forward_vt_lazy.
            dev_ntt_forward(b, &stream, &mut c2, &ksk_tables, n, k_ksk, 0, false)?;
            let key_range = i * k_ksk * n..(i + 1) * k_ksk * n;
            ffi::ew_mul_shoup_acc(
                &stream,
                &b.kernels.ew_mul_shoup_acc,
                &mut acc0,
                &c2,
                &keys.c0.slice(key_range.clone()),
                &keys.c0_shoup.slice(key_range.clone()),
                &ksk_tables.moduli,
                n as u32,
                k_ksk as u32,
            )?;
            ffi::ew_mul_shoup_acc(
                &stream,
                &b.kernels.ew_mul_shoup_acc,
                &mut acc1,
                &c2,
                &keys.c1.slice(key_range.clone()),
                &keys.c1_shoup.slice(key_range),
                &ksk_tables.moduli,
                n as u32,
                k_ksk as u32,
            )?;
        }
        Ok((
            stream.clone_dtoh(&acc0)?,
            stream.clone_dtoh(&acc1)?,
            [p_dev, c2, acc0, acc1],
        ))
    };

    match run() {
        Ok((v0, v1, buffers)) if v0.len() == k_ksk * n && v1.len() == k_ksk * n => {
            for buf in buffers {
                release(buf);
            }
            let a0 = Array2::from_shape_vec((k_ksk, n), v0).ok()?;
            let a1 = Array2::from_shape_vec((k_ksk, n), v1).ok()?;
            Some((
                Poly::<Ntt>::from_gpu_coefficients(ctx_ksk, a0),
                Poly::<Ntt>::from_gpu_coefficients(ctx_ksk, a1),
            ))
        }
        _ => None,
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
