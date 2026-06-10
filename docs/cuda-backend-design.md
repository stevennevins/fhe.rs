# CUDA backend design for fhe.rs

Status: implemented behind the `cuda` cargo feature. No public API changes.

## Goals and non-goals

Accelerate the polynomial-arithmetic hot paths of `fhe-math` (NTT/INTT,
element-wise modular arithmetic, RNS basis extension/scaling, key-switching
inner products) so that BFV ciphertext operations in the `fhe` crate get
end-to-end speedups. Encryption/decryption sampling, serialization, and key
generation stay on the CPU.

Hard constraints honored by this design:

- **C1** Zero public API changes: all GPU code is internal to `fhe-math` (and
  a thin layer in `fhe`); dispatch happens inside existing methods.
- **C2** CPU path untouched by default: everything is behind a `cuda` cargo
  feature; without it, not a single line of the crate changes.
- **C3** Bit-exact results: GPU kernels re-implement the *same* algorithms
  with the *same* precomputed tables as the CPU code (see "Bit-exactness").
- **C4** Graceful degradation: feature on + no usable GPU ⇒ silent CPU
  fallback (documented and tested).
- **C5** `unsafe` confined to one FFI boundary module.
- **C6** MIT-compatible dependencies only.

## CUDA crate choice: `cudarc`

We use [`cudarc`](https://crates.io/crates/cudarc) (MIT OR Apache-2.0) with
`default-features = false, features = ["std", "driver", "nvrtc",
"fallback-dynamic-loading"]`.

Rationale:

- **No build-time CUDA requirement.** `cudarc` with `fallback-dynamic-loading`
  loads `libcuda.so` / `libnvrtc.so` at *runtime* with `dlopen`. A machine
  without CUDA can still `cargo build --features cuda`; the library detects
  the missing driver at runtime and falls back to CPU. This is exactly the C4
  story and also makes the CI compile-only job trivial (no toolkit container
  needed to *link*).
- **No `nvcc` requirement.** Kernels are written as CUDA C source embedded in
  the crate (`include_str!`) and compiled once at first use by NVRTC for the
  *actual* device's compute capability. No PTX shipping or `build.rs` steps.
- **Safe wrappers.** Device memory (`CudaSlice<u64>`), streams, and module
  loading are safe RAII types; the remaining `unsafe` (kernel launches) is
  isolated in `fhe-math/src/cuda/ffi.rs`.
- Alternative considered: `cust` (Rust-CUDA project). Rejected: requires
  PTX produced ahead of time (or nvcc at build time), less actively
  maintained, and its device-memory API is less ergonomic for our
  pool-of-`u64`-buffers usage.

## Where the backend hooks in (no API change)

`fhe-math` gains a private module `fhe_math::cuda` (feature-gated). A global
lazily-initialized singleton holds the device state:

```text
static CUDA: OnceLock<Option<CudaBackend>>   // None => no usable device
```

`CudaBackend` owns the `cudarc` context, compiled module, stream(s), a device
buffer pool, and per-`Context` cached tables (twiddles, moduli constants).

Dispatch is internal and size-aware. The existing entry points consult
`cuda::backend()` and a granularity heuristic, then either run the existing
CPU code (unchanged) or call the GPU routine:

| Entry point (existing, unchanged signature)        | GPU routine                |
|----------------------------------------------------|----------------------------|
| `Poly::into_ntt` / `into_power_basis` (rq/mod.rs)  | batched NTT/INTT over all k RNS rows (per-stage kernels + one fused shared-memory kernel for the last 9 stages) |
| `Scaler::scale` (rq/scaler.rs)                     | fused backward NTT → RNS basis extension/scaling kernel → forward NTT, device-resident |
| `KeySwitchingKey::key_switch{,_assign}` (fhe crate) | fused broadcast → lazy NTT → Shoup multiply-accumulate loop with device-cached key material (covers relinearization and rotations) |

`Multiplicator::multiply` is therefore GPU-accelerated end to end through
its building blocks: 7 `Scaler::scale` calls, the NTT conversions, and the
relinearization key switch.

Element-wise `Add`/`Sub` of ciphertexts stays on the CPU **by design**: it is
O(k·n) data for O(k·n) work and is strictly transfer-bound (see PCIe analysis).

## The PCIe transfer problem (granularity analysis)

A single forward NTT at n = 2^14 takes ~100–300 µs on a modern CPU core. The
same polynomial (one RNS row) is 128 KiB; round-tripping it over PCIe 4.0 x16
(~25 GiB/s effective) costs ~10 µs of pure transfer *plus* ~5–10 µs of launch
and synchronization latency per op. Naively offloading a single NTT therefore
wins only ~2–3× and offloading a single ciphertext *addition* (pure memcpy
arithmetic) always **loses**.

Consequences baked into the design:

1. **Minimum offload granularity is "all k RNS rows of a polynomial at
   once"** (one launch transforms a k×n matrix), and only above a size
   threshold (`n·k ≥ CUDA_MIN_ELEMS`, tuned by benchmark; small parameters
   such as n = 2^12 with 1–2 moduli always run on CPU).
2. **Ciphertext multiplication is offloaded as one fused operation**:
   upload `c1`, `c2` once, then perform extension to the doubled RNS basis,
   forward NTTs, tensor products, inverse NTTs, scaling back, and (when
   enabled) the relinearization inner product entirely device-resident, and
   download only the final two output polynomials. The arithmetic is
   O(k²·n·log n) for O(k·n) bytes moved, which is where a GPU wins big.
3. **Key material is cached on the device.** Relinearization/Galois key
   polynomials are uploaded once (keyed by the key's stable address /
   generation counter) and reused across every multiply/rotation.
4. **Ciphertext add/sub never goes to the GPU** unless the operands are
   already device-resident (they are not, in the current host-resident
   `Poly` model), because transfer alone exceeds CPU compute time.

## Memory management

- **Device buffer pool.** A thread-local free-list keyed by buffer length
  (`HashMap<usize, Vec<CudaSlice<u64>>>`); buffers stay associated with the
  thread's stream. Polynomial sizes are few and highly repetitive, so
  pooling eliminates `cuMemAlloc` latency from the hot path.
- **Table cache.** Per (moduli list, degree) — value-keyed, so context
  recreation reuses uploads — the backend uploads once: moduli, Barrett and
  Shoup constants, concatenated forward/inverse twiddle tables for every
  RNS modulus. Scaler constants (gamma/omega/theta tables) and
  key-switching keys are cached the same way, the latter keyed by the key
  polynomials' addresses plus content samples.
- **Transfers** use ordinary pageable copies (`memcpy_htod`/`memcpy_dtoh`),
  with the standalone NTT downloading directly into the caller's buffer.
  Pinned (write-combined) staging was measured in Phase 4 and was *slower*
  on this hardware (WC reads); pageable bandwidth is ~10–13 GB/s.
- **Out-of-memory behavior:** every GPU path has a CPU equivalent, so
  allocation failures (like any other CUDA error) cause a silent fall back
  to the CPU implementation; they never abort and never corrupt data. The
  per-thread buffer pool and key/table caches are bounded by the number of
  distinct (moduli, degree) contexts and keys used by the application.

## Streams and concurrency

- One global CUDA context; **one stream per host thread** (`thread_local`),
  so concurrent ciphertext operations from multiple threads don't serialize
  against each other's transfers.
- Within one fused op, kernels are enqueued back-to-back on the thread's
  stream with a single `stream.synchronize()` before the final download.
- The buffer pool and NVRTC compilation cache are `Mutex`-protected; kernel
  launches themselves are per-stream and lock-free.
- A multi-threaded stress test (Phase 5) exercises concurrent multiplies.

## Bit-exactness strategy (C3)

The GPU kernels do not invent their own arithmetic:

- The NTT kernels use the **host-precomputed** `omegas`/`omegas_shoup` /
  `zetas_inv`/`zetas_inv_shoup` tables from the existing `NttOperator`
  (native backend), uploaded verbatim, and implement the same
  Cooley–Tukey / Gentleman–Sande butterflies with the same lazy Shoup
  reduction (`lazy_mul_shoup`, `reduce1`) — 128-bit high products via
  `__umul64hi`. Outputs are reduced at the same points as the CPU code, so
  every intermediate and final coefficient is identical.
- Element-wise kernels mirror `zq::Modulus::{add, sub, mul, mul_shoup}`
  (Barrett/Shoup) exactly.
- RNS scaling kernels mirror `rns::scaler::RnsScaler` arithmetic exactly,
  using the same precomputed theta/garner constants uploaded from the host.
- Differential tests (≥ 50) assert `==` (never approximate) between CPU and
  GPU outputs across all supported degrees, moduli counts, edge cases, and
  1000+ random NTT∘INTT round trips.

Note: when the `tfhe-ntt` feature is also enabled, the CUDA backend is
compiled out entirely (bit-exactness is defined against the native
`NttOperator` tables); `cuda` + `tfhe-ntt` builds behave exactly like
`tfhe-ntt` alone.

One C1 nuance: with the `cuda` feature enabled, `fhe-math` exposes a single
`#[doc(hidden)]` internal entry point (`__cuda_key_switch`) consumed by the
`fhe` crate's key-switching code. The default-features API surface is
unchanged, and the hidden item is additive (no existing downstream code is
affected).

## Build story

| Scenario | Works? | Requirements |
|---|---|---|
| `cargo build` (no features) | yes | none — identical to `main` |
| `cargo build --features cuda` | yes | none at build time (no nvcc, no toolkit): kernels are CUDA C strings, NVRTC compiles them at runtime |
| run with `cuda` feature, GPU present | GPU path | NVIDIA driver (`libcuda.so`) + `libnvrtc.so` (CUDA toolkit ≥ 12) |
| run with `cuda` feature, no GPU/driver | CPU fallback | none |

Supported compute capabilities: 7.0+ (anything NVRTC for CUDA 12/13 emits;
tested on sm_120 / Blackwell). The kernel source uses no architecture
specific intrinsics beyond `__umul64hi` (available everywhere).

Environment switch: setting `FHE_CUDA_DISABLE=1` forces the CPU path (used in
tests and as an operational escape hatch).

## Failure modes

- No device / driver missing ⇒ `CudaBackend::new()` returns `None` once;
  all ops use CPU. (C4; tested by setting `FHE_CUDA_DISABLE=1`.)
- NVRTC compile error ⇒ treated as "no backend" with a `log::warn!`; CPU
  fallback. (Should not happen on supported toolkits; covered in CI compile
  job by compiling the kernel source with NVRTC where available.)
- Device OOM ⇒ error propagated (no abort), op retried on CPU when a CPU
  path exists.

## Testing & validation plan

- Phase 2: differential kernel tests (`--features cuda`), ≥ 50 tests.
- Phase 3: full `fhe` test suite + examples under both modes, identical
  outputs.
- Phase 4: criterion grid (`crates/fhe/benches/hotpaths.rs`) compared against
  the saved `cpu-main` baseline; acceptance criteria in the project goal.
- Phase 5: clippy/fmt clean, README docs, failure-mode and thread-stress
  tests.
