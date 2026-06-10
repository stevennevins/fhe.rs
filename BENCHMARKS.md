# Benchmarks: CPU baseline vs CUDA backend

## Hardware / software

| Component | Value |
|---|---|
| CPU | ARM Neoverse-N1, 128 cores @ 3.0 GHz (single-threaded library; benches use 1 core) |
| RAM | 62 GiB |
| GPU | NVIDIA RTX PRO 6000 Blackwell Max-Q Workstation Edition, 96 GiB, compute capability 12.0 |
| NVIDIA driver | 595.58.03 |
| CUDA toolkit | 13.2 (`libnvrtc` used at runtime; no `nvcc` required) |
| Rust | 1.96.0 stable |
| OS | Ubuntu 24.04 (Linux 6.8), aarch64 |

## Reproduction

```bash
# CPU baseline (saved as criterion baseline "cpu-main"):
cargo bench --bench hotpaths -- --save-baseline cpu-main

# CUDA run, compared against the saved baseline:
cargo bench --bench hotpaths --features cuda -- --baseline cpu-main

# Correctness:
cargo test --workspace                  # default features (CPU)
cargo test --workspace --features fhe/cuda,fhe-math/cuda   # differential GPU tests

# Public API unchanged vs main (default features):
cargo semver-checks --workspace --baseline-rev main
```

Gate G5 was re-verified from a clean clone of this branch with the commands
above: 171 default-feature tests and 231 cuda-feature tests pass, and
`cargo semver-checks` reports "no semver update required" for all four
crates. (One pre-existing issue unrelated to this work: the `rgsw` example
panics identically on `main`, on this branch in CPU mode, and in CUDA mode.)

The benchmark grid lives in `crates/fhe/benches/hotpaths.rs`: forward/inverse
NTT (all RNS rows of one polynomial), batched forward NTT (64 polynomials),
ciphertext add, ciphertext multiply + relinearization (`Multiplicator`), and
column rotation, for n ∈ {2^12, 2^13, 2^14, 2^15} and k ∈ {2, 6, 15} 62-bit
RNS moduli.

## Phase 0 — CPU baseline (`cpu-main`, commit at gate G0)

`cargo test --workspace --release`: 171 passed, 0 failed.

Criterion medians, single thread:

### NTT (per polynomial = k rows of size n)

| n | k | forward | backward | forward ×64 batch |
|---|---|---|---|---|
| 4096 | 2 | 171.6 µs | 193.7 µs | — |
| 4096 | 6 | 519.0 µs | 585.9 µs | 33.7 ms |
| 4096 | 15 | 1.315 ms | 1.478 ms | — |
| 8192 | 2 | 371.2 µs | 416.4 µs | — |
| 8192 | 6 | 1.134 ms | 1.266 ms | 73.0 ms |
| 8192 | 15 | 2.850 ms | 3.183 ms | — |
| 16384 | 2 | 806.8 µs | 894.7 µs | — |
| 16384 | 6 | 2.437 ms | 2.709 ms | 156.6 ms |
| 16384 | 15 | 6.131 ms | 6.813 ms | — |
| 32768 | 2 | 1.730 ms | 1.915 ms | — |
| 32768 | 6 | 5.227 ms | 5.780 ms | 333.9 ms |
| 32768 | 15 | 13.11 ms | 14.47 ms | — |

### BFV ciphertext operations

| n | k | add_ct | mul_relin | rotate_columns |
|---|---|---|---|---|
| 4096 | 2 | 16.1 µs | 9.249 ms | 785.9 µs |
| 4096 | 6 | 56.6 µs | 31.40 ms | 5.432 ms |
| 4096 | 15 | 159.7 µs | 113.1 ms | 31.26 ms |
| 8192 | 2 | 35.2 µs | 19.32 ms | 1.693 ms |
| 8192 | 6 | 127.6 µs | 65.00 ms | 11.65 ms |
| 8192 | 15 | 330.9 µs | 242.4 ms | 66.47 ms |
| 16384 | 2 | 84.5 µs | 40.23 ms | 3.640 ms |
| 16384 | 6 | 272.7 µs | 135.8 ms | 25.15 ms |
| 16384 | 15 | 786.3 µs | 509.5 ms | 145.2 ms |
| 32768 | 2 | 180.8 µs | 83.58 ms | 7.893 ms |
| 32768 | 6 | 595.2 µs | 331.9 ms | 53.51 ms |
| 32768 | 15 | 1.729 ms | 1.154 s | 309.4 ms |

## Phase 4 — CUDA results (gate G4)

Same grid with `--features cuda`, measured against the saved `cpu-main`
baseline on the hardware above. Criterion medians; speedup = CPU baseline /
CUDA time.

### NTT (per polynomial = k rows of size n)

| n | k | forward | speedup | backward | speedup | forward ×64 batch | speedup |
|---|---|---|---|---|---|---|---|
| 4096 | 2 | 44.0 µs | 3.9× | 49.5 µs | 3.9× | — | — |
| 4096 | 6 | 72.2 µs | 7.2× | 77.4 µs | 7.6× | 4.81 ms | 7.0× |
| 4096 | 15 | 152.5 µs | 8.6× | 152.7 µs | 9.7× | — | — |
| 8192 | 2 | 63.6 µs | 5.8× | 67.7 µs | 6.2× | — | — |
| 8192 | 6 | 123.5 µs | 9.2× | 128.1 µs | 9.9× | 8.30 ms | 8.8× |
| 8192 | 15 | 271.0 µs | 10.5× | 280.5 µs | 11.3× | — | — |
| 16384 | 2 | 102.4 µs | 7.9× | 106.4 µs | 8.4× | — | — |
| 16384 | 6 | 228.5 µs | 10.7× | 228.5 µs | 11.9× | **14.96 ms** | **10.5×** |
| 16384 | 15 | 574.4 µs | 10.7× | 533.9 µs | 12.8× | — | — |
| 32768 | 2 | 169.7 µs | 10.2× | 174.3 µs | 11.0× | — | — |
| 32768 | 6 | 423.0 µs | 12.4× | 461.2 µs | 12.5× | **27.53 ms** | **12.1×** |
| 32768 | 15 | 1.025 ms | 12.8× | 1.025 ms | 14.1× | — | — |

### BFV ciphertext operations

| n | k | add_ct | Δ | mul_relin | speedup | rotate_columns | speedup |
|---|---|---|---|---|---|---|---|
| 4096 | 2 | 16.2 µs | ±0 (CPU) | 1.57 ms | 5.9× | 247.8 µs | 3.2× |
| 4096 | 6 | 57.8 µs | ±0 (CPU) | 3.24 ms | 9.7× | 624.0 µs | 8.7× |
| 4096 | 15 | 151.9 µs | ±0 (CPU) | 7.64 ms | 14.8× | 1.446 ms | 21.6× |
| 8192 | 2 | 34.5 µs | ±0 (CPU) | 2.59 ms | 7.5× | 394.4 µs | 4.3× |
| 8192 | 6 | 124.6 µs | ±0 (CPU) | 6.01 ms | 10.8× | 1.016 ms | 11.5× |
| 8192 | 15 | 318.6 µs | ±0 (CPU) | 15.02 ms | 16.1× | 2.490 ms | 26.7× |
| 16384 | 2 | 81.8 µs | ±0 (CPU) | 4.61 ms | 8.7× | 684.5 µs | 5.3× |
| 16384 | 6 | 267.6 µs | ±0 (CPU) | **11.80 ms** | **11.5×** | 1.857 ms | 13.5× |
| 16384 | 15 | 704.3 µs | ±0 (CPU) | 29.13 ms | 17.5× | 5.133 ms | 28.3× |
| 32768 | 2 | 174.6 µs | ±0 (CPU) | 8.85 ms | 9.4× | 1.211 ms | 6.5× |
| 32768 | 6 | 567.7 µs | ±0 (CPU) | **23.27 ms** | **14.3×** | 3.964 ms | 13.5× |
| 32768 | 15 | 1.550 ms | ±0 (CPU) | 85.38 ms | 13.5× | 9.941 ms | 31.1× |

### Acceptance criteria (G4)

| Target | Result |
|---|---|
| mul+relin ≥ 5× at n = 2^14, ≥ 6 moduli | **11.5×** (k=6), 17.5× (k=15) ✓ |
| mul+relin ≥ 10× at n = 2^15 | **14.3×** (k=6), 13.5× (k=15) ✓ |
| Batched NTT (64 polys) ≥ 10× at n ≥ 2^14 | **10.5×** (2^14), **12.1×** (2^15) ✓ |
| Ciphertext add no slower than CPU | unchanged — the dispatcher keeps add on the CPU (transfer-bound: O(k·n) bytes for O(k·n) work) ✓ |
| Small parameters auto-CPU | ops with n·k < 2^13 elements stay on the CPU (`MIN_NTT_ELEMS`, asserted by `cuda::tests::small_params_stay_on_cpu`); above the threshold the GPU already wins (e.g. mul_relin 5.9× at n=2^12, k=2) ✓ |

### Notes

- The dominant cost of a standalone GPU NTT is the PCIe round trip:
  pageable host↔device bandwidth on this (aarch64) platform measures
  ~10–13 GB/s, vs ~40 µs of kernel time for a 2^15 × 15 transform. Pinned
  (write-combined) staging measured *slower* (reads from WC memory) and was
  not adopted. Ciphertext-level operations amortize transfers by fusing the
  whole pipeline (basis extension → tensor products → scaling →
  key-switch) on the device, which is why mul/rotate speedups exceed the
  standalone NTT speedups.
- The GPU idles to P8 between criterion measurements; benchmarks use a 2 s
  warm-up so clocks are at steady state when sampling. (With a 500 ms
  warm-up, large-batch numbers degraded up to 4× from clock ramping.)
- Out-of-device-memory or any other CUDA failure falls back to the CPU
  path (no abort, no error surfaced through the unchanged public API).

## Typed FheGoldilocks SIMD operations

Wall-clock medians for the typed `fhe::typed::FheGoldilocks` API
(plaintext modulus t = 2^64 − 2^32 + 1, the Plonky2/Plonky3 field) at the
curated 128-bit parameters: degree 16384, six moduli (291-bit q). Every
operation processes all 16384 SIMD slots at once; the per-slot column is
the CUDA time divided by 16384 (throughput, not latency — a single
operation costs the full wall time regardless of how many slots are used).

Reproduce with:

```bash
cargo run --release -p fhe --example goldilocks_timing                  # CPU
cargo run --release -p fhe --example goldilocks_timing --features cuda  # GPU
```

| Op | CPU | CUDA | speedup | per slot (CUDA) |
|---|---|---|---|---|
| `encrypt_slots` (16384 values) | 33.7 ms | 28.2 ms | 1.2× | ~1.7 µs |
| `+` (slot-wise add) | 0.26 ms | 0.25 ms | ±0 (CPU) | ~15 ns |
| `*` + relinearization | 131.1 ms | 26.7 ms | **4.9×** | ~1.6 µs |
| `decrypt_slots` | 38.8 ms | 35.1 ms | 1.1× | ~2.1 µs |

The typed multiply (26.7 ms) is slower than the raw `mul_relin` grid row
at the same n = 16384, k = 6 (11.8 ms) because the hotpaths grid uses a
small plaintext modulus: a ~2^64 modulus pays extra in the BigUint
plaintext scaling path. That is the documented noise/scaling cost of
64-bit t, not typed-layer overhead. Encrypt/decrypt/add are dominated by
CPU-side encoding and stay near the CPU times.

## Confidential token kit

Wall-clock cost of the `fhe::token` confidential transfer at the curated
128-bit `FheUint64` parameters (degree 16384, six moduli, 291-bit q),
with an in-process 3-party committee. One transfer performs one
interactive balance-guard comparison (blinded-difference threshold
decryption), three homomorphic multiplications (two cmux balance
updates and the transferred-amount select), and two gateway refreshes
of the touched balances.

Reproduce with:

```bash
cargo run --release -p fhe --example confidential_transfer_timing                  # CPU
cargo run --release -p fhe --example confidential_transfer_timing --features cuda  # GPU
```

| Op | CPU | CUDA |
|---|---|---|
| committee keygen (N = 3) | 0.51 s | 0.31 s |
| one confidential transfer | 1.14 s | 0.32 s |

The CUDA speedup (3.5×) comes almost entirely from the five
relinearized multiplications inside the transfer; the committee
round-trips (decryption shares, mask encryptions) are CPU-side and
dominate the remaining 0.3 s.
