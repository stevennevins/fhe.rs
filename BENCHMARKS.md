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
```

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

## Phase 4 — CUDA results

(To be filled at gate G4: same grid with `--features cuda`, speedup table,
dispatcher heuristics, and profiling notes for any missed target.)
