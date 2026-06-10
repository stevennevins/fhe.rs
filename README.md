# fhe.rs: Fully Homomorphic Encryption in Rust

[![continuous integration](https://github.com/tlepoint/fhe.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/tlepoint/fhe.rs/actions/workflows/rust.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Code coverage](https://codecov.io/gh/tlepoint/fhe.rs/branch/main/graph/badge.svg?token=LCBSDMB5NS)](https://codecov.io/gh/tlepoint/fhe.rs)

This repository contains the `fhe.rs` library, an experimental cryptographic library in Rust for Ring-LWE-based homomorphic encryption, developed by [Tancrède Lepoint](https://tancre.de).
For more information about the library, see [fhe.rs](https://fhe.rs).

The library features:

* An implementation of a RNS-variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme;
* Performances comparable or better than state-of-the-art libraries in C++ and Go.

> **Note**
> This library is **not** related to the `tfhe-rs` library (a.k.a. `concrete`), Zama's fully homomorphic encryption in Rust, available at [tfhe.rs](https://github.com/zama-ai/tfhe-rs).

## fhe.rs crates

`fhe.rs` is implemented using the Rust programming language. The ecosystem is composed of four public crates (packages):

* [![fhe crate version](https://img.shields.io/crates/v/fhe.svg)](https://crates.io/crates/fhe) [`fhe`](https://crates.io/crates/fhe): This crate contains the implementations of the homomorphic encryption schemes;
* [![fhe-math crate version](https://img.shields.io/crates/v/fhe-math.svg)](https://crates.io/crates/fhe-math) [`fhe-math`](https://crates.io/crates/fhe-math): This crate contains the core mathematical operations for the `fhe` crate;
* [![fhe-traits crate version](https://img.shields.io/crates/v/fhe-traits.svg)](https://crates.io/crates/fhe-traits) [`fhe-traits`](https://crates.io/crates/fhe-traits): This crate contains traits for homomorphic encryption schemes;
* [![fhe-util crate version](https://img.shields.io/crates/v/fhe-util.svg)](https://crates.io/crates/fhe-util) [`fhe-util`](https://crates.io/crates/fhe-util): This crate contains utility functions for the `fhe` crate.

### Installation

To install, add the following to your project's `Cargo.toml` file:

```toml
[dependencies]
fhe = "0.2.0"
fhe-traits = "0.1.1"
```

## GPU acceleration (CUDA, experimental)

The `cuda` feature offloads the polynomial-arithmetic hot paths (NTT,
RNS basis extension/scaling, key switching) to an NVIDIA GPU, which speeds
up BFV ciphertext multiplication, relinearization, and rotation by roughly
an order of magnitude at large parameters (see `BENCHMARKS.md`):

```toml
[dependencies]
fhe = { version = "0.2.0", features = ["cuda"] }
```

- **Build prerequisites: none.** Kernels are CUDA C compiled at runtime by
  NVRTC; no `nvcc` or CUDA toolkit is needed to build (the `cudarc`
  dependency loads `libcuda`/`libnvrtc` dynamically).
- **Runtime prerequisites:** an NVIDIA driver and the CUDA NVRTC library
  (CUDA toolkit ≥ 12), Linux. Compute capability 7.0+ is supported.
- **Graceful fallback:** if no usable GPU (or no driver) is present at
  runtime, all operations transparently use the CPU path. Setting
  `FHE_CUDA_DISABLE=1` forces the CPU path.
- **Bit-exact:** GPU results are identical to CPU results for every
  operation; this is enforced by differential tests
  (`cargo test -p fhe-math --features cuda`).
- **Known limitations:** the `cuda` feature has no effect when combined
  with the `tfhe-ntt` feature; small parameter sets (e.g. n = 2¹², 1–2
  moduli) partially stay on the CPU where the GPU transfer cost would
  dominate; device memory is not zeroized.

Design details live in `docs/cuda-backend-design.md`.

## 64-bit plaintext moduli and zk compatibility

This fork supports plaintext moduli up to 2^64, with a typed API
(`fhe::typed`) offering two 64-bit message types with different semantics:

| | `FheUint64` | `FheGoldilocks` |
|---|---|---|
| Plaintext modulus t | 2^64 | 2^64 − 2^32 + 1 (the Goldilocks prime) |
| Arithmetic | wrapping `u64` (`wrapping_add`/`sub`/`mul`/`neg`) | field arithmetic mod t |
| SIMD batching | none — t = 2^64 is not NTT-friendly | `degree` slots per ciphertext |
| Interop story | same message space as tfhe-rs' `FheUint64` | same field as Plonky2/Plonky3 zk circuits |
| Verified by | `crates/fhe/tests/typed_fheuint64.rs` | `crates/fhe/tests/typed_goldilocks.rs` |

**`FheUint64`** fixes t = 2^64, so encrypted `+`, `-`, `*` decrypt to
exactly Rust's wrapping `u64` results — the same message space as tfhe-rs'
`FheUint64`. Since 2^64 admits no plaintext NTT, each ciphertext carries a
single value.

**`FheGoldilocks`** fixes t = 2^64 − 2^32 + 1. Because 2^32 divides t − 1,
a plaintext NTT exists for every practical degree, so one ciphertext
batches `degree` independent field elements (16384 slots at the curated
128-bit parameters) with slot-wise `+`, `-`, `*` — in exactly the field
Plonky2/Plonky3 use. Inputs ≥ t are reduced modulo t on encryption;
encrypted slot operations are differentially tested against an independent
u128 reference implementation, including the 2^32-structured edge cases.

Both moduli cost the same noise budget (~64 bits of q per message), so they
share parameter sizing: the curated `default_parameters_128()` sets
(degree 16384, 291-bit q, 128-bit security per the
[homomorphicencryption.org](https://homomorphicencryption.org) standard)
support multiplicative depth 2, verified empirically by the tests above.
Deeper circuits need a larger degree and ciphertext modulus.

## Minimum supported version / toolchain

Rust **1.91.1** or newer (Rust 2024 edition).

## ⚠️ Security / Stability

The implementations contained in the `fhe.rs` ecosystem have never been independently audited for security.

Use at your own risk.
