# Goal A: Goldilocks SIMD — plaintext NTT for 64-bit moduli

## Context: where the codebase stands

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). This work stacks
on branch `feat/bfv-true-64bit` (PR #2, itself stacked on the CUDA backend
PR #1 / branch `feat/cuda-backend`). Verify the merge state of both PRs
before branching, and stack a new branch on whichever tip is current.

Already done — do not redo:

- Plaintext moduli t up to and including 2^64 work end-to-end. Moduli in
  [2^62, 2^64] route through the BigUint `PlaintextModulus::Large` path
  (`crates/fhe/src/bfv/parameters.rs`). With t = 2^64, encrypted add/mul
  match u64 `wrapping_add`/`wrapping_mul` exactly.
- Encoding at a level where the ciphertext modulus q <= t fails loudly
  (guard in `crates/fhe/src/bfv/plaintext_vec.rs`).
- Tests: `crates/fhe/tests/plaintext_64bit.rs` (16 tests covering
  round-trips, wrapping ops, public-key encryption, multiparty decryption,
  i64 decode, serialization, levels, one CUDA-gated test at degree 8192).

The limitation this goal removes: moduli >= 2^62 have NO SIMD/batching.
`NttOperator` (`crates/fhe-math/src/ntt/`) is built on
`fhe_math::zq::Modulus`, which is capped at 62 bits, so the builder sets
`ntt_operator` to `None` for Large moduli and only `Encoding::poly` works.

## The task

t = 2^64 - 2^32 + 1 = 18446744069414584321 (Goldilocks, the Plonky2/Plonky3
field) is prime with 2^32 | t - 1, so a radix-2 plaintext NTT exists for
every practical polynomial degree. Unlock SIMD encoding for Goldilocks so
users get slot-wise encrypted arithmetic in the same field zk circuits use.

Approach: add a 64-bit-capable NTT for the **plaintext side only**. The hot
ciphertext paths must stay on the 62-bit `Modulus` — do not touch them.
Evaluate honestly before coding:

1. A generic NTT over u128 arithmetic for any NTT-friendly 64-bit prime.
2. A Goldilocks-specialized NTT using the reduction trick from
   2^64 ≡ 2^32 - 1 (mod t) — simple and well documented in the zk world.

Plaintext encode/decode is not performance critical; correct and simple
beats fast. Option 2 with a clear "Goldilocks only" boundary is acceptable
if documented.

Wire-up points:

- `ntt_operator` construction in `BfvParametersBuilder::build`
  (`parameters.rs`, the `PlaintextModulus` match arm).
- The three SIMD gates in `plaintext_vec.rs` (`try_encode` for `&[u64]`,
  `&[BigUint]`, and `try_encode_vt`) — they currently error with
  `EncodingNotSupported` when `ntt_operator` is `None`.
- The SIMD decode path in `plaintext.rs` (search `EncodingEnum::Simd`),
  which converts through u64 today.
- `matrix_reps_index_map` already exists per degree and is
  modulus-agnostic.

Constraint to verify, not assume: SIMD requires t ≡ 1 (mod 2n). Goldilocks
satisfies this for every power-of-two n up to 2^31, but assert it in code
the same way the existing `NttOperator::new` does.

## Verification requirements

- Differential test: SIMD slot-wise encrypted add/mul must match plain
  Goldilocks field arithmetic computed independently (u128 or BigUint).
  The test must encode WHY: slot semantics = field semantics.
- Round-trip encode/decode (no encryption) for SIMD at several degrees.
- A test sized above the GPU threshold (k*n >= 2^13, `MIN_NTT_ELEMS` in
  `crates/fhe-math/src/cuda/mod.rs:39`) run with `--features cuda` —
  smaller tests silently run on CPU even with the feature enabled. The
  machine has an RTX PRO 6000.
- Non-NTT-friendly large moduli (e.g. t = 2^64) must still cleanly reject
  SIMD — the existing `t_2_64_simd_encoding_rejected` test must keep
  passing.
- `cargo test --workspace`, `cargo test -p fhe --features cuda`,
  `cargo clippy --workspace --all-features`, `cargo fmt --check` all clean.

## Rules

- No shortcuts; honest tradeoffs are fine if documented and tested.
- Surgical changes: do not refactor the existing 62-bit `NttOperator` or
  any ciphertext-side code.
- Degree-16 parameters in tests are fine (insecure but matches repo
  convention).
- Commit per milestone with clear messages.
