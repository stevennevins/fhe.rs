# Goal B: tfhe-rs-style typed API — FheUint64 and curated 64-bit parameters

## Context: where the codebase stands

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). This work stacks
on branch `feat/bfv-true-64bit` (PR #2, itself stacked on the CUDA backend
PR #1 / branch `feat/cuda-backend`). Verify the merge state of both PRs
before branching, and stack a new branch on whichever tip is current.

Already done — do not redo:

- Plaintext moduli t up to and including 2^64 work end-to-end through the
  BigUint `PlaintextModulus::Large` path
  (`crates/fhe/src/bfv/parameters.rs`). With t = 2^64, every u64 is a valid
  message and encrypted add/sub/neg/mul match Rust's wrapping u64 semantics
  exactly. `&[u64]` encodes in, `Vec<u64>` decodes out.
- Tests: `crates/fhe/tests/plaintext_64bit.rs` (16 tests). Read them first;
  they demonstrate the full low-level API this goal wraps.
- Encoding at a level where the ciphertext modulus q <= t fails loudly.

The gap this goal fills: users must juggle `BfvParametersBuilder`,
`Plaintext::try_encode`, `Encoding::poly`, and `Ciphertext` by hand.
tfhe-rs instead exposes typed integers (`FheUint64`) with operator
overloading. Add that ergonomic layer.

## The task

Add a thin typed layer in a new module of `crates/fhe` (suggest
`crates/fhe/src/typed/` or similar). Do NOT disturb the existing API.

1. A `FheUint64` wrapper over `Ciphertext` bound to t = 2^64 parameters:
   - `encrypt(value: u64, key, rng) -> FheUint64` (secret- and public-key)
   - `decrypt(&self, sk) -> u64`
   - `+`, `-`, `*`, unary `-` via `std::ops` traits (reference and owned
     variants matching how `Ciphertext` already implements them — see
     `crates/fhe/src/bfv/ops/`)
   - Multiplication needs a `RelinearizationKey`; decide the ergonomics
     deliberately (tfhe-rs uses a thread-local server key; a simpler
     explicit-key API is acceptable — document the divergence).
2. A curated default parameter set for 64-bit messages at 128-bit security.
   Constraints discovered in prior work:
   - `default_parameters_128` in `parameters.rs` has
     `debug_assert!(plaintext_nbits < 64)` and generates plaintext primes
     via `generate_prime`, which cannot produce >= 2^62 values (the
     `Modulus` type backing it is 62-bit-capped). Do not fight this —
     extend the table with explicit moduli lists for t = 2^64 instead.
   - The plaintext context needs ciphertext moduli totalling at least
     t_bits + 60 bits, and each multiplication burns roughly 64+ bits of
     noise budget with this t. Size q for at least 1-2 multiplications and
     verify the depth empirically with a test, not arithmetic on paper.
   - Use standard 128-bit-security degree/q pairings (homomorphic
     encryption standard tables; degree 8192 or 16384 territory for q in
     the 180-250 bit range).
3. Mirror tfhe-rs naming where it is free to do so; do not contort the
   design to match it. Document each intentional divergence in the module
   docs.

## Verification requirements

- Round-trip and wrapping-arithmetic tests for `FheUint64` against plain
  u64 `wrapping_*` ops, including operator-trait sugar.
- A multiplication-depth test on the curated 128-bit parameter set proving
  the advertised depth actually decrypts correctly.
- At least one test sized above the GPU threshold (k*n >= 2^13) run with
  `--features cuda`; the machine has an RTX PRO 6000. Production-sized
  parameters from item 2 qualify naturally.
- `cargo test --workspace`, `cargo test -p fhe --features cuda`,
  `cargo clippy --workspace --all-features`, `cargo fmt --check` all clean.
- Doc examples on the typed API that compile (doctests).

## Rules

- No shortcuts; honest tradeoffs are fine if documented and tested.
- The typed layer is additive — zero changes to existing public API
  behavior. Run the full suite to prove it.
- Tests must encode WHY (e.g. "FheUint64 mul matches u64 wrapping_mul"),
  not just exercise code.
- Commit per milestone with clear messages.
