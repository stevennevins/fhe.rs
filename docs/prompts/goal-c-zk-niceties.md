# Goal C: zk-adjacent niceties — FheGoldilocks and the compatibility story

## Prerequisite — read first

Do NOT start this goal unless BOTH are already merged or on the branch you
are stacking on:

- Goal A (`docs/prompts/goal-a-goldilocks-simd.md`): plaintext SIMD/NTT for
  the Goldilocks prime t = 2^64 - 2^32 + 1.
- Goal B (`docs/prompts/goal-b-tfhe-rs-typed-api.md`): the `FheUint64`
  typed layer and curated 128-bit-security parameters for 64-bit messages.

If either is missing, stop and do that goal instead. This goal is the
polish layer; it has no value standing alone.

## Context: where the codebase stands

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). Base work:
branch `feat/bfv-true-64bit` (PR #2) made 62- to 64-bit plaintext moduli
work through the BigUint path with native-u64 wrapping semantics, tested on
both the CPU and CUDA backends (`crates/fhe/tests/plaintext_64bit.rs`).
Goal A added a Goldilocks plaintext NTT; Goal B added the typed API.

## The task

1. **`FheGoldilocks` typed wrapper.** Mirror the `FheUint64` design from
   Goal B, but over the Goldilocks field with SIMD slots:
   - `encrypt_slots(&[u64], key, rng)` / `decrypt_slots(...) -> Vec<u64>`
     (values reduced mod t; document the reduction behavior explicitly)
   - Slot-wise `+`, `-`, `*` via operator traits
   - Field semantics, not wrapping-integer semantics: document that
     arithmetic is mod 2^64 - 2^32 + 1, matching Plonky2/Plonky3.
2. **Differential test against a reference Goldilocks implementation.**
   Implement (or vendor in a dev-dependency, if one is already in the
   dependency tree — check before adding) plain Goldilocks field ops and
   assert encrypted slot ops match across random inputs, including values
   near t and the 2^32-structured edge cases (x = 2^32, t - 1, 2^64 mod t).
3. **Document the compatibility story.** A README section plus module-level
   doc comments covering:
   - u64 messages: t = 2^64, wrapping semantics, tfhe-rs message-space
     compatibility, no SIMD (not NTT-friendly).
   - Goldilocks: SIMD slots, field semantics, zk (Plonky2/Plonky3)
     interop rationale.
   - The tradeoff table: SIMD availability, noise budget cost of 64-bit t,
     parameter sizing guidance (point at the curated set from Goal B).
   Keep claims verifiable — every documented behavior must have a test.

## Verification requirements

- Differential tests as above; edge cases mandatory, not optional.
- Doctests on all new public items compile and pass.
- At least one Goldilocks SIMD test sized above the GPU threshold
  (k*n >= 2^13, `MIN_NTT_ELEMS` in `crates/fhe-math/src/cuda/mod.rs:39`)
  run with `--features cuda`; the machine has an RTX PRO 6000.
- `cargo test --workspace`, `cargo test -p fhe --features cuda`,
  `cargo clippy --workspace --all-features`, `cargo fmt --check` all clean.

## Rules

- No shortcuts; honest tradeoffs are fine if documented and tested.
- Additive only — no changes to existing public API behavior.
- Do not add heavyweight zk dependencies (no plonky2/plonky3 crates) just
  for a reference implementation; plain u128 arithmetic is enough.
- Commit per milestone with clear messages.
