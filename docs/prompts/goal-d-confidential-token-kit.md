# Goal D: confidential token kit — self-hosted committee/gateway + ERC7984-style token

## Prerequisite — read first

Do NOT start this goal unless Goal B (`docs/prompts/goal-b-tfhe-rs-typed-api.md`,
the `FheUint64` typed layer) is merged or on the branch you are stacking on.
Goal C (`FheGoldilocks`) is NOT required. If Goal B is missing, stop and do
that goal instead.

## Context and motivation

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). The typed layer
(`fhe::typed::FheUint64`) gives wrapping-u64 encrypted arithmetic; the
`fhe::mbfv` module gives multiparty BFV primitives (collective public key
generation, threshold/secret-key-switch decryption, share aggregation).

The product goal: support OpenZeppelin-style confidential tokens
(github.com/OpenZeppelin/openzeppelin-confidential-contracts, the ERC7984
suite) **with the trust anchor — the threshold committee and decryption
gateway — under our own control** instead of Zama's. Throughput is NOT a
requirement; correctness and self-custody of the committee are.

Design decision already made (do not relitigate): comparisons are
**interactive**, via the committee, not homomorphic. The fhEVM model is the
peer: a t-of-n committee that decrypts designated values. We accept one
committee round-trip per comparison batch in exchange for staying inside
the depth budget of BFV without bootstrapping. Two consequences the
implementation must own:

1. **Noise lifecycle.** A token balance is a long-lived ciphertext updated
   on every transfer; without periodic committee recryption it dies of
   noise. Refresh is a correctness requirement, not an optimization.
2. **Leakage accounting.** Whatever the committee learns during a
   comparison (e.g. a blinded difference) must be documented precisely and
   asserted in tests. "The committee learns nothing it shouldn't" is a
   claim that needs a written definition of "shouldn't".

## The task

1. **Typed serialization.** `to_bytes`/`from_bytes` (via the existing
   `fhe_traits::Serialize`/`Deserialize` machinery) for `FheUint64` and
   `typed::ServerKey`, validating on deserialize that the parameters have
   t = 2^64. A gateway that cannot move ciphertexts over a wire is not a
   gateway.

2. **Committee/gateway module** (suggested: `fhe::gateway`), built on
   `fhe::mbfv`. An in-process committee of N parties (no networking in v1 —
   the protocol structure matters, the transport does not):
   - collective key generation (the token's public key is the committee's
     collective key; no single party ever holds the secret key);
   - `threshold_decrypt(handle)` — decryption of a designated ciphertext
     from t-of-n decryption shares;
   - `refresh(ct) -> ct'` — recryption to a fresh low-noise ciphertext of
     the same value, without any party seeing the plaintext;
   - `compare_ge(a, b) -> FheUint64` — the interactive comparison: returns
     a fresh encryption of 1 if a >= b else 0. The committee must not learn
     the raw operands. Blinding the decrypted intermediate (e.g. a
     multiplicatively blinded difference under a documented range
     restriction on values, such as amounts < 2^62) is acceptable; document
     exactly what each committee member learns per invocation, and test
     that the raw operands are never reconstructable from what a single
     party sees.

3. **Branch-free encrypted logic** (suggested: `fhe::typed::safe_math`):
   - `select(b, x, y) = b*x + (1-b)*y` over `FheUint64` (one homomorphic
     multiply; b is an encrypted 0/1 from the gateway);
   - `try_sub(a, b) -> (success_bit, result)` and
     `try_add(a, b) -> (success_bit, result)` mirroring fhEVM's
     `FHESafeMath`: on underflow/overflow the result selects back to the
     original value and the success bit encrypts 0. Never panic, never
     reveal which branch was taken.

4. **Confidential token service** (suggested: `fhe::token` or an example
   crate): the ERC7984 core semantics —
   - handle-based ciphertext store with a minimal ACL
     (`allow(handle, account)` / `is_allowed`), mirroring `FHE.allow`;
   - `mint(to, amount)` (amount public at mint, like ERC7984 mints);
   - `transfer(from, to, encrypted_amount)` that **never rejects**: on
     insufficient balance the transferred amount selects to an encryption
     of zero and balances stay unchanged — an observer of the ciphertexts
     and the call trace must not be able to tell a failed transfer from a
     zero-amount transfer;
   - encrypted total supply maintained as an invariant;
   - automatic `refresh` of touched balances via the gateway, with the
     refresh policy (every transfer, or every k transfers with a measured
     noise margin) chosen empirically and documented.

5. **End-to-end validation — the master verification for ALL of the
   above.** One integration test (`tests/confidential_token_e2e.rs`) that
   runs the full lifecycle and is the acceptance gate for every service in
   this goal; a service that is not exercised by this test is not done:
   1. committee keygen (N = 3 parties, in-process) — token deploys under
      the collective key;
   2. mint 1,000,000 to alice; mint 500,000 to bob;
   3. alice transfers 300,000 to bob (sufficient funds) — success path;
   4. bob transfers 10,000,000 to alice (insufficient funds) — the call
      completes without error, decrypted balances are unchanged, and the
      transferred-amount ciphertext decrypts to 0;
   5. a sequence of at least 10 further alternating transfers — this is
      the noise-lifecycle proof: it MUST route through gateway refresh and
      MUST fail if refresh is disabled (add a companion test asserting
      garbage-or-error without refresh, so the lifecycle claim is tested,
      not asserted);
   6. throughout: a plaintext reference ledger runs alongside; after every
      step, threshold-decrypt all balances and the total supply and assert
      exact equality with the reference;
   7. invariants asserted at every step: total supply constant under
      transfers, no single committee party's view contains a raw operand
      of any comparison, every stored ciphertext handle respects the ACL.

## Checkpoint gates — commit per gate, in order

Each gate is binary: every criterion is a command that passes or a test
that exists and passes. Do not start a gate before the previous one is
committed. If a gate cannot be met, stop and document why rather than
weakening the criterion.

**G1 — typed serialization (task 1).**
- `FheUint64` and `ServerKey` round-trip: `from_bytes(to_bytes(x))`
  decrypts/behaves identically; tested for fresh, added, and multiplied
  ciphertexts.
- Deserializing with parameters where t != 2^64 returns `Err` (test
  asserts the error, not a panic).
- `cargo test -p fhe serialization` green; `cargo clippy --workspace
  --all-features` and `cargo fmt --check` clean (these two repeat in every
  gate and are not restated below).

**G2 — committee/gateway (task 2).**
- N = 3 keygen: a value encrypted under the collective key
  threshold-decrypts correctly; decryption with only 1 party's share fails
  to produce the plaintext (test).
- `refresh`: take a ciphertext within 2 multiplications of noise failure
  (construct it empirically), refresh, then perform 2 further
  multiplications and decrypt correctly. The pre-refresh copy with the
  same 2 multiplications decrypts incorrectly (test proves refresh adds
  budget, not just "doesn't break").
- `compare_ge`: correct on >= 1000 random pairs plus the boundary set
  {(x,x), (x,x+1), (x+1,x), (0,0), (0,max), (max,max)} where max is the
  documented operand bound; result ciphertext decrypts to exactly 0 or 1.
- Leakage test: for a logged comparison transcript, assert each single
  party's view does not determine either raw operand (e.g. two different
  operand pairs produce identically-distributed single-party views under
  the blinding; at minimum, assert the blinded value differs from the true
  difference and the documented bound holds).

**G3 — branch-free safe math (task 3).**
- `select`, `try_add`, `try_sub` match a plaintext reference on >= 1000
  random triples plus all boundary cases (0, 1, max-1, max for each
  operand); success bits decrypt to exactly 0 or 1.
- Underflow/overflow cases: result decrypts to the ORIGINAL value (state
  rollback semantics), success bit to 0.
- Depth audit: a test performs `try_sub` followed by `select` on fresh
  ciphertexts at the curated Goal-B parameters and decrypts correctly —
  proving the per-transfer circuit fits the depth budget without refresh.

**G4 — token service (task 4).**
- `mint`/`transfer`/`balance_of`/total-supply unit tests against the
  plaintext reference ledger.
- Never-revert: insufficient-funds transfer returns `Ok`, balances
  unchanged, transferred amount decrypts to 0 (test).
- ACL: reading a balance handle without `allow` returns `Err` (test).
- Refresh policy: the chosen policy (every transfer or every k) is stated
  in the module docs WITH the measured noise margin that justifies it.

**G5 — end-to-end validation (task 5).**
- `tests/confidential_token_e2e.rs` runs the full lifecycle below and
  passes on CPU and with `--features cuda`.
- The no-refresh companion test fails-or-garbages exactly as predicted
  (asserted, not eyeballed).
- Every public item added in G1–G4 is called at least once by the e2e
  test (grep-verifiable: list the public API in the PR description with
  the e2e line number exercising each).
- Full suite green: `cargo test --workspace`,
  `cargo test -p fhe --features cuda`.

## Verification requirements

- The e2e test above passes with `cargo test --workspace` and with
  `cargo test -p fhe --features cuda` (the machine has an RTX PRO 6000);
  the >= 10-transfer sequence sizes the parameters realistically (the
  curated degree-16384 set from Goal B, not toy parameters).
- The no-refresh companion test proves refresh is load-bearing.
- A leakage section in the module docs states exactly what a committee
  member sees per comparison and per refresh; each claim in it backed by a
  test inspecting the actual share/blinded values.
- Doctests on all new public items compile and pass.
- `cargo test --workspace`, `cargo test -p fhe --features cuda`,
  `cargo clippy --workspace --all-features`, `cargo fmt --check` all clean.

## Rules

- No invented cryptography: the gateway composes existing `mbfv`
  primitives. If a step requires a protocol not constructible from them,
  stop and surface it rather than improvising.
- Interactive means interactive: do not smuggle in a homomorphic
  comparison circuit "while we're here". That is a different goal.
- Additive only — no changes to existing public API behavior.
- Honest failure modes: anything the committee could learn beyond the
  documented leakage is a bug, not a footnote.
- Commit per milestone with clear messages.
