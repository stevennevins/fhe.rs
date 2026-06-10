# Goal E: ERC7984 extension suite for the confidential token kit

## Prerequisite — read first

Do NOT start this goal unless Goal D (`docs/prompts/goal-d-confidential-token-kit.md`
— `fhe::gateway`, `fhe::typed::safe_math`, `fhe::token`) is merged or on
the branch you are stacking on. If Goal D is missing, stop and do that
goal instead.

## Context and motivation

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). Goal D
delivered the ERC7984 core: `fhe::token::ConfidentialToken` with
encrypted balances under a self-hosted 3-of-3 committee, never-reverting
transfers, a chain-of-custody ACL, and gateway refresh as the noise
lifecycle.

The product goal now: mirror the **extension suite** of
OpenZeppelin's confidential contracts
(github.com/OpenZeppelin/openzeppelin-confidential-contracts,
`contracts/token/ERC7984/extensions/`) on top of that core, so the kit
covers the same compliance and integration surface as the Solidity
stack: account restrictions, identity checks, observers, encrypted
freezing, public↔confidential wrapping, and the RWA composition.

Two extensions are explicitly OUT of scope for this goal:

- **ERC7984Votes**: requires the `VotesConfidential` checkpoint/delegation
  utility, a separate goal-sized piece of machinery.
- **ERC7984Hooked**: a dynamic module registry is an architecture
  decision (trait objects vs generics) that deserves its own design
  round. Do not smuggle a half-version in.

If you finish everything below with budget to spare, write
`docs/prompts/goal-f-*.md` proposals for those two instead of starting
them.

## Critical constraint — the depth budget (read before designing)

The curated `FheUint64::default_parameters_128` parameters support a
multiplicative depth of 2, and Goal D's transfer already consumes 1
level on each touched balance (the cmux guard). **ERC7984Freezable adds
a second encrypted guard to every transfer** (available = balance −
frozen, checked with a second comparison and folded in with a second
cmux). The per-transfer circuit therefore grows to depth 2 on the
sender balance — exactly the budget, with zero margin.

Consequences the implementation must own, not discover:

1. The freezable transfer MUST have its own depth audit test (G4 below)
   before any other freezable test is written.
2. If the combined circuit does not fit, the correct fixes are, in
   order of preference: (a) restructure the circuit to combine the two
   guards into one bit (`success = ge(available, amount)` only — the
   plain balance check is implied by `available <= balance`), (b)
   refresh the balance mid-transfer through the gateway (one extra
   committee round-trip, documented), (c) stop and document. Do NOT
   silently switch to deeper parameters; that invalidates every
   measured number in BENCHMARKS.md.
3. Every new encrypted guard leaks its outcome to the committee
   (Goal D's documented comparison leakage). Every extension below that
   performs a comparison must extend the leakage documentation AND the
   audit-log assertions, not just the happy-path tests.

## The task

Each extension is a separate module under `fhe::token` (suggested:
`fhe::token::extensions::*`), composing with `ConfidentialToken` —
prefer wrapper types or an options struct over inheritance-style traits;
match the existing code's style. Mirror semantics, not Solidity shape.

1. **Restricted** (mirrors `ERC7984Restricted.sol`): per-account
   restriction state (`Default` / `Blocked` / `Allowed`) with a
   blocklist mode (default allowed unless blocked) and an allowlist
   mode (default blocked unless allowed). A restricted party makes
   `transfer` return a structural `Err` BEFORE any encrypted work
   (restrictions are public, like the Solidity original — document
   this: restriction status and its enforcement are intentionally
   visible).

2. **IdentityCheck** (mirrors `ERC7984IdentityCheck.sol`): a pluggable
   identity registry (a Rust trait with `is_verified(account) -> bool`)
   checked for the RECIPIENT on transfer and mint; unverified recipient
   is a public structural `Err`. Ship an in-memory registry impl for
   tests.

3. **ObserverAccess** (mirrors `ERC7984ObserverAccess.sol`):
   `set_observer(account, observer)` / `observer(account)`. From the
   moment an observer is set, every NEW handle the account's activity
   creates (its rotated balance handles and the transferred-amount
   handles of transfers it participates in) is also ACL-allowed to the
   observer. Removing the observer stops future grants but does not
   revoke past ones (mirror OZ semantics; document this).

4. **Freezable** (mirrors `ERC7984Freezable.sol`): an encrypted frozen
   amount per account, set by an authorized freezer role via
   `set_confidential_frozen(account, FheUint64)`;
   `confidential_frozen(account)` and `confidential_available(account)`
   return ACL'd handles. Transfers are guarded by
   `available = balance - frozen` (branch-free: a transfer exceeding
   available selects to zero exactly like an insufficient-balance
   transfer, indistinguishable to observers). Frozen amounts above the
   balance must saturate, not underflow (use the existing safe-math
   semantics).

5. **ERC20-style wrapper** (mirrors `ERC7984ERC20Wrapper.sol`, adapted:
   there is no ERC20 here): a `PublicLedger` (plain u64 balances, part
   of the module, trivially) plus `wrap(account, amount)` — moves
   public balance into confidential mint — and the two-phase
   `request_unwrap(account, FheUint64) -> UnwrapRequest` /
   `finalize_unwrap(request)` — the amount is threshold-decrypted by
   the committee in the finalize step (documented leakage: an unwrap
   reveals its amount, by design) and credited to the public ledger.
   Conservation invariant: public + confidential total supply is
   constant across wrap/unwrap.

6. **Rwa composition** (mirrors `ERC7984Rwa.sol`): one type composing
   Restricted + Freezable + pause + agent role: `pause()`/`unpause()`
   (paused transfers are structural `Err`s), `block_user`/`unblock_user`,
   `set_confidential_frozen`, `force_transfer(from, to, FheUint64)`
   (agent-only; bypasses pause, restrictions, and the frozen guard but
   NOT the balance guard — a forced transfer still cannot overdraw),
   and `recover(lost, recipient)` which force-moves the full balance
   INCLUDING frozen amounts and re-freezes the recovered frozen portion
   at the recipient (mirror OZ's recovery semantics; the frozen amount
   travels encrypted, via an encrypted min and saturating arithmetic —
   never decrypted).

7. **End-to-end validation** (`tests/erc7984_extensions_e2e.rs`): one
   integration test at the curated production parameters running an
   RWA lifecycle that exercises EVERY extension above (a service not
   exercised here is not done): wrap from the public ledger, set an
   observer, freeze part of a balance, prove a transfer over the
   available amount silently zeroes while one under it succeeds, block
   a user and prove the public revert, pause/unpause, force-transfer,
   recover a "lost wallet" with a frozen portion, unwrap back to the
   public ledger — with a plaintext reference model asserted after
   every step, the supply-conservation invariant across the
   public/confidential boundary, and the leakage/ACL invariants from
   the Goal D e2e extended to the new comparisons.

## Checkpoint gates — commit per gate, in order

Each gate is binary: every criterion is a command that passes or a test
that exists and passes. Do not start a gate before the previous one is
committed. If a gate cannot be met, stop and document why rather than
weakening the criterion. `cargo clippy --workspace --all-features` and
`cargo fmt --check` clean repeat in every gate and are not restated.

**G1 — Restricted + IdentityCheck (tasks 1, 2).**
- Blocklist mode: blocked sender and blocked recipient each produce
  `Err` with no new handles created (assert handle count unchanged);
  unblocking restores transfer (test).
- Allowlist mode: default-deny proven by a transfer between two
  unlisted accounts failing; allowing both restores it (test).
- Unverified recipient: transfer and mint both `Err`; verifying via the
  registry trait restores both (test against the in-memory registry).
- Restriction/identity checks happen before encrypted work: a blocked
  transfer performs zero committee comparisons (assert via the audit
  log length, not timing).

**G2 — ObserverAccess (task 3).**
- After `set_observer(alice, eve)`: a subsequent transfer's new sender
  balance handle AND transferred-amount handle are `is_allowed` for
  eve, and `decrypt_for(handle, eve)` succeeds (test).
- Handles created BEFORE the observer was set remain denied (test).
- After removing the observer: the next transfer's new handles are
  denied to eve, while previously granted ones still decrypt (test
  pinning the documented no-revocation semantics).

**G3 — Freezable (task 4).**
- `confidential_available` = balance − frozen on >= 100 random
  (balance, frozen) pairs including frozen = 0, frozen = balance, and
  frozen > balance (saturating to available = 0); all decrypted via the
  committee against a plaintext reference (test).
- Guard semantics: with balance 1000 and frozen 600, a transfer of 401
  silently zeroes (balances unchanged, transferred amount decrypts to
  0) and a transfer of 400 succeeds — and an observer of handles and
  call traces cannot distinguish the zeroed case from a zero-amount
  transfer (same assertions as the Goal D never-revert test).
- Only the freezer role may set frozen amounts; others get `Err` (test).
- Leakage: the freezable transfer's extra comparison appears in the
  audit log and the single-party-view assertions from Goal D pass over
  it (test).

**G4 — Freezable depth audit (the constraint above).**
- A test at `FheUint64::default_parameters_128` runs ONE freezable
  transfer (freeze guard + balance guard + selects) on fresh
  ciphertexts and decrypts every output exactly; it documents in an
  assertion message which circuit variant (a) or (b) from the
  constraint section was used.
- The Goal D no-refresh companion logic repeated for freezable
  transfers: with refresh disabled, balances corrupt within a measured
  number of transfers, asserted with an explicit bound; with refresh
  enabled, a 10-transfer freezable sequence stays exact (test).

**G5 — wrapper (task 5).**
- Round-trip: wrap 1000 → confidential transfer 300 → unwrap 700
  returns exactly 700 to the public ledger; the reference model matches
  at every step (test).
- Conservation: public total + decrypted confidential supply constant
  across >= 20 random wrap/transfer/unwrap operations (test).
- Two-phase unwrap: `finalize_unwrap` of a request whose account lacks
  the encrypted funds credits exactly 0 / fails per documented
  semantics — pick one, document it, and pin it (test).
- The unwrap-reveals-amount leakage is stated in the module docs and
  asserted: the finalize step's decrypted value appears in the audit
  log / transcript (test).

**G6 — Rwa composition (task 6).**
- Pause: transfers `Err` while paused, succeed after unpause; non-agent
  cannot pause (test).
- Force transfer: succeeds from a blocked, frozen sender while paused;
  still cannot overdraw (forced transfer of more than the balance
  silently zeroes — test).
- Recover: a wallet with balance 1000 of which 400 frozen recovers to a
  new wallet holding balance 1000 with 400 still frozen; the frozen
  amount is never threshold-decrypted during recovery (assert via
  audit log: no decrypt of the frozen value, only the documented
  comparison/refresh traffic) (test).
- Role enforcement: every agent-gated entry point `Err`s for
  non-agents (one test sweeping all of them).

**G7 — end-to-end validation (task 7).**
- `tests/erc7984_extensions_e2e.rs` runs the full RWA lifecycle above
  at the curated degree-16384 parameters and passes on CPU and with
  `--features cuda`.
- Every public item added in G1–G6 is called at least once by the e2e
  test (grep-verifiable: list the public API in the PR description
  with the e2e line number exercising each).
- The plaintext reference model is asserted after every lifecycle step;
  supply conservation across the public/confidential boundary is
  asserted after every wrap/unwrap.
- Full suite green: `cargo test --workspace` and
  `cargo test -p fhe --features cuda`.
- `examples/` timing updated: measure one freezable (double-guard)
  transfer CPU and CUDA and record both in BENCHMARKS.md next to the
  Goal D numbers.

## Verification requirements

- All gate tests pass via `cargo test --workspace` and
  `cargo test -p fhe --features cuda` (the machine has an RTX PRO 6000).
- Doctests on all new public items compile and pass.
- Every new committee interaction (the freeze guard comparison, the
  unwrap decryption, recovery's encrypted min) is covered by the
  leakage documentation in the module that performs it, and each
  documented claim is asserted by a test against real transcript
  values — "the committee learns nothing it shouldn't" stays a tested
  claim, not a slogan.
- `cargo clippy --workspace --all-features`, `cargo fmt --check` clean.

## Rules

- No invented cryptography: extensions compose `fhe::gateway`,
  `fhe::typed::safe_math`, and `fhe::token` primitives. If a semantic
  requires a protocol not constructible from them (e.g. encrypted
  addresses for Omnibus-style routing), stop and surface it rather
  than improvising.
- Public checks stay public: Restricted/IdentityCheck/pause mirror the
  Solidity originals in reverting publicly. Do not "improve" them into
  encrypted checks — that changes the leakage model and the gas/work
  profile the suite is documented against.
- Additive only — no changes to existing public API behavior. The
  Goal D e2e test must still pass unmodified.
- Honest failure modes: anything the committee could learn beyond the
  documented leakage is a bug, not a footnote.
- Commit per gate with clear messages.
