# Goal I: pay for grants only where the chain reads them (ACL gas)

## Prerequisite — read first

Do NOT start this goal unless Goal H (`docs/prompts/goal-h-composability.md`
— the on-chain ACL, symbolic ops, batches, and the auction example) is
merged or on the branch you are stacking on. Foundry (`anvil`, `forge`)
must be on the machine. Read the "Composability" section of
`docs/onchain-gateway.md` and the "On-chain ACL gas impact" section of
`BENCHMARKS.md` end to end — the table there IS this goal's target, and
`contracts/test/GasImpact.t.sol` is the fixture every claim must be
proven against.

## Context and motivation

Goal H priced the on-chain ACL honestly: ~24k gas per grant (one cold
SSTORE plus the `Allowed` event), six grants on an observed transfer's
fulfillment (+147,934, 128,456 → 276,390), plus two observer-snapshot
slots on the transfer entry point (+28,836). A three-subagent design
review of those costs converged on one observation:

**The chain only READS `isAllowed` in three places** — `allow`'s
chain-of-custody check, `requestOp`/`requestBatch` operand
authorization, and third-party views (`SealedBidAuction.submitBid`).
Every other grant exists purely to feed the coprocessor's mirror, which
is driven by request-ordered events and deterministic rules, not by
storage. Storage grants are therefore only owed where one of those
three readers needs them; everything else can be derived or carried by
events. Separately, every fulfillment pays ~24k of per-transaction
overhead that an operator with a backlog never needs to pay more than
once.

The measured ceiling if this lands: `fulfillTransfer` ~276k → ~135k
(back to the Goal G shape plus events), `confidentialTransfer` entry
back to ~94k, `registerInput` and `fulfillWrap` back to their Goal G
numbers — with the composability surface intact.

Explored and REJECTED during the review, recorded here so future goals
do not re-litigate: Merkle/accumulator ACLs (proofs churn per
fulfillment; break-even never arrives at six 32-byte grants),
commitment aggregation (breaks the per-handle integrity property the
tamper tests pin), fulfillment calldata diets (the echoes are
load-bearing for `_rotate` targets, not just the hash), and pure
events-only grants (the three contract read sites are real).

## Critical constraints — read before designing

1. **Trust model unchanged.** The coprocessor stays the v1 trusted
   executor; the enforcement point for decryption stays its mirrored
   read path; deferred binding and input-proof TODOs are untouched.
   Deriving grants moves no trust: the mirror evaluates the same
   deterministic rules against the same request-ordered state.
2. **Goal D–G test assertions survive unchanged** (Goal D/E files
   unmodified; F/G files extended only — the standing rule). **Goal H
   assertions survive too, with ONE named exception**: forge tests that
   assert `isAllowed(handle, observer)` on-chain may be REWRITTEN to
   pin the epoch semantics instead (I1 changes what the chain answers
   for observer pairs — that is the point, and it must be pinned, not
   deleted). Every Rust-side observer regression (`onchain_extensions`,
   `onchain_acl`, `onchain_e2e`) passes unchanged: the mirror's
   answers must be IDENTICAL to Goal H's.
3. **`fhe::token` / `fhe::gateway` public API stays frozen**; the
   gateway's existing entry points, events, and fulfillment signatures
   survive unchanged. New entry points (`fulfillMany`) are additive.
   `fhe-coprocessor` may break its API.
4. **Name every semantic change** the way Goal H named deferred
   binding. Known ones to name in docs: (a) the chain stops answering
   `isAllowed` for observers (observer rights become mirror-derived;
   third-party contracts cannot check them on-chain), (b) an account's
   implicit grant follows its CURRENT balance/frozen handle — on-chain
   chain-of-custody over a rotated-away (stale) handle requires an
   explicit `allow` made while it was current. The mirror keeps Goal
   H's permanent semantics for decryption either way.
5. **Every gas claim is proven by the committed fixture**
   (`GasImpact.t.sol` via `forge test --match-contract GasImpactTest
   --gas-report`), comparing against the Goal H numbers in
   BENCHMARKS.md — same discipline as the Goal H follow-up commit.

## The task

1. **Epoch-based observer grants (I1).** Drop the four per-handle
   observer storage grants and both request-time snapshot slots.
   On-chain state: `observerOf[account]` (exists) plus
   `observerSince[account]` — the request id at which the current
   observer was set. Rule, evaluated identically by the coprocessor's
   mirror in request order: observer O of account X may read every
   handle created FOR X by a request with id ≥ observerSince[X] while
   O was X's observer (the mirror closes the interval on
   removal/replacement — track intervals, not just the latest).
   No-retroactive-grants and removal-keeps-past-handles semantics must
   reproduce exactly (the Goal E/F/H Rust observer tests are the
   regression suite). The snapshot mappings and their writes/deletes
   are removed.
2. **Derived (implicit) grants (I2).** `isAllowed(handle, account)`
   becomes a view over: the explicit-grant mapping (written ONLY by
   `allow()` and by symbolic-result creation), OR
   `confidentialBalanceOf[account] == handle`, OR
   `confidentialFrozen[account] == handle`, OR
   `inputOwner[handle] == account`, OR the agent on a current frozen
   handle. `registerInput`, `fulfillWrap`, `fulfillTransfer`,
   `fulfillFrozenSet`, `fulfillRecover`, `fulfillUnwrap` stop writing
   grant storage for those derivable readers. Decide explicitly, and
   document, whether `Allowed` events are still emitted for derivable
   grants (the mirror already applies its own deterministic rules in
   `process()`; events for derivable grants are visibility, not
   enforcement — if dropped, say so in the docs and PR).
   Transferred-amount handles keep explicit grants for both parties
   (nothing derives them) unless you adopt the reviewed lazy-grant
   variant — if you do, name its trust-model footnote.
3. **Adaptive cross-request fulfillment batching (I3).** A
   `fulfillMany` entry point: one coprocessor transaction fulfilling
   consecutive pending requests N..N+k of mixed kinds, looping the
   EXACT existing per-id binding checks (`_fulfill` semantics per
   request: in order, op tag, payload hash) and emitting the existing
   per-request fulfillment events. The operator batches ONLY requests
   already in its pending map — adaptive, never waiting to fill a
   batch, so single-request latency is unchanged. Crash-restart: the
   cursor advances atomically across the batch; extend the
   crash-restart test across a `fulfillMany` boundary. While in the
   area, fold in the reviewed freebies: pack the request op tag into
   the request-hash slot (one slot per pending request instead of two;
   keep ABI-compatible `requestOpTag`/`requestHash` views) — and keep
   `fulfillAck`'s semantics reachable through `fulfillMany` so ack
   storms coalesce.
4. **Re-measure and document (I4).** Update the BENCHMARKS.md ACL
   gas-impact table to three columns (Goal G base / Goal H / Goal I)
   from the fixture; add a `fulfillMany` row measured at a realistic
   mixed backlog (e.g. the 8-op sequential scenario from
   `onchain_batch.rs`). Re-run the production-parameter e2e (CPU and
   CUDA) to show FHE latency is still unchanged within noise. Update
   `docs/onchain-gateway.md`: the ACL section describes the
   derived+epoch model, and the "named" list gains constraint 4's two
   semantic changes.

## Checkpoint gates — commit per gate, in order

`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
(stable), `forge test`, and `cargo test --workspace --release` repeat
clean in every gate.

**I1 — epoch observers.** Snapshot machinery gone; observer mirror
interval-based; all Rust observer regressions green unchanged; forge
tests pin the epoch rules (set-after-request not granted, removal
closes the interval, replacement opens a new one); fixture shows the
entry-point and fulfillment deltas.

**I2 — derived grants.** The view rule; storage writes removed at
every derivable site; `onchain_acl.rs` green unchanged; forge tests
pin the stale-handle custody change and that `allow()` still works on
current handles and explicit grants; fixture deltas recorded.

**I3 — fulfillMany.** Mixed-kind batched fulfillment with per-request
binding intact; crash-restart across a fulfillMany boundary; gas
comparison vs one-tx-per-request in the commit message; op-tag slot
packing landed with ABI-compatible views.

**I4 — measurement + docs.** The three-column table; e2e re-run CPU
and CUDA; docs name the semantic changes; quickstart and auction
examples untouched and green.

## Verification requirements

- `GasImpact.t.sol` is the proof for every gas number; extend it only
  by adding scenarios (the existing canonical flow stays measurable).
- Goal D–G assertions all survive; Goal H survives except the
  enumerated observer-`isAllowed` forge assertions, which are replaced
  by epoch pins (diff must show nothing else changed in those tests).
- The mirror's decrypt answers are bit-identical to Goal H across the
  whole regression suite — the optimization is invisible off-chain.
- The auction example runs green unmodified: third-party contracts
  built on `allow`/`isAllowed`/`requestBatch` must not notice I1/I2.
- The PR description shows the before/after table and names both
  semantic changes and the `Allowed`-event decision.

## Rules

- Storage is owed only to the chain's three read sites; everything
  else must justify its SSTORE or lose it.
- If an optimization threatens any frozen assertion, drop the
  optimization, not the assertion — and record the attempt in the PR.
- The rejected-ideas list above is binding for this goal: do not
  spend gates re-exploring Merkle ACLs, commitment aggregation, or
  calldata diets.
- Carry the Goal G liveness lessons and the Goal H mirror-determinism
  lesson (grants are a pure function of request-order state on BOTH
  sides) into every change; the epoch intervals must replay
  identically from the event log after a crash.
