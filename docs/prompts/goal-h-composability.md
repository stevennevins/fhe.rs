# Goal H: make encrypted state composable (symbolic handles + on-chain ACL)

## Prerequisite — read first

Do NOT start this goal unless Goal G (`docs/prompts/goal-g-api-simplicity.md`
— the `Client`/`Operator` surface and the ERC7984-aligned gateway) is
merged or on the branch you are stacking on. Foundry (`anvil`, `forge`)
must be on the machine (check `anvil --version`; stop and surface it if
missing). Read `docs/onchain-gateway.md` end to end — especially the
"Divergences from OZ ERC7984, named" section and the fhEVM mapping
table, whose "symbolic execution: none" and "ACL: coprocessor-side"
rows are exactly what this goal changes. Clone
https://github.com/zama-ai/relayer-sdk and study how fhEVM handles are
derived and type-tagged (`FhevmHandle`) before designing — the point is
to close the gap with their model, not to invent a third one.

## Context and motivation

Goal G made the kit as easy to USE as fhEVM. It did not make it as
easy to BUILD ON. Today the operation set is closed: every encrypted
operation is a matched triple — a contract entry point, a coprocessor
match arm, a kit circuit — and adding one means changing all three and
redeploying. fhEVM's coprocessor instead executes arbitrary
compositions (`FHE.add`, `FHE.ge`, `FHE.select`, ...) requested by
contracts it has never seen, because:

1. **Result handles are symbolic**: derived on-chain from
   `keccak(op, input handles, ...)` BEFORE the ciphertext exists, so
   contracts can chain operations in one transaction and the FHE work
   materializes afterward.
2. **The ACL is an on-chain contract**: `FHE.allow(handle, account)`
   is public state any contract can write (for handles it is allowed
   to manage) and the decryption path reads.

What composability buys (from the Goal G review discussion, kept here
as the requirement's motivation): third-party encrypted logic without
coprocessor changes, atomic multi-step operations in one transaction,
cross-contract use of encrypted state, and latency hiding (the
transaction confirms at chain speed; the FHE compute pipelines behind
it). What it costs, named: a symbolic handle is a PROMISE about a
future ciphertext, so the chain can no longer hash-bind every handle
at mint time — `handleCommitment` becomes deferred (posted at
materialization) and the binding rests on the fulfillment transaction
being coprocessor-signed. That is a real weakening relative to Goal F's
anchor-at-mint and must be documented, not hidden.

This goal builds the smallest honest version of that model: a generic
encrypted-op surface with symbolic result handles, an on-chain ACL,
atomic multi-op batches, and ONE worked third-party example proving a
developer can build new encrypted logic without touching the
coprocessor crate.

## Critical constraints — read before designing

1. **No new cryptography, trust model unchanged.** The coprocessor
   remains the v1 trusted executor; the committee stays in-process
   N-of-N; input proofs remain the named TODO-by-trust-model. Symbolic
   handles change WHEN binding happens, not WHO is trusted. The
   deferred-binding weakening must be stated in
   `docs/onchain-gateway.md` with the same bluntness as the existing
   trust-model section.
2. **The Goal G token surface is frozen.** Every existing entry point
   (`confidentialTransfer`, `wrap`/`unwrap`, the Rwa agent ops, ...),
   every request/fulfillment event, and every Goal D–G test assertion
   survives unchanged. The token may OPTIONALLY be re-expressed over
   the new primitives internally only if every test (including
   gas-shape equality and the leakage sweeps) still passes bit-for-bit
   on assertions; if that re-expression threatens any assertion, keep
   the token on its dedicated circuits and say so.
3. **`fhe::token` / `fhe::gateway` public API stays frozen** (same
   rule and same exception process as Goal G: an accessor-level
   addition needs explicit justification in the gate commit).
4. **`fhe-coprocessor` may break its API** (still `publish = false`),
   but the Goal G `Client`/`Operator` ergonomics bar still applies to
   everything new: no rng threading, no manual serialization, no raw
   alloy plumbing in user-facing flows.
5. **Handle compatibility.** fhEVM-style structured handles (type tag
   + version in the trailing bytes) replace the opaque keccak handles
   for NEW symbolic results. Existing anchor-at-mint handles (inputs,
   token fulfillment outputs) keep their current derivation — do not
   migrate them; document the two kinds and how a reader tells them
   apart.
6. **Leakage discipline extends to the new ops.** Every new primitive
   that reveals anything (a comparison's blinded difference, a select)
   gets the same transcript/audit treatment as the Goal D/E circuits,
   and the e2e-style leakage sweep must cover compositions, not just
   single ops.

## The task

1. **On-chain ACL** (`contracts/src/` — a new contract or a gateway
   extension, your call, justified): `allow(handle, account)` /
   `isAllowed(handle, account)` in the fhEVM shape. Authorization to
   grant follows fhEVM's model (the handle's owner/creator contract
   may grant). The coprocessor's `decrypt_for` read path now enforces
   FROM the on-chain ACL state (mirrored by events, like the rest of
   the policy state) instead of its private kit ACL; the existing
   observer-grant semantics must reproduce exactly on top of it (the
   Goal E/F observer tests are the regression suite).
2. **Symbolic encrypted ops**: a generic request entry point (e.g.
   `requestOp(uint8 op, bytes32 lhs, bytes32 rhs) returns (bytes32 result)`)
   for a SMALL fixed alphabet — `add`, `sub`, `ge`, `select` is enough
   to express a guarded transfer — where `result` is derived
   deterministically on-chain (keccak of op, inputs, request id, and a
   domain tag, with the fhEVM-style type/version trailing bytes).
   The coprocessor materializes results in request order and posts
   `handleCommitment` at fulfillment (the deferred binding). Sender
   authorization: the caller must be allowed (per the ACL) on every
   input handle.
3. **Atomic batches**: one transaction carrying an ordered list of ops
   where later ops may reference earlier results IN THE SAME BATCH
   (the symbolic derivation makes the intra-batch handles computable
   on-chain). One request id per batch, one fulfillment per batch.
   This is also the moment to design the `fulfillBatch` gas
   amortization the Goal G batching discussion identified — same
   binding rules, several fulfillments' payloads in one transaction.
4. **The third-party proof**: a worked example contract
   (`contracts/src/examples/` or similar) built ONLY on the public
   primitives — suggested: a sealed-bid auction step or an encrypted
   escrow with threshold release (`ge` + `select` + transfer of the
   selected amount) — plus a Rust example driving it through `Client`
   extended with `client.request_op(...)` / `client.batch(...)`.
   The acceptance bar: this example adds NO code to the coprocessor
   crate's op execution (the coprocessor learns nothing about
   "auctions") and NO new contract entry points on the gateway.
5. **Client + Operator extensions**: `Client` gains the op/batch
   methods and an `allow` method; result-handle decryption goes
   through the same ACL-checked `balance`-style read path. The
   `Operator` loop executes the new request kinds with the same
   strict-order, idempotent-resume properties (crash-restart coverage
   extends to a half-materialized batch).
6. **Docs**: update `docs/onchain-gateway.md` — the mapping table rows
   for symbolic execution and ACL flip from "none/coprocessor-side" to
   the new reality; a new section explains the two handle kinds, the
   deferred-binding trade, and what is STILL deliberately absent
   (input proofs, networked committee, arbitrary-contract FHE — the
   alphabet is fixed and small, and that is a feature).

## Checkpoint gates — commit per gate, in order

`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
(stable), `forge test`, and `cargo test --workspace --release` repeat
clean in every gate.

**H1 — on-chain ACL.** ACL contract + coprocessor read path driven by
it; all Goal E/F/G observer and ACL-denial assertions green unchanged;
forge tests pin the grant-authorization rules.

**H2 — symbolic ops.** The op alphabet with symbolic result handles;
deferred commitment posting; forge tests pin handle derivation and
input-authorization reverts; a Rust test proves a `ge`+`select`
composition decrypts to the reference value and its leakage transcript
passes the Goal D sweeps.

**H3 — batches.** Atomic multi-op batches with intra-batch references;
`fulfillBatch`; crash-restart test extended across a batch boundary;
gas measurements comparing batched vs sequential fulfillment in the
commit message.

**H4 — the example + docs.** The third-party example contract and its
client-driven Rust example (CPU and CUDA); docs updated; the
quickstart stays untouched and green.

## Verification requirements

- Goal D–G test files: every assertion survives (diff assertion lines;
  Goal D/E files unmodified, Goal F/G files extended only).
- The production-parameter e2e passes CPU and CUDA, and gains at least
  one symbolic-composition step with reference-model and leakage
  assertions.
- The example contract demonstrably adds zero coprocessor code: CI
  greps or the PR diff proves the coprocessor crate's op execution is
  untouched by H4.
- BENCHMARKS.md gains a symbolic-op and batched-fulfillment latency
  table (same harness discipline as the existing gateway table).
- The PR description shows a before/after: the closed-triple change
  process vs the example contract's diff.

## Rules

- Smallest honest alphabet: resist adding ops the example does not
  need. Every op added must appear in a test with reference + leakage
  assertions.
- Encrypted guards never revert, including in compositions: a `select`
  on a failed `ge` produces the same fulfillment shape as a successful
  one. Public checks (ACL membership, handle existence, batch
  well-formedness) revert in the contract.
- Name every weakening (deferred binding, fixed alphabet, grant
  authorization rules) in the docs the way Goal F named
  censorship/stalling — a reader must be able to enumerate what the
  chain does NOT guarantee.
- Honest failure modes: if alloy or gas constraints force a scope cut
  (e.g. batch size limits), document the limit and pin it in a forge
  test rather than leaving it implicit.
- Commit per gate with clear messages; carry the Goal G liveness
  lessons (direct receipt lookup, subscription resync, simple nonces)
  into any new chain interaction rather than re-learning them.
