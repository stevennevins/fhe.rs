# Goal F: exercise the confidential token kit via on-chain transactions

## Prerequisite — read first

Do NOT start this goal unless Goal E (`docs/prompts/goal-e-erc7984-extensions.md`
— `fhe::token::extensions::*`) is merged or on the branch you are
stacking on. This goal also requires Foundry (`anvil`, `forge`) on the
machine; check first (`anvil --version`) and stop and surface it if
missing rather than substituting a mock chain.

## Context and motivation

Repo: fhe.rs (fork stevennevins/fhe.rs of tlepoint/fhe.rs). Goals D and
E delivered an in-process confidential token kit: `ConfidentialToken`
plus the ERC7984 extension suite (Restricted, IdentityCheck,
ObserverAccess, Freezable, the public-ledger wrapper, Rwa), all driven
by direct Rust calls with `Account = u64` and the documented caveat
that caller authenticity is "the embedding application's problem."

The product goal now: BE that embedding application. Mirror the fhEVM
deployment shape — a chain that holds **handles and access-control
state**, and an off-chain **coprocessor** that owns the ciphertexts and
the committee — and drive the full extension lifecycle through real
signed transactions on a local EVM devnet:

- A minimal Solidity contract, `ConfidentialTokenGateway.sol`,
  ERC7984-shaped: balance handles as `bytes32`, extension entry points
  (`transfer`, `setObserver`, `setConfidentialFrozen`, `blockUser`,
  `pause`, `forceTransfer`, `recover`, `wrap`, `requestUnwrap`),
  role modifiers, and request/fulfilled events.
- A Rust coprocessor (new binary or crate, e.g.
  `crates/fhe-coprocessor` or an `examples/` binary if it stays small)
  that subscribes to the contract's events via `alloy`, executes the
  corresponding `fhe::token` / `fhe::token::extensions` operation, and
  posts the resulting handles back in a fulfillment transaction.
- The on-chain `msg.sender` becomes the authenticated caller: an
  `Address ↔ Account` binding closes the kit's documented
  no-signature-checking gap. Role checks (agent, freezer) and public
  policy checks (restricted, paused, identity) are enforced **in the
  contract**, where they are public anyway; encrypted guards stay in
  the coprocessor.

## Critical constraints — read before designing

1. **Ciphertexts never go in calldata.** A degree-16384 ciphertext is
   megabytes. The chain carries 32-byte handles and commitments
   (`keccak256` of the serialized ciphertext); ciphertext bytes live in
   the coprocessor's store. An input ciphertext (a transfer amount) is
   registered with the coprocessor first (off-chain call), which
   returns a handle + commitment the user then passes in the
   transaction. Document this transport split explicitly — it is the
   fhEVM input-handle model, not a shortcut.
2. **The chain is the source of truth for ordering and authorization;
   the coprocessor is the source of truth for encrypted state.** Every
   state transition must be attributable to exactly one on-chain
   request event, and fulfillments must be applied in request order.
   No coprocessor-initiated state changes.
3. **Honest trust model, documented in the coprocessor's module docs:**
   v1's coprocessor is a *trusted executor* (it could decrypt nothing
   — the committee is still N-of-N — but it could censor or reorder).
   Do not invent fraud proofs, attestations, or staking. Name the gap;
   don't fill it.
4. **No new cryptography and no consensus machinery.** The committee
   stays the in-process `fhe::gateway::Committee` inside the
   coprocessor. Networked MPC between separate committee processes is
   its own future goal.
5. **Additive only.** No changes to existing `fhe::token` /
   `fhe::gateway` public API behavior; Goal D and Goal E test suites
   pass unmodified. The coprocessor composes the existing extensions —
   if a semantic cannot be built from their public API plus the
   documented internal seams, stop and surface it.

## The task

1. **Contract** (`contracts/` via Foundry, or `forge` project under a
   new top-level dir; match repo layout conventions): the
   `ConfidentialTokenGateway` above, with per-extension entry points
   gated exactly as the Rust extensions gate them (agent role for
   pause/block/freeze/force/recover, identity registry for recipients,
   open `setObserver` for one's own account only — `msg.sender` IS the
   account, which closes the Goal E caveat about unauthenticated
   `set_observer`). Public policy rejections revert on-chain (cheap,
   public, before any coprocessor work — the same "public checks stay
   public" rule as Goal E).
2. **Coprocessor**: event-driven loop over anvil websocket
   (`alloy`): decode request event → execute the mapped
   `fhe::token::extensions` call → store new ciphertexts → submit
   fulfillment tx with new handles + commitments. Idempotent per
   request id; crash-and-restart replays from the last fulfilled event.
3. **Input registration API**: the off-chain path by which a user
   submits an encrypted amount (serialized `FheUint64`) and receives
   `(handle, commitment)`; the contract accepts only registered
   commitments.
4. **Decryption/read path**: `balanceHandle(account)` on-chain; the
   ACL check for `decrypt_for` driven by on-chain state (owner,
   observer grants) so that a read permission granted by an on-chain
   transaction is the one the coprocessor enforces.
5. **End-to-end validation** (`tests/onchain_e2e.rs`, `#[ignore]`d if
   `anvil` is absent — detected, not hardcoded): spin anvil, deploy,
   then run the Goal E lifecycle entirely through signed transactions
   from distinct keys: wrap, set observer (and prove a *different*
   sender cannot set someone else's observer — the new auth actually
   binds), freeze, transfer over/under available, block + revert,
   pause/unpause, force transfer, recover, unwrap — asserting after
   every fulfillment that (a) on-chain handles rotated as evented,
   (b) coprocessor decryptions match the plaintext reference model,
   (c) supply conservation holds across the boundary, and (d) the
   Goal D/E leakage sweeps still pass over the coprocessor's audit
   logs.

## Checkpoint gates — commit per gate, in order

`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and
(for contract gates) `forge test` clean repeat in every gate.

**G1 — scaffolding.** Foundry project + contract skeleton compiles;
anvil spins up in a test harness; a Rust test deploys the contract via
`alloy` and round-trips one event (request emitted → decoded in Rust →
fulfillment tx → state read back). No FHE yet.

**G2 — input registration + handle anchoring.** Registered ciphertext
→ `(handle, commitment)`; contract rejects unregistered commitments
(test); commitment recomputed from stored bytes matches (test);
tampered bytes detected (test).

**G3 — core transfer via transaction.** A signed `transfer(to, handle)`
tx → coprocessor fulfillment → on-chain handles rotated, balances
decrypt to the reference, insufficient funds is the same silent-zero
(the *fulfillment* succeeds; nothing on-chain distinguishes it — test
pins this, including gas-shape equality of the two fulfillments).
Sender authentication: a tx from a key not bound to the `from` account
reverts (test).

**G4 — extension entry points.** Each Goal E extension drivable by tx
with contract-side gating proven by revert tests per role/policy, and
the encrypted semantics proven by decryption against the reference
(freeze → over-available transfer zeroes; recover carries frozen
encrypted; unwrap reveals amount and credits the public ERC20-side
balance — pick the contract-side public representation and document
it).

**G5 — e2e + ops.** `tests/onchain_e2e.rs` full lifecycle as above;
coprocessor crash-restart mid-lifecycle resumes correctly (test);
README or `docs/` section describing the architecture, the transport
split, and the v1 trust model; BENCHMARKS.md gains a
"request-tx → fulfillment-tx" latency table for transfer and freezable
transfer (CPU and CUDA), measured by the e2e harness.

## Verification requirements

- All gate tests pass via `cargo test --workspace --release` (chain
  tests self-skip with a loud message when `anvil` is missing) and
  `forge test`.
- `cargo test -p fhe --release --features cuda` still green.
- Goal D and Goal E test files unmodified.
- The trust-model documentation states exactly what the coprocessor
  can and cannot do, and the censorship/reordering gap is named.

## Rules

- Public checks stay public: policy gating lives in the contract and
  reverts; encrypted guards live in the coprocessor and never revert.
  Do not blur this line in either direction.
- No invented cryptography, no consensus machinery, no networked MPC.
- The chain layer must not weaken any Goal D/E leakage claim: the
  coprocessor's audit logs remain the leakage record, and the e2e
  re-runs the existing sweeps over them.
- Honest failure modes: if `alloy`/Foundry friction forces a scope cut
  (e.g. websocket vs polling), document the cut in the gate's commit
  message rather than silently downgrading.
- Commit per gate with clear messages.
