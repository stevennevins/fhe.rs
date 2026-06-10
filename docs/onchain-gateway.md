# On-chain gateway: driving the confidential token kit by transaction

Goals D and E built an in-process confidential token kit
(`fhe::token::ConfidentialToken` plus the ERC7984 extension suite in
`fhe::token::extensions`) with `Account = u64` and the documented caveat
that caller authenticity is "the embedding application's problem". This
deployment IS that embedding application, in the fhEVM shape:

- **The chain** (`contracts/src/ConfidentialTokenGateway.sol`, a Foundry
  project run on a local anvil devnet) holds 32-byte ciphertext
  **handles**, keccak256 **commitments** to the ciphertext bytes, and all
  **public** access-control state: the agent role, pause, the blocklist,
  the identity registry, observer assignments, public ERC20-side
  balances, and the request/fulfillment cursor.
- **The coprocessor** (`crates/fhe-coprocessor`) holds the ciphertexts
  and the in-process N-of-N threshold committee
  (`fhe::gateway::Committee`), subscribes to the contract's request
  events over the anvil websocket via `alloy`, executes the mapped
  `fhe::token` / `fhe::token::extensions` operation, and posts the
  resulting handles and commitments back in one fulfillment transaction
  per request.

`msg.sender` is the authenticated caller: the coprocessor binds each
address to a kit account on first sight, which closes the kit's
no-signature-checking gap. In particular `setObserver` has no account
parameter at all — a transaction can only set its **own** sender's
observer, closing the Goal E caveat about unauthenticated
`set_observer`.

## Public checks stay public

Role checks (agent/freezer) and public policy (pause, blocklist,
identity verification of recipients, public-balance sufficiency for
wraps) are enforced **in the contract** and revert — cheaply, publicly,
before any coprocessor work. Encrypted guards (balance and frozen-amount
sufficiency) run **in the coprocessor** and never revert: an
insufficient transfer fulfills with exactly the same transaction shape
as a successful one, and the G3 test pins that the two fulfillments'
execution gas is equal (only the EIP-2028 calldata pricing of the random
handle bytes differs). The coprocessor re-checks the mirrored public
policy through the kit's own `Rwa` extension; this is redundant by
construction (the mirror is fed only by the chain's own events) and
exists because the coprocessor composes the existing extensions rather
than re-implementing their circuits.

## The transport split (input registration)

Ciphertexts never enter calldata: a degree-16384 ciphertext is megabytes
and the chain carries only 32-byte values. A user submits an encrypted
amount (a serialized `FheUint64`) to the coprocessor **off-chain**
(`Client::encrypt_input`, which encrypts, registers, and anchors),
which validates it against the deployment parameters, stores the bytes,
anchors `(handle, commitment = keccak256(bytes), owner)` on-chain with
`registerInput`, and returns the handle. The user's transaction then
carries only the handle; the contract accepts only anchored handles
spent by their owner. This is the fhEVM input-handle model, not a
shortcut. The anchoring transaction is sent by the coprocessor but is
not a state transition of the token — it publishes which ciphertext a
future request may refer to.

Every fulfillment likewise posts the keccak256 commitment of each new
ciphertext alongside its handle, so the chain anchors the entire
encrypted state: recomputing the commitment from the coprocessor's
stored bytes must match the chain (tested), and tampered store bytes are
detected before any use (tested).

## Ordering and attributability

The chain is the source of truth for ordering and authorization; the
coprocessor is the source of truth for encrypted state. Every
state-changing entry point assigns a strictly increasing request id and
records `keccak256(op, payload)`. Fulfillments are coprocessor-only,
must arrive **in request order** (`lastFulfilledId + 1`), and must
recompute the recorded hash from their own arguments — so every
encrypted state transition is attributable to exactly one on-chain
request, and the coprocessor cannot reorder, skip, or invent
transitions. Requests with no confidential state (faucet credits,
observer/verify/block/pause changes, which take effect on-chain
immediately) are acknowledged with `fulfillAck` so the cursor still
advances one fulfillment per request.

Crash recovery: `lastFulfilledId` is the durable resume cursor. A
restarted service replays the contract's event log from genesis, skips
everything at or below the cursor, and resumes in order — idempotent per
request id (tested in `tests/crash_restart.rs`).

## Trust model (v1) — what the coprocessor can and cannot do

The coprocessor is a **trusted executor**:

- It **cannot decrypt anything unilaterally.** The committee inside it
  is N-of-N multiparty BFV; this deployment adds no new cryptography and
  no consensus machinery, and the committee's leakage profile is
  unchanged from Goals D/E (the e2e re-runs the Goal D/E single-party
  leakage sweeps over the coprocessor's audit logs).
- It **cannot fabricate or reorder state transitions** on-chain: the
  contract binds each fulfillment to the hash of exactly one request, in
  order.
- It **can censor and stall**: nothing forces it to fulfill at all, and
  by stalling it delays everything after the stalled request (ordering
  is strict). It is also the sole holder of the ciphertext store, so
  losing that store is a liveness (not confidentiality) loss.

That censorship/stalling gap is **named, not filled**: v1 has no fraud
proofs, attestations, or staking, deliberately.

Known v1 scope cuts, also deliberate:

- The coprocessor's durable state (token, extensions, ciphertext store,
  address↔account binding) lives in memory and is handed to a restarted
  event loop as a value; production would persist it. The
  crash-restart test exercises exactly this seam.
- The committee is in-process (`fhe::gateway::Committee`); networked MPC
  between separate committee processes is its own future goal.
- The decryption read path is an off-chain call
  (`Coprocessor::decrypt_for`) whose ACL is driven by on-chain state:
  ownership and observer grants accumulated from on-chain transactions
  decide who a handle decrypts for (tested: a read permission granted by
  an on-chain transaction is the one the coprocessor enforces, and a
  never-granted account is denied on every handle).

## What runs where, per entry point

| Entry point | Contract (reverts) | Coprocessor (never reverts) |
|---|---|---|
| `faucet` | credits `publicBalance` | mirrors the public ledger |
| `wrap` | public-balance check + debit | confidential mint (+ observer grant) |
| `transfer` | pause, blocklist, identity, input ownership | freezable double-guard transfer, observer grants |
| `setObserver` | own account only (`msg.sender`) | mirrors the observer registry |
| `setVerified` / `setBlocked` / `setPaused` | agent role; takes effect on-chain | mirrors policy state |
| `setConfidentialFrozen` | agent role, input ownership | stores the encrypted frozen amount |
| `forceTransfer` | agent role | core-circuit transfer (balance guard only) |
| `recover` | agent role | full-balance move, frozen carried as encrypted `min` |
| `requestUnwrap` | input ownership | threshold-decrypts the amount (by design), credits `publicBalance` on success via the fulfillment |

Latency of the request-tx → fulfillment-tx round trip is measured by the
e2e harness; see the "On-chain gateway" section of `BENCHMARKS.md`.
