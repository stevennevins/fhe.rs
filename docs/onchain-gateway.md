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

## Using the kit

Two roles, two types, mirroring fhEVM's dApp-SDK / operator split:

- **`fhe_coprocessor::Client`** — the user side. Encrypt-and-register
  inputs, send entry-point transactions (each call resolves when its
  request is fulfilled), read back what the ACL allows. A client
  cannot reach the committee, the ciphertext store, or threshold
  decryption — structurally, not by convention.
- **`fhe_coprocessor::Operator`** — the operator side. One constructor
  over the committee, `spawn()` for the live event loop,
  `run_until_idle()`/`run_until()` for deterministic tests, and a
  shutdown-and-handover seam (`into_state()`/`resume()`) for crash
  recovery.

The whole flow (`crates/fhe-coprocessor/examples/quickstart.rs` runs
exactly this against a local anvil; it is also the acceptance test for
the API's simplicity):

```rust
let operator = Operator::new(committee, agent, coprocessor_provider, gateway)?;
let alice = operator.client(alice_provider, alice_address).await;
let bob = operator.client(bob_provider, bob_address).await;
let operator = operator.spawn();

alice.faucet(1000).await?;          // public credit
alice.wrap(1000).await?;            // public -> confidential
let input = alice.encrypt_input(250).await?;   // encrypt, register, anchor
alice.transfer(bob_address, input).await?;     // resolves on fulfillment
let balance = alice.balance(alice_address).await?;  // ACL-checked decrypt
```

For building ON the kit rather than just using the token, `Client`
also exposes the composability surface (see "Composability" below):
`allow(handle, account)`, the symbolic ops
(`add`/`sub`/`ge`/`select`/`request_op`), atomic `batch(&[OpSpec])`,
and the generic ACL-checked `decrypt(handle)`.
`crates/fhe-coprocessor/examples/auction.rs` drives the worked
third-party contract (`contracts/src/examples/SealedBidAuction.sol`)
end to end.

### fhEVM concept mapping

| fhEVM concept | This kit |
|---|---|
| `createEncryptedInput(...).add64(v).encrypt()` | `client.encrypt_input(v)` — encrypts under the committee key, registers the ciphertext with the coprocessor, anchors `(handle, commitment, owner)` on-chain |
| input handle (`input.handles[0]`) | the `B256` handle `encrypt_input` returns; spendable on-chain only by its owner |
| input proof (`input.inputProof`) | **deliberately absent** — TODO-by-trust-model: the coprocessor validates inputs against the deployment parameters when it registers them, and v1 trusts it as executor; a ZK proof of plaintext knowledge is future work |
| `confidentialTransfer(to, handle, proof)` | `client.transfer(to, input)` (contract entry point `confidentialTransfer(to, amountHandle)`) |
| `confidentialBalanceOf(account)` (returns an `euint64` handle) | the contract's `confidentialBalanceOf(account)` (returns the `bytes32` handle) |
| ACL allow (`FHE.allow(...)`) | the contract's `allow(handle, account)` / `isAllowed(handle, account)` — public on-chain state written at every handle creation (ownership, observer grants) and extended by transaction with fhEVM's chain-of-custody rule; the coprocessor's read path enforces a mirror of exactly this state |
| user decryption (`fhevm.userDecrypt(...)`) | `client.balance(account)` / `client.frozen(account)` — threshold-decrypts through the ACL, errors cleanly when not granted |
| decryption oracle callback | the request/fulfillment cycle: every entry point emits a request event; the operator posts one bound fulfillment transaction per request, in order |
| symbolic execution on ciphertext handles | `requestOp` / `requestBatch` over a SMALL FIXED alphabet (`add`, `sub`, `ge`, `select`): result handles are derived on-chain before the ciphertext exists, so calls chain immediately; the coprocessor materializes them in request order (see "Composability" below) |
| KMS / threshold network | the in-process N-of-N `fhe::gateway::Committee` (networked MPC is a named future goal) |

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
  (`Coprocessor::decrypt_for`) whose ACL **is** the on-chain state: the
  contract's `isAllowed` mapping, written at every handle creation and
  by `allow` transactions, is mirrored into the coprocessor in request
  order and is the only authorization source the read path consults
  (tested: a read permission granted by an on-chain transaction is the
  one the coprocessor enforces, and a never-granted account is denied
  on every handle).

## Composability: the on-chain ACL and symbolic ops (Goal H)

Goals F/G made the kit easy to USE; this layer makes it possible to
BUILD ON: third-party encrypted logic without coprocessor changes,
atomic multi-step operations, cross-contract use of encrypted state,
and latency hiding (the request transaction confirms at chain speed;
the FHE compute pipelines behind it). `SealedBidAuction.sol` is the
worked proof: an auction settled over encrypted bids using ONLY
`allow`, `isAllowed`, and `requestBatch` — zero coprocessor code, zero
new gateway entry points.

### The on-chain ACL

`isAllowed(handle, account)` is public contract state. The contract
writes it at every handle creation — `registerInput` allows the owner;
balance rotations allow the account (plus the observer the request
saw); transfers allow both parties on the transferred amount; frozen
handles allow the account and the freezer; force transfers grant no
observers — and `allow(handle, account)` extends it with fhEVM's
chain-of-custody rule: only a caller already allowed on a handle may
grant further access. Observer grants use a snapshot taken at REQUEST
time, because the coprocessor mirrors observer state in request order
and `observerOf` can change between request and fulfillment.

`allow` rides the request/ack cycle like the other mirrored policy
state, so when a `Client::allow` call resolves, the grant is live in
the coprocessor's read path. Divergence from fhEVM, named: the ACL is
a gateway extension, not a separate ACL contract — the coprocessor
replays exactly one contract's event stream, and v1 gains nothing from
a second deployment. There is no `allowTransient` and no
`makePubliclyDecryptable`; grants are permanent and revocation does
not exist (matching the kit's "no retroactive revocation" observer
semantics).

### The two handle kinds, and how a reader tells them apart

1. **Anchor-at-mint handles** (encrypted inputs, token fulfillment
   outputs): opaque keccak values minted by the coprocessor, whose
   `handleCommitment` is posted in the SAME transaction that
   introduces them. These keep their Goal F derivation, unchanged.
2. **Symbolic result handles** (`requestOp`/`requestBatch` results):
   derived ON-CHAIN before the ciphertext exists, as
   `keccak256("fhe.rs/sym" ‖ op ‖ lhs ‖ rhs ‖ cond ‖ requestId ‖ opIndex)`
   with fhEVM-style trailing bytes written in — byte 21 = `0xff` (the
   FhevmHandle computed marker), byte 30 = the type tag (`ebool` = 0,
   `euint64` = 5), byte 31 = the version (0).

A reader distinguishes them by the trailing structure (an
anchor-at-mint handle has random trailing bytes; matching the marker,
tag, and version by chance is ~2^-24) — but the CONTRACT never does:
operand types come from a storage mapping written at derivation time,
never parsed out of handle bytes, so a 1-in-256 collision cannot
confuse consensus.

### The deferred-binding weakening, named

An anchor-at-mint handle is hash-bound to its ciphertext from the
moment the chain learns it. A symbolic handle is a PROMISE: its
`handleCommitment` is zero until the coprocessor's fulfillment posts
it. Between request and fulfillment the binding rests entirely on the
fulfillment transaction being coprocessor-signed — the chain cannot
detect a coprocessor that materializes a wrong ciphertext, only one
that breaks request order or the request hash. This is a real
weakening relative to Goal F's anchor-at-mint, accepted as the price
of chaining (callers compose on results that do not exist yet), and it
does not change WHO is trusted: the same v1 trusted executor, with the
same censor/stall powers, now also promises future ciphertexts.

### Symbolic ops and atomic batches

The alphabet is `add`, `sub`, `ge`, `select` — the smallest set that
expresses a guarded transfer, and its smallness is a feature (every op
is tested with reference and leakage assertions; there is no general
VM). Public checks revert in the contract: unknown op, wrong arity,
wrong operand type, an operand the caller is not allowed on (which
doubles as the existence check — every real handle has at least one
grant). Encrypted semantics never revert: a `select` over a failed
`ge` fulfills with the same shape as a successful one. `ge` operands
must be below 2^40 (the committee's comparison bound) — like the
kit's safe-math domain, a documented precondition on encrypted values
that cannot be checked. `ge` runs the committee's blinded-difference
comparison; its transcripts land in `Coprocessor::op_compares` and the
e2e sweeps them with the Goal D single-party-view assertions,
compositions included.

`requestBatch` carries an ordered op list — one request id, one
`fulfillBatch` posting every commitment (measured: both the request
and fulfillment sides cost roughly half the sequential gas at 8 ops).
Later ops reference earlier results positionally via `batchRef(i)`
markers, because result handles embed the request id, which an
off-chain builder cannot know; a contract calling `requestBatch` gets
the real handles back synchronously and may use either form. Batches
are bounded at `MAX_BATCH_OPS = 32` (pinned by a forge test) so
request and fulfillment gas stay predictable.

### Still deliberately absent

- **Input proofs** — unchanged TODO-by-trust-model from Goal F.
- **A networked committee** — the N-of-N stays in-process.
- **Arbitrary-contract FHE** — the alphabet is fixed and small; there
  is no bytecode-driven symbolic executor, no `allowTransient`, no
  public decryption. Each would change the trust or leakage story and
  is out of scope by design.

## What runs where, per entry point

| Entry point | Contract (reverts) | Coprocessor (never reverts) |
|---|---|---|
| `faucet` | credits `publicBalance` | mirrors the public ledger |
| `wrap` | public-balance check + debit | confidential mint (+ observer grant) |
| `confidentialTransfer` | pause, blocklist, identity, input ownership | freezable double-guard transfer, observer grants |
| `setObserver` | own account only (`msg.sender`) | mirrors the observer registry |
| `setVerified` / `blockUser`/`unblockUser` / `pause`/`unpause` | agent role; takes effect on-chain | mirrors policy state |
| `setConfidentialFrozen` | agent role, input ownership | stores the encrypted frozen amount |
| `forceConfidentialTransferFrom` | agent role | core-circuit transfer (balance guard only; unlike OZ, moves frozen funds too — see below) |
| `recover` | agent role | full-balance move, frozen carried as encrypted `min` |
| `unwrap` | input ownership | threshold-decrypts the amount (by design), credits `publicBalance` on success via the fulfillment |
| `allow` | chain of custody (caller must be allowed on the handle); takes effect on-chain | mirrors the grant into the read path |
| `requestOp` / `requestBatch` | op known, arity, operand types, caller allowed on every operand; derives the result handle(s) | executes the op(s) in request order, posts the deferred commitment(s) |

### Divergences from OZ ERC7984, named

The external surface follows OpenZeppelin's confidential-contracts
naming (`confidentialTransfer`, `confidentialBalanceOf`,
`confidentialFrozen`, `setConfidentialFrozen`, `wrap`/`unwrap`,
`blockUser`/`unblockUser`, `pause`/`unpause`, `isVerified`), with these
deliberate divergences:

- **`forceConfidentialTransferFrom` moves frozen funds.** OZ's version
  keeps the frozen guard (frozen tokens must be unfrozen first); the
  kit's `Rwa::force_transfer` bypasses it by design, and only the
  encrypted balance guard applies. Same name, different compliance
  semantics — flagged here and in the contract natspec.
- **`bytes32` handles instead of `externalEuint64 + inputProof`** —
  the transport split (see above); input proofs are the named
  TODO-by-trust-model.
- **No `confidentialTotalSupply`, operators
  (`confidentialTransferFrom`/`setOperator`), or token metadata** —
  supply is not tracked on-chain (the faucet is a test stand-in) and
  `msg.sender` IS the account, so operator-style delegation is out of
  scope.
- **`confidentialTransfer` reverts `NoBalance` for a never-funded
  sender** where OZ would silently zero; the kit requires an existing
  balance handle, and the revert (a public "never funded" signal) keeps
  the coprocessor from processing unfundable transfers.

Latency of the request-tx → fulfillment-tx round trip is measured by the
e2e harness; see the "On-chain gateway" section of `BENCHMARKS.md`.
