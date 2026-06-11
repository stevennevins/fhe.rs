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

### fhEVM concept mapping

| fhEVM concept | This kit |
|---|---|
| `createEncryptedInput(...).add64(v).encrypt()` | `client.encrypt_input(v)` — encrypts under the committee key, registers the ciphertext with the coprocessor, anchors `(handle, commitment, owner)` on-chain |
| input handle (`input.handles[0]`) | the `B256` handle `encrypt_input` returns; spendable on-chain only by its owner |
| input proof (`input.inputProof`) | **deliberately absent** — TODO-by-trust-model: the coprocessor validates inputs against the deployment parameters when it registers them, and v1 trusts it as executor; a ZK proof of plaintext knowledge is future work |
| `confidentialTransfer(to, handle, proof)` | `client.transfer(to, input)` (contract entry point `confidentialTransfer(to, amountHandle)`) |
| `confidentialBalanceOf(account)` (returns an `euint64` handle) | the contract's `confidentialBalanceOf(account)` (returns the `bytes32` handle) |
| ACL allow (`FHE.allow(...)`) | ownership and observer grants accumulated from on-chain transactions; enforced by the coprocessor's read path |
| user decryption (`fhevm.userDecrypt(...)`) | `client.balance(account)` / `client.frozen(account)` — threshold-decrypts through the ACL, errors cleanly when not granted |
| decryption oracle callback | the request/fulfillment cycle: every entry point emits a request event; the operator posts one bound fulfillment transaction per request, in order |
| symbolic execution on ciphertext handles | none — each request maps to one `fhe::token` operation executed by the coprocessor |
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
| `confidentialTransfer` | pause, blocklist, identity, input ownership | freezable double-guard transfer, observer grants |
| `setObserver` | own account only (`msg.sender`) | mirrors the observer registry |
| `setVerified` / `blockUser`/`unblockUser` / `pause`/`unpause` | agent role; takes effect on-chain | mirrors policy state |
| `setConfidentialFrozen` | agent role, input ownership | stores the encrypted frozen amount |
| `forceConfidentialTransferFrom` | agent role | core-circuit transfer (balance guard only; unlike OZ, moves frozen funds too — see below) |
| `recover` | agent role | full-balance move, frozen carried as encrypted `min` |
| `unwrap` | input ownership | threshold-decrypts the amount (by design), credits `publicBalance` on success via the fulfillment |

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
