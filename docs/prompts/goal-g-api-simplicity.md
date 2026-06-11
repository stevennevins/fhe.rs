# Goal G: make the kit's tooling and contract API as simple as fhEVM's

## Prerequisite — read first

Do NOT start this goal unless Goal F (`docs/prompts/goal-f-onchain-transactions.md`
— `contracts/` + `crates/fhe-coprocessor`) is merged or on the branch
you are stacking on. Foundry (`anvil`, `forge`) must be on the machine
(check `anvil --version`; stop and surface it if missing). Read
`docs/onchain-gateway.md` and the Goal F tests before designing.

## Context and motivation

Goal F works, but its surface shows its construction. Compare the two
user flows for "transfer 100 confidentially":

**Zama fhEVM (the bar):**

```typescript
const input = await fhevm
  .createEncryptedInput(contractAddress, userAddress)
  .add64(100)
  .encrypt();
await token.confidentialTransfer(recipient, input.handles[0], input.inputProof);
const balance = await fhevm.userDecrypt(token.confidentialBalanceOf(user));
```

Three calls, one mental model: *build encrypted input → one
transaction → read back when you're allowed.*

**This kit today (Goal F):**

```rust
let ct = service.coprocessor().committee().encrypt(100, &mut rng).unwrap();
let (handle, _) = service.register_and_anchor(alice.address, &ct.to_bytes()).await.unwrap();
gateway.transfer(bob.address, handle).send().await.unwrap().get_receipt().await.unwrap();
service.catch_up().await.unwrap();
let h = gateway.balanceHandle(alice.address).call().await.unwrap();
let balance = service.coprocessor_mut().decrypt_for(h, alice.address).unwrap();
```

Six steps, three different objects (`Service`, `Coprocessor`, the raw
`alloy` instance), the user threads an `rng`, serializes ciphertexts by
hand, and must know which object owns which half. The Goal F tests
paper over this with `exec!`/`input!`/`balance!` macros — every macro a
test needed is an API the library is missing. The product goal: a
developer integrating this kit writes code as simple as the fhEVM
snippet, without learning the internals.

This goal is about SUBTRACTION and packaging, not new features. The
protocol (request events, ordered fulfillments, commitments, the trust
model) does not change.

## Critical constraints — read before designing

1. **No new cryptography, no protocol changes.** The contract's
   request/fulfillment protocol, the transport split, the trust model,
   and every Goal F security property stay exactly as documented in
   `docs/onchain-gateway.md`. This is an API layer, not a redesign —
   if simplifying the surface seems to require weakening a Goal F
   test, stop and surface it.
2. **`fhe::token` / `fhe::gateway` public API stays frozen.** Goal D/E
   test files unmodified, as in Goal F.
3. **`fhe-coprocessor` is unpublished (`publish = false`) and MAY break
   its API.** Renames, merges, and deletions there are in scope —
   prefer deleting a public item over documenting why it's awkward.
   The Goal F tests may be rewritten against the new surface, but every
   ASSERTION they make must survive (same coverage, simpler harness);
   the e2e's reference model, leakage sweeps, gas-shape equality, and
   crash-restart semantics are non-negotiable.
4. **Two-role split, two types.** fhEVM separates the dApp-side SDK
   from the operator-side infrastructure. Mirror that: one USER-facing
   client (encrypt-and-register inputs, send entry-point transactions,
   read/decrypt what the ACL allows — no committee, no `Coprocessor`
   access) and one OPERATOR-facing service (the event loop + durable
   state). A user of the client type must be structurally unable to
   reach `threshold_decrypt` or the ciphertext store.
5. **Simplicity is measured, not asserted.** Define the metric up
   front: the quickstart example must drive wrap → transfer → read in
   ≤ 10 client calls with zero `unwrap`-chained alloy plumbing, zero
   manual serialization, zero `rng` parameters, and no `mut` access to
   coprocessor internals. Count before/after public items
   (`cargo doc` item count or similar) for `fhe-coprocessor` and
   report both numbers in the PR; the number must go down or every
   addition must be justified in the PR description.

## The task

1. **User client** (`fhe-coprocessor::client` or a small new crate if
   cleaner): the fhEVM-shaped flow —
   `client.encrypt_input(100).await?` (builds, registers, anchors,
   returns the handle), `client.transfer(to, input).await?` (sends the
   tx AND waits for the fulfillment event — the request id is in the
   receipt, the fulfillment event is the completion signal),
   `client.balance(account).await?` (reads the on-chain handle and
   decrypts through the read path, erroring cleanly when the ACL says
   no). Every entry point of the gateway gets one method; rng and
   serialization live inside. Waiting-for-fulfillment must be
   event-driven (subscribe before send), not polling.
2. **Operator service**: collapse the `Service` / `Coprocessor` split
   the tests currently juggle into one constructor and one `run`
   surface (`spawn`/`run_until_idle`/shutdown-and-handover for the
   crash test). `Coprocessor::new(committee, params, agent)` taking
   `params` the committee already knows is the kind of seam to remove
   — if `Committee` needs a `params()` accessor, that is a frozen-API
   exception to surface and justify, not silently add.
3. **Contract ergonomics pass**: revisit `ConfidentialTokenGateway`'s
   external surface against ERC7984 naming (`confidentialTransfer`,
   `confidentialBalanceOf`, ...) so a Solidity developer reading the
   OZ confidential-contracts docs recognizes it. Keep the
   request/fulfillment internals as they are. Any rename must update
   the forge tests, the `sol!` bindings, and `docs/onchain-gateway.md`
   together.
4. **Quickstart**: `crates/fhe-coprocessor/examples/quickstart.rs` —
   spin anvil, deploy, start the operator, then the fhEVM-shaped user
   flow, printed step by step. This example IS the acceptance test for
   constraint 5; it also self-skips loudly without Foundry.
5. **Docs**: `docs/onchain-gateway.md` gains a "Using the kit" section
   that walks the quickstart and a table mapping each fhEVM concept
   (encrypted input, handle, ACL allow, user decryption, callback) to
   this kit's equivalent — including what this kit deliberately does
   NOT have (input proofs are TODO-by-trust-model: name it).

## Checkpoint gates — commit per gate, in order

`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
(stable), `forge test`, and `cargo test --workspace --release` repeat
clean in every gate.

**G1 — client.** The user client exists; the Goal F G3 transfer test
rewritten against it (same assertions, no macros, no direct
`Coprocessor` access from the user side).

**G2 — operator.** The unified operator surface; crash-restart test
rewritten against the handover seam; Goal F G4 extensions test
rewritten with client + operator only.

**G3 — contract naming.** ERC7984-aligned external surface; forge
tests, bindings, and docs updated in the same commit; e2e still green.

**G4 — quickstart + docs + counts.** The example runs CPU and CUDA;
docs section lands; before/after public-item counts in the commit
message; BENCHMARKS latency numbers re-measured if the client path
changed them (it should not — say so explicitly if confirmed).

## Verification requirements

- All Goal F assertions survive in the rewritten tests (diff the
  assertion lines, not just the test names) and the production-param
  e2e passes CPU and CUDA.
- Goal D and Goal E test files unmodified; `cargo test -p fhe
  --release --features cuda` still green.
- The quickstart example compiles in the doc-tested or example-built
  path of CI (`cargo test --workspace` builds examples).
- The PR description shows the before/after flow snippets (like the
  two blocks above) and the public-item counts.

## Rules

- Subtraction first: prefer deleting/merging public items over adding
  wrappers on top of the old surface. The old `Service`/`Coprocessor`
  split must not survive as a deprecated layer.
- The client must not be able to decrypt what the ACL forbids — keep
  the test proving a non-granted account is denied.
- Public checks stay public, encrypted guards never revert — the
  simplified API must not blur Goal F's line (e.g. the client's
  `transfer` resolving a silent-zero must look IDENTICAL to a
  successful one; only decryption reveals the difference).
- Honest failure modes: if alloy ergonomics force a scope cut
  (e.g. polling instead of event-driven completion), document it in
  the gate's commit message rather than silently downgrading.
- Commit per gate with clear messages.
