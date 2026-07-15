# EAS Invariant Specification

**Target:** [ethereum-attestation-service/eas-contracts](https://github.com/ethereum-attestation-service/eas-contracts)
at commit `aa47c22642d13d814993aa8c8a25a8ba59d795f7` (2026-05-18), Solidity 0.8.29, protocol v1.4.0.

**Scope:** `EAS.sol`, `SchemaRegistry.sol`, `EIP1271Verifier.sol`, and the
`SchemaResolver` interaction surface. Out of scope for this pass: `Indexer.sol`,
`EIP712Proxy` and the example resolvers (they are integration surface, not core
state machines).

**What this document is:** every property below is a statement the contracts
are *supposed* to keep true across any sequence of calls by any actors. Each
gets encoded as a Foundry invariant/property test in `test/`, then the whole
suite is graded with mutation testing (Gambit): a mutant that survives means a
property gap, a mutant killed means the spec has teeth. IDs are stable and
referenced from the test suite and the kill matrix.

**Honesty note:** EAS is a mature, well-unit-tested codebase (its Hardhat suite
passes 178 specs; see `baseline/`). What it does not have is a
property/invariant layer — zero `.t.sol` files, zero `invariant` tests. This
spec adds that layer. Finding actual bugs is *not* the claim; making the
intended behavior explicit, machine-checked, and mutation-graded is.

Notation: `A = _db[uid]` is the stored attestation for `uid`; `S = registry[schemaUID]`
is a schema record. "Ghost" variables are bookkeeping the test harness tracks
across calls.

---

## 1. Attestation storage & UID integrity

### INV-A1 — UID uniqueness (no silent overwrite)
Once `_db[uid]` is non-empty, it is never written again. Two attestations never
share a UID, even when all UID-hash inputs collide (the `bump` loop,
`EAS.sol:449-462`, must find a fresh slot).
*Test:* ghost set of all UIDs returned by every `attest*` call; assert no
duplicates and `getAttestation(uid)` matches the ghost record forever after.
*Why it matters:* UIDs are the foreign key the entire ecosystem (indexers,
resolvers, referenced attestations) hangs off.

### INV-A2 — UID is content-derived
For every stored attestation, `uid == keccak256(schema, recipient, attester,
time, expirationTime, revocable, refUID, data, bump)` for some `bump ≥ 0`
(`EAS.sol:696-711`), and `A.uid == uid` (self-consistency of the stored struct).
*Test:* recompute the hash from the stored fields for bumps 0..k.

### INV-A3 — Attestation immutability (single mutable field)
After creation, every field of `A` except `revocationTime` is frozen forever.
`revocationTime` changes at most once, from `0` to a nonzero value.
*Test:* ghost snapshot at creation; compare after every subsequent call in the
sequence.

### INV-A4 — No attestation without a registered schema
`A.schema` always refers to a schema with `S.uid != 0` at attestation time
(`EAS.sol:414-418`). Since schemas are never deleted (INV-S2), this holds
permanently: no stored attestation ever points at an unregistered schema.

### INV-A5 — Reference integrity (with the intra-batch nuance)
If `A.refUID != 0`, then `_db[A.refUID]` exists. Note the implementation order:
the new attestation is written to `_db` *before* the refUID existence check
(`EAS.sol:464-471`), which deliberately legitimizes batch item *i* referencing
batch item *j < i* created in the same `multiAttest` call — and would even
accept a self-reference if `uid == refUID` were constructible (it is not: that
is a keccak fixed point). The invariant as tested: after any completed
top-level call, every nonzero `refUID` in storage resolves to a valid
attestation.

### INV-A6 — Time sanity
`A.time` equals the block timestamp of the creating transaction;
`A.expirationTime` is either `0` (never expires) or `> A.time` at creation
(`EAS.sol:427-429`); if revoked, `A.revocationTime ≥ A.time`.

## 2. Revocation semantics

### INV-R1 — Only the attester revokes
A successful on-chain revocation of `uid` implies the caller (or the verified
delegated signer) is exactly `A.attester` (`EAS.sol:525-528`). Recipient,
schema owner, resolver — nobody else can ever set `revocationTime`.

### INV-R2 — Irrevocability is permanent and schema-inherited
If `S.revocable == false`, every attestation under `S` has
`A.revocable == false` (`EAS.sol:431-434`), and no attestation with
`A.revocable == false` is ever revoked (`EAS.sol:532-534`). Corollary tested:
`A.revocable == true` ⟹ `S.revocable == true`.

### INV-R3 — Revocation is single-shot and terminal
`revocationTime` transitions `0 → t` at most once (`EAS.sol:536-540`); a second
revoke of the same UID always reverts (`AlreadyRevoked`). There is no
un-revoke.

### INV-R4 — Revocation requires the correct schema handle
Revoking `uid` via schema argument `s` succeeds only if `A.schema == s`
(`EAS.sol:520-523`) — no cross-schema revocation.

## 3. Timestamping & off-chain revocation registries

### INV-T1 — Write-once timestamps
`_timestamps[data]` transitions `0 → t` at most once (`EAS.sol:727-735`);
re-timestamping reverts. Same for per-revoker off-chain revocations:
`_revocationsOffchain[r][data]` is write-once *per revoker r*
(`EAS.sol:741-751`), while distinct revokers stay independent.

### INV-T2 — Recorded time is honest
Any nonzero stored timestamp equals the block timestamp of the transaction
that set it (checked via ghost recording; `multiTimestamp` gives all items of
one call the identical time, `EAS.sol:364-373`).

## 4. Value conservation (the resolver ETH path)

### INV-V1 — EAS never retains ETH
After any external call completes, `address(eas).balance` is unchanged from
before the call (canonically 0). Every wei of `msg.value` either reaches
schema resolvers or is refunded to `msg.sender` (`EAS.sol:559-690, 713-722`).
*Test:* invariant handler with payable attest/revoke/multi variants against
payable and non-payable resolvers; assert
`sum(resolver deltas) + refund == msg.value` per call and `eas.balance == 0`
as a global invariant (modulo force-fed ETH, which we test separately: the
comment at `EAS.sol:122-125` explains the `availableValue` ratchet exists
precisely so stuck ETH can never become spendable headroom — it starts at
`msg.value`, so a request for `value > msg.value` reverts `InsufficientValue`
even when the contract balance could cover it, and force-fed ETH never moves.
Verified in `test/fuzz/ValueConservation.t.sol::testFuzz_V1_forceFedEth_isNotSpendable`;
an earlier draft of this spec misread the comment as conceding the opposite).

### INV-V2 — No payment without a payable destination
If `S.resolver == address(0)` or `resolver.isPayable() == false`, any request
with `value != 0` reverts (`EAS.sol:568-579, 582-585, 656-663`). Money can
never be sent into the void.

### INV-V3 — Batch value accounting never over-spends
Across `multiAttest`/`multiRevoke` batches, the sum of values forwarded to
resolvers never exceeds `msg.value` (the `availableValue` ratchet,
`EAS.sol:126-154, 586-595, 665-675`), and any remainder is refunded exactly
once, on the last batch only.

## 5. Delegation & replay protection (EIP1271Verifier)

### INV-D1 — Nonce strict monotonicity
`getNonce(a)` never decreases, for any account, under any call mix
(`_verifyAttest`/`_verifyRevoke` post-increment, `EIP1271Verifier.sol:116,150`;
`increaseNonce` requires strictly higher, `EIP1271Verifier.sol:83-92`).

### INV-D2 — No signature replay
A given (signer, signed-payload) pair is consumed at most once: after a
delegated attest/revoke succeeds with nonce `n`, resubmitting the identical
signature always reverts (the nonce embedded in the digest has moved).
`increaseNonce` invalidates all signatures signed under lower nonces.

### INV-D3 — Attribution is signer-exact
A delegated attestation stores `A.attester == request.attester` (the signature
subject), never `msg.sender` (the relayer) (`EAS.sol:103-112`). Corollary:
only `request.attester`'s valid signature can create attestations attributed
to them; delegated revocation authorization is likewise checked against the
signer, not the relayer.

### INV-D4 — Deadline enforcement
A delegated request with `deadline != 0` and `deadline < block.timestamp`
always reverts (`EIP1271Verifier.sol:97-99,135-137`), and an expired-deadline
attempt does *not* burn a nonce (revert rolls back the increment).

## 6. Schema registry

### INV-S1 — Schema UID is content-derived and collision-checked
`register` derives the UID from `(schema, resolver, revocable)`
(`SchemaRegistry.sol:52-54`) and reverts on an existing UID
(`SchemaRegistry.sol:32-34`): identical triples cannot be registered twice;
distinct triples always can, by anyone (permissionless).

### INV-S2 — Schema records are immutable and eternal
Once registered, a `SchemaRecord`'s fields never change and the record is
never deleted. There is no admin, no upgrade hook, no unregister path.
*Test:* ghost snapshot at registration, compared after arbitrary call
sequences.

## 7. Atomicity (batch calls)

### INV-B1 — All-or-nothing batches
If any item in a `multiAttest`/`multiRevoke` (delegated or not) reverts, the
entire transaction reverts: storage shows either all items applied or none.
*Test:* inject one failing item (bad schema, expired time, wrong signer,
unfunded value) at a random position; assert zero state delta.

### INV-B2 — Batch/single equivalence
A `multiAttest` of n items leaves the same end state (modulo UIDs' `time`
equality within one block) as n sequential `attest` calls with the same data —
and returns UIDs in request order (`_mergeUIDs`, `EAS.sol:757-775`).

---

## Planned mechanization

| Layer | Tool | Deliverable |
|---|---|---|
| Handler-based invariant suite (INV-A*, R*, T*, V*, S*) | Foundry `invariant` tests + ghost state | `test/invariant/` |
| Stateless property tests (INV-D*, B*, edge reverts) | Foundry fuzz tests | `test/fuzz/` |
| Spec grading | Gambit mutants over `EAS.sol`/`SchemaRegistry.sol`/`EIP1271Verifier.sol` → kill matrix per invariant ID | `mutation/` |

Every claim in the eventual report links back to a runnable command and a
committed log.
