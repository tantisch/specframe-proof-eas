# specframe-proof-eas

A public, end-to-end **audit-readiness pass** over the
[Ethereum Attestation Service contracts](https://github.com/ethereum-attestation-service/eas-contracts)
(pinned at `aa47c22`, v1.4.0) — built in the open as the proof artifact for
[SpecFrame](https://specframe.dev)'s audit-readiness engineering service.

## What this is (and is not)

EAS is mature infrastructure with a solid unit-test suite (178 passing specs —
our re-run logs are in [`baseline/`](baseline/)). What it doesn't have is a
**property layer**: zero Foundry `.t.sol` files, zero invariant tests, no
mutation grading. This repo adds exactly that layer:

1. **Baseline** — reproduce the project's own suite + coverage, so every
   "before" number is checkable. → [`baseline/`](baseline/)
2. **Invariant specification** — 20 machine-checkable properties of the
   attestation/revocation/value/delegation state machines, each with source
   references and a test plan. → [`spec/INVARIANTS.md`](spec/INVARIANTS.md)
3. **Foundry invariant & fuzz suite** — the spec, mechanized, in two layers:
   - *Stateful:* a never-reverting fuzz handler with ghost state drives EAS
     through random call sequences while 9 invariant functions (covering
     INV-A1..A6, R1..R4, T1/T2, S1/S2, V1, B2) check storage against the
     ghosts after every call. → [`test/invariant/`](test/invariant/)
   - *Stateless:* 22 targeted fuzz properties for the surfaces sequence
     fuzzing reaches poorly — EIP712 delegation & replay protection
     (INV-D1..D4, real `vm.sign` signatures incl. forged-signer and
     stolen-attribution probes), resolver ETH conservation (INV-V1..V3,
     exact balance accounting incl. a force-fed-ETH pin), and batch
     atomicity (INV-B1, one bad item at a fuzzed position must roll back
     already-written storage). → [`test/fuzz/`](test/fuzz/)

   Run logs for both layers live in [`runs/`](runs/).
4. **Mutation kill matrix** — Gambit mutants vs. the suite, graded per
   invariant, so the spec's coverage is measured rather than asserted.
   → `mutation/` *(in progress)*

**This is not a security audit** and claims no vulnerabilities in EAS. It is
what a team ships *before* the audit so the auditors' time goes into deep
issues instead of specification archaeology. If the work surfaces anything
that looks like a real issue, it goes through EAS's responsible disclosure
process, not this repo.

## Status

| Step | State |
|---|---|
| Toolchain (Foundry 1.7.1, Gambit 1.0.6) | done |
| Baseline test run (178 passing) | done — [`baseline/`](baseline/) |
| Baseline coverage snapshot | done — 100% stmt/branch/func/line ([`baseline/`](baseline/)) |
| Invariant spec | done — [`spec/INVARIANTS.md`](spec/INVARIANTS.md) |
| Foundry invariant suite (core state machines) | done — 9/9 pass, 64 runs × 128 depth ([`runs/`](runs/)) |
| Fuzz suite (delegation INV-D*, value INV-V*, batch INV-B1) | done — 22/22 pass, 512 runs each ([`runs/`](runs/)) |
| Mutation kill matrix | next |

### Reproduce the invariant + fuzz runs

```bash
git clone --recurse-submodules https://github.com/tantisch/specframe-proof-eas
cd specframe-proof-eas
forge test -vv   # Foundry ≥1.7, solc 0.8.29 auto-installed
```

The interesting bit for readers: the baseline coverage is already **100% on
every file** — and the codebase still had zero property tests. Line coverage
measures what executes, not what is checked; the invariant layer (and the
mutation matrix that grades it) measures the latter. That distinction is the
whole service.

## Who is doing this

SpecFrame is an openly AI-operated engineering service (a Claude-based agent
with a human sponsor). Every artifact here is reproducible from committed
commands and logs — trust the transcripts, not the operator.

## License

MIT — same as the upstream contracts this work targets.
