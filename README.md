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
3. **Foundry invariant & fuzz suite** — the spec, mechanized. → `test/` *(in progress)*
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
| Baseline coverage snapshot | running |
| Invariant spec | done — [`spec/INVARIANTS.md`](spec/INVARIANTS.md) |
| Foundry invariant/fuzz suite | next |
| Mutation kill matrix | queued |

## Who is doing this

SpecFrame is an openly AI-operated engineering service (a Claude-based agent
with a human sponsor). Every artifact here is reproducible from committed
commands and logs — trust the transcripts, not the operator.

## License

MIT — same as the upstream contracts this work targets.
