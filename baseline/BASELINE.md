# EAS eas-contracts — "BEFORE" baseline snapshot

Captured: 2026-07-15 ~01:15 UTC on this VPS.
Repo: github.com/ethereum-attestation-service/eas-contracts
Commit: aa47c22642d13d814993aa8c8a25a8ba59d795f7 (2026-05-18, "Update node to 24")
License: MIT. Package: @ethereum-attestation-service/eas-contracts v1.9.0.

## Environment
- node v22.23.1, pnpm 11.13.0 (corepack), solc 0.8.29 via Hardhat
- Local-only deviation from upstream (NOT part of any claim): added
  pnpm-workspace.yaml with `allowBuilds: keccak, secp256k1` so pnpm 11
  runs the two native-module build scripts; package.json untouched.

## Code volume
- Production Solidity (contracts/, excluding contracts/tests/): 2,775 LOC
- Test-helper Solidity (contracts/tests/): present, excluded from coverage
  by upstream .solcover.ts (skipFiles: ['tests'])
- TypeScript tests (test/): 7,081 LOC

## Existing test suite ("before")
- `pnpm test` (Hardhat + Mocha): **178 passing, 0 failing**, ~50s
  Transcript tail: baseline/test-run-20260715.log (full run to be
  re-captured in the public proof repo's CI — that is the citable one)
- Foundry: foundry.toml exists, but **zero `*.t.sol` files** in the repo
- **Zero** occurrences of "invariant" in contracts/ or test/
- **Zero** occurrences of "fuzz" in test/
→ The gap is property-based/invariant/fuzz testing and mutation
  resistance, NOT unit-test count. All claims must be phrased that way:
  EAS is well unit-tested; it has no property-testing layer.

## Coverage ("before")
- `pnpm test:coverage` (solidity-coverage, upstream .solcover.ts):
  RESULTS PENDING — fill in from baseline/coverage-run-20260715.log
