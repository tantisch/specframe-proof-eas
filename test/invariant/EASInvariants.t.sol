// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { Test } from "forge-std/Test.sol";

import { EAS } from "@eas/EAS.sol";
import { SchemaRegistry } from "@eas/SchemaRegistry.sol";
import { SchemaRecord } from "@eas/ISchemaRegistry.sol";
import { ISchemaResolver } from "@eas/resolver/ISchemaResolver.sol";
import { Attestation, EMPTY_UID, NO_EXPIRATION_TIME } from "@eas/Common.sol";

import { EASHandler } from "./handlers/EASHandler.sol";

/// @notice Handler-based invariant suite for EAS.
/// Invariant IDs refer to spec/INVARIANTS.md; every assertion message carries
/// the ID so a failed run (or a killed mutant in the mutation matrix) maps
/// straight back to the spec.
contract EASInvariants is Test {
    SchemaRegistry internal registry;
    EAS internal eas;
    EASHandler internal handler;

    function setUp() public {
        registry = new SchemaRegistry();
        eas = new EAS(registry);
        handler = new EASHandler(registry, eas);

        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = EASHandler.warp.selector;
        selectors[1] = EASHandler.registerSchema.selector;
        selectors[2] = EASHandler.registerDuplicateSchema.selector;
        selectors[3] = EASHandler.attest.selector;
        selectors[4] = EASHandler.multiAttest.selector;
        selectors[5] = EASHandler.revoke.selector;
        selectors[6] = EASHandler.revokeAsStranger.selector;
        selectors[7] = EASHandler.revokeWrongSchema.selector;
        selectors[8] = EASHandler.timestampData.selector;
        selectors[9] = EASHandler.revokeOffchain.selector;
        selectors[10] = EASHandler.revokeOffchain.selector; // double weight: cheap probe
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
        targetContract(address(handler));
    }

    /// INV-A1 + INV-A2 + INV-A3: every UID the handler ever received still
    /// resolves to exactly the snapshot taken at creation (revocationTime is
    /// the single mutable field), the stored struct is self-consistent, and
    /// the UID is content-derived from the stored fields.
    function invariant_A1_A2_A3_attestations_match_creation_snapshot() public view {
        uint256 n = handler.uidCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 uid = handler.uids(i);
            EASHandler.GhostAttestation memory g = handler.ghostOf(uid);
            Attestation memory a = eas.getAttestation(uid);

            assertEq(a.uid, uid, "INV-A2: stored struct uid != lookup uid");
            assertEq(a.schema, g.schema, "INV-A3: schema mutated");
            assertEq(a.time, g.time, "INV-A3: time mutated");
            assertEq(a.expirationTime, g.expirationTime, "INV-A3: expirationTime mutated");
            assertEq(a.refUID, g.refUID, "INV-A3: refUID mutated");
            assertEq(a.recipient, g.recipient, "INV-A3: recipient mutated");
            assertEq(a.attester, g.attester, "INV-A3: attester mutated");
            assertEq(a.revocable, g.revocable, "INV-A3: revocable mutated");
            assertEq(keccak256(a.data), keccak256(g.data), "INV-A3: data mutated");

            // INV-A2: uid == keccak(fields, bump) for some small bump
            bool derived = false;
            for (uint32 bump = 0; bump < 16; bump++) {
                if (
                    keccak256(
                        abi.encodePacked(
                            a.schema,
                            a.recipient,
                            a.attester,
                            a.time,
                            a.expirationTime,
                            a.revocable,
                            a.refUID,
                            a.data,
                            bump
                        )
                    ) == uid
                ) {
                    derived = true;
                    break;
                }
            }
            assertTrue(derived, "INV-A2: uid is not content-derived from stored fields");
        }
    }

    /// INV-A4: every stored attestation points at a registered schema.
    function invariant_A4_schema_always_registered() public view {
        uint256 n = handler.uidCount();
        for (uint256 i = 0; i < n; i++) {
            EASHandler.GhostAttestation memory g = handler.ghostOf(handler.uids(i));
            SchemaRecord memory s = registry.getSchema(g.schema);
            assertTrue(s.uid != EMPTY_UID, "INV-A4: attestation references unregistered schema");
        }
    }

    /// INV-A5: every nonzero refUID in storage resolves to a valid attestation.
    function invariant_A5_references_resolve() public view {
        uint256 n = handler.uidCount();
        for (uint256 i = 0; i < n; i++) {
            Attestation memory a = eas.getAttestation(handler.uids(i));
            if (a.refUID != EMPTY_UID) {
                assertTrue(eas.isAttestationValid(a.refUID), "INV-A5: dangling refUID");
            }
        }
    }

    /// INV-A6: creation time is honest; expiration is 0 or strictly later than
    /// creation; revocation (if any) is not before creation.
    function invariant_A6_time_sanity() public view {
        uint256 n = handler.uidCount();
        for (uint256 i = 0; i < n; i++) {
            Attestation memory a = eas.getAttestation(handler.uids(i));
            if (a.expirationTime != NO_EXPIRATION_TIME) {
                assertGt(a.expirationTime, a.time, "INV-A6: expirationTime <= creation time");
            }
            if (a.revocationTime != 0) {
                assertGe(a.revocationTime, a.time, "INV-A6: revoked before creation");
            }
        }
    }

    /// INV-R1/R2/R3 (storage side): revocationTime in storage exactly matches
    /// the ghost record of handler-performed revocations — nothing else ever
    /// set or cleared it — and irrevocable attestations are never revoked.
    /// (The acting side — who may revoke, single-shot, wrong-schema rejection —
    /// is probed on every handler call and lands in `violations`.)
    function invariant_R_revocation_matches_ghost() public view {
        uint256 n = handler.uidCount();
        for (uint256 i = 0; i < n; i++) {
            EASHandler.GhostAttestation memory g = handler.ghostOf(handler.uids(i));
            Attestation memory a = eas.getAttestation(handler.uids(i));

            assertEq(a.revocationTime, g.revokedAt, "INV-R1/R3: revocationTime diverges from ghost");
            if (!a.revocable) {
                assertEq(a.revocationTime, 0, "INV-R2: irrevocable attestation has revocationTime");
            }
            if (a.revocable) {
                (, bool schemaRevocable, ) = handler.ghostSchemaOf(a.schema);
                assertTrue(schemaRevocable, "INV-R2: revocable attestation under irrevocable schema");
            }
        }
    }

    /// INV-S2 (+ INV-S1 uid binding): every registered schema still returns
    /// exactly the record captured at registration.
    function invariant_S2_schemas_immutable() public view {
        uint256 n = handler.schemaCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 uid = handler.schemaUIDs(i);
            (ISchemaResolver resolver, bool revocable, string memory schema) = handler.ghostSchemaOf(uid);
            SchemaRecord memory s = registry.getSchema(uid);

            assertEq(s.uid, uid, "INV-S1: stored schema uid != lookup uid");
            assertEq(address(s.resolver), address(resolver), "INV-S2: resolver mutated");
            assertEq(s.revocable, revocable, "INV-S2: revocable mutated");
            assertEq(keccak256(bytes(s.schema)), keccak256(bytes(schema)), "INV-S2: schema string mutated");
        }
    }

    /// INV-T1/T2 (storage side): stored timestamps equal the ghost-recorded
    /// block time of the first (only) successful write.
    function invariant_T_timestamps_match_ghost() public view {
        uint256 n = handler.timestampedCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 data = handler.timestamped(i);
            assertEq(
                eas.getTimestamp(data),
                handler.ghostTimestampedAt(data),
                "INV-T1/T2: stored timestamp diverges from ghost"
            );
        }
        uint256 m = handler.offchainRevCount();
        for (uint256 i = 0; i < m; i++) {
            (address revoker, bytes32 data, uint64 at) = handler.offchainRevs(i);
            assertEq(
                eas.getRevokeOffchain(revoker, data),
                at,
                "INV-T1/T2: stored off-chain revocation diverges from ghost"
            );
        }
    }

    /// INV-V1: EAS retains no ETH (all handler calls are value-zero this pass;
    /// the payable-resolver value-conservation handler is a separate suite).
    function invariant_V1_eas_holds_no_ether() public view {
        assertEq(address(eas).balance, 0, "INV-V1: EAS retained ETH");
    }

    /// All in-handler semantic probes (INV-R1/R2/R3/R4, INV-T1, INV-S1,
    /// INV-B2 order/length) passed — the violation log is empty.
    function invariant_no_semantic_violations() public view {
        uint256 n = handler.violationCount();
        if (n != 0) {
            revert(string(abi.encodePacked("handler violation: ", handler.violations(0))));
        }
    }
}
