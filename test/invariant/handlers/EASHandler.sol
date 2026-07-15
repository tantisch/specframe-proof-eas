// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { EAS } from "@eas/EAS.sol";
import { SchemaRegistry } from "@eas/SchemaRegistry.sol";
import { SchemaRecord } from "@eas/ISchemaRegistry.sol";
import { ISchemaResolver } from "@eas/resolver/ISchemaResolver.sol";
import { Attestation, EMPTY_UID, NO_EXPIRATION_TIME } from "@eas/Common.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    MultiAttestationRequest,
    RevocationRequest,
    RevocationRequestData
} from "@eas/IEAS.sol";

/// @notice Fuzz handler driving EAS + SchemaRegistry with ghost bookkeeping.
///
/// Design rules:
/// - The handler NEVER reverts and never asserts. With `fail_on_revert = false`
///   a reverting handler call is silently discarded by the fuzzer, which would
///   silently disable any in-handler check. Instead, every semantic prediction
///   mismatch is appended to `violations`, which persists and is asserted empty
///   by the invariant contract (INV-R1/R2/R3, INV-T1, INV-S1 probes).
/// - Ghost state records what *should* be true (creation snapshots, revocation
///   times, first-timestamp times); the invariant contract compares it against
///   live storage (INV-A1..A6, INV-S2, INV-T2, INV-V1).
contract EASHandler is CommonBase, StdCheats, StdUtils {
    SchemaRegistry public immutable registry;
    EAS public immutable eas;

    address[] internal actors;

    // ---- ghost: schemas -----------------------------------------------------
    bytes32[] public schemaUIDs;
    struct GhostSchema {
        ISchemaResolver resolver;
        bool revocable;
        string schema;
    }
    mapping(bytes32 => GhostSchema) internal ghostSchemas;
    uint256 internal schemaNonce;

    // ---- ghost: attestations ------------------------------------------------
    bytes32[] public uids;
    struct GhostAttestation {
        bool exists;
        bytes32 schema;
        uint64 time;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        address recipient;
        address attester;
        bytes data;
        uint64 revokedAt; // 0 = not revoked (via this handler)
    }
    mapping(bytes32 => GhostAttestation) internal ghosts;

    // ---- ghost: timestamps & off-chain revocations ---------------------------
    bytes32[] public timestamped;
    mapping(bytes32 => uint64) public ghostTimestampedAt;
    struct OffchainRev {
        address revoker;
        bytes32 data;
        uint64 at;
    }
    OffchainRev[] public offchainRevs;
    mapping(address => mapping(bytes32 => uint64)) public ghostOffchainAt;

    // ---- violations (persist across the run; asserted empty as an invariant) -
    string[] public violations;

    // ---- call summary ---------------------------------------------------------
    mapping(string => uint256) public calls;

    constructor(SchemaRegistry registry_, EAS eas_) {
        registry = registry_;
        eas = eas_;
        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("carol"));
        actors.push(makeAddr("dave"));
        actors.push(makeAddr("eve"));
    }

    // ---- views used by the invariant contract --------------------------------

    function uidCount() external view returns (uint256) {
        return uids.length;
    }

    function schemaCount() external view returns (uint256) {
        return schemaUIDs.length;
    }

    function timestampedCount() external view returns (uint256) {
        return timestamped.length;
    }

    function offchainRevCount() external view returns (uint256) {
        return offchainRevs.length;
    }

    function violationCount() external view returns (uint256) {
        return violations.length;
    }

    function ghostOf(bytes32 uid) external view returns (GhostAttestation memory) {
        return ghosts[uid];
    }

    function ghostSchemaOf(bytes32 uid)
        external
        view
        returns (ISchemaResolver resolver, bool revocable, string memory schema)
    {
        GhostSchema storage g = ghostSchemas[uid];
        return (g.resolver, g.revocable, g.schema);
    }

    // ---- internal helpers ------------------------------------------------------

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, actors.length - 1)];
    }

    function _fail(string memory reason) internal {
        violations.push(reason);
    }

    // ---- actions ----------------------------------------------------------------

    /// Time moves forward between calls so time-derived fields are distinguishable.
    function warp(uint256 seed) external {
        calls["warp"]++;
        vm.warp(block.timestamp + bound(seed, 1, 3 days));
    }

    /// INV-S1 (registration side): fresh triples always register; the returned
    /// UID is recorded with a full snapshot for the INV-S2 immutability check.
    function registerSchema(uint256 actorSeed, uint256 seed) external {
        calls["registerSchema"]++;
        string memory schema = string(abi.encodePacked("uint256 field_", vm.toString(schemaNonce++)));
        bool revocable = seed % 2 == 0;

        vm.prank(_actor(actorSeed));
        try registry.register(schema, ISchemaResolver(address(0)), revocable) returns (bytes32 uid) {
            if (bytes(ghostSchemas[uid].schema).length != 0) {
                _fail("INV-S1: schema UID collision across distinct triples");
            }
            schemaUIDs.push(uid);
            ghostSchemas[uid] = GhostSchema(ISchemaResolver(address(0)), revocable, schema);
        } catch {
            _fail("INV-S1: registering a fresh (schema,resolver,revocable) triple reverted");
        }
    }

    /// INV-S1 (collision side): re-registering an existing triple must revert.
    function registerDuplicateSchema(uint256 actorSeed, uint256 schemaSeed) external {
        calls["registerDuplicateSchema"]++;
        if (schemaUIDs.length == 0) return;
        bytes32 uid = schemaUIDs[bound(schemaSeed, 0, schemaUIDs.length - 1)];
        GhostSchema storage g = ghostSchemas[uid];

        vm.prank(_actor(actorSeed));
        try registry.register(g.schema, g.resolver, g.revocable) returns (bytes32) {
            _fail("INV-S1: duplicate (schema,resolver,revocable) triple registered twice");
        } catch {
            // expected: AlreadyExists
        }
    }

    /// Happy-path attest; ghost snapshot recorded for INV-A1..A6.
    function attest(
        uint256 actorSeed,
        uint256 schemaSeed,
        uint256 recipientSeed,
        uint256 expSeed,
        uint256 refSeed,
        uint256 dataSeed
    ) external {
        calls["attest"]++;
        if (schemaUIDs.length == 0) return;
        bytes32 schemaUID = schemaUIDs[bound(schemaSeed, 0, schemaUIDs.length - 1)];
        GhostSchema storage s = ghostSchemas[schemaUID];

        AttestationRequestData memory d = AttestationRequestData({
            recipient: _actor(recipientSeed),
            // 0 = never expires; otherwise strictly in the future
            expirationTime: expSeed % 3 == 0
                ? NO_EXPIRATION_TIME
                : uint64(block.timestamp + bound(expSeed, 1 hours, 365 days)),
            // an irrevocable schema only accepts irrevocable attestations
            revocable: s.revocable && (expSeed % 2 == 0),
            refUID: (refSeed % 3 == 0 || uids.length == 0)
                ? EMPTY_UID
                : uids[bound(refSeed, 0, uids.length - 1)],
            data: abi.encodePacked(dataSeed),
            value: 0
        });

        address attester = _actor(actorSeed);
        vm.prank(attester);
        try eas.attest(AttestationRequest(schemaUID, d)) returns (bytes32 uid) {
            _recordAttestation(uid, schemaUID, d, attester);
        } catch {
            _fail("attest: valid request reverted");
        }
    }

    /// Batch attest on one schema (1..3 items). Ghosts recorded per returned UID,
    /// in order — feeds INV-A1 and the INV-B2 order guarantee.
    function multiAttest(
        uint256 actorSeed,
        uint256 schemaSeed,
        uint256 sizeSeed,
        uint256 dataSeed
    ) external {
        calls["multiAttest"]++;
        if (schemaUIDs.length == 0) return;
        bytes32 schemaUID = schemaUIDs[bound(schemaSeed, 0, schemaUIDs.length - 1)];
        GhostSchema storage s = ghostSchemas[schemaUID];

        uint256 n = bound(sizeSeed, 1, 3);
        AttestationRequestData[] memory items = new AttestationRequestData[](n);
        for (uint256 i = 0; i < n; i++) {
            items[i] = AttestationRequestData({
                recipient: _actor(dataSeed + i),
                expirationTime: NO_EXPIRATION_TIME,
                revocable: s.revocable,
                refUID: EMPTY_UID,
                data: abi.encodePacked(dataSeed, i),
                value: 0
            });
        }
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest(schemaUID, items);

        address attester = _actor(actorSeed);
        vm.prank(attester);
        try eas.multiAttest(reqs) returns (bytes32[] memory newUIDs) {
            if (newUIDs.length != n) {
                _fail("INV-B2: multiAttest returned wrong number of UIDs");
                return;
            }
            for (uint256 i = 0; i < n; i++) {
                _recordAttestation(newUIDs[i], schemaUID, items[i], attester);
            }
        } catch {
            _fail("multiAttest: valid batch reverted");
        }
    }

    function _recordAttestation(
        bytes32 uid,
        bytes32 schemaUID,
        AttestationRequestData memory d,
        address attester
    ) internal {
        if (ghosts[uid].exists) {
            _fail("INV-A1: attest returned an already-used UID");
            return;
        }
        uids.push(uid);
        ghosts[uid] = GhostAttestation({
            exists: true,
            schema: schemaUID,
            time: uint64(block.timestamp),
            expirationTime: d.expirationTime,
            revocable: d.revocable,
            refUID: d.refUID,
            recipient: d.recipient,
            attester: attester,
            data: d.data,
            revokedAt: 0
        });
    }

    /// Attester-initiated revoke. Outcome is predicted from ghost state and any
    /// mismatch is a violation: success required iff (revocable && not yet
    /// revoked) — INV-R2 and INV-R3 exercised on every call.
    function revoke(uint256 uidSeed) external {
        calls["revoke"]++;
        if (uids.length == 0) return;
        bytes32 uid = uids[bound(uidSeed, 0, uids.length - 1)];
        GhostAttestation storage g = ghosts[uid];
        bool shouldSucceed = g.revocable && g.revokedAt == 0;

        vm.prank(g.attester);
        try eas.revoke(RevocationRequest(g.schema, RevocationRequestData(uid, 0))) {
            if (!shouldSucceed) {
                _fail(
                    g.revokedAt != 0
                        ? "INV-R3: second revoke of the same UID succeeded"
                        : "INV-R2: irrevocable attestation was revoked"
                );
            } else {
                g.revokedAt = uint64(block.timestamp);
            }
        } catch {
            if (shouldSucceed) {
                _fail("INV-R: attester revoke of a revocable, unrevoked attestation reverted");
            }
        }
    }

    /// INV-R1: anyone who is not the attester must never be able to revoke.
    function revokeAsStranger(uint256 uidSeed, uint256 actorSeed) external {
        calls["revokeAsStranger"]++;
        if (uids.length == 0) return;
        bytes32 uid = uids[bound(uidSeed, 0, uids.length - 1)];
        GhostAttestation storage g = ghosts[uid];

        address stranger = _actor(actorSeed);
        if (stranger == g.attester) return;

        vm.prank(stranger);
        try eas.revoke(RevocationRequest(g.schema, RevocationRequestData(uid, 0))) {
            _fail("INV-R1: non-attester revoked an attestation");
        } catch {
            // expected: AccessDenied (or Irrevocable/AlreadyRevoked — all are rejections)
        }
    }

    /// INV-R4: revoking through the wrong schema handle must revert.
    function revokeWrongSchema(uint256 uidSeed, uint256 schemaSeed) external {
        calls["revokeWrongSchema"]++;
        if (uids.length == 0 || schemaUIDs.length < 2) return;
        bytes32 uid = uids[bound(uidSeed, 0, uids.length - 1)];
        GhostAttestation storage g = ghosts[uid];
        bytes32 wrongSchema = schemaUIDs[bound(schemaSeed, 0, schemaUIDs.length - 1)];
        if (wrongSchema == g.schema) return;

        vm.prank(g.attester);
        try eas.revoke(RevocationRequest(wrongSchema, RevocationRequestData(uid, 0))) {
            _fail("INV-R4: revocation via a mismatched schema handle succeeded");
        } catch {
            // expected: InvalidSchema
        }
    }

    /// INV-T1/T2: first timestamp of a datum succeeds and records now; the
    /// mix of fresh vs. already-timestamped data probes the write-once rule.
    function timestampData(uint256 seed) external {
        calls["timestampData"]++;
        bytes32 data;
        if (timestamped.length != 0 && seed % 3 == 0) {
            data = timestamped[bound(seed, 0, timestamped.length - 1)]; // re-timestamp probe
        } else {
            data = keccak256(abi.encodePacked("ts", seed));
        }
        bool isFresh = ghostTimestampedAt[data] == 0;

        try eas.timestamp(data) returns (uint64 t) {
            if (!isFresh) {
                _fail("INV-T1: re-timestamping the same data succeeded");
            } else if (t != uint64(block.timestamp)) {
                _fail("INV-T2: timestamp() returned a time other than block.timestamp");
            } else {
                ghostTimestampedAt[data] = t;
                timestamped.push(data);
            }
        } catch {
            if (isFresh) {
                _fail("INV-T1: first-time timestamp of fresh data reverted");
            }
        }
    }

    /// INV-T1 (off-chain revocations): write-once per (revoker, data); distinct
    /// revokers of the same data stay independent.
    function revokeOffchain(uint256 actorSeed, uint256 seed) external {
        calls["revokeOffchain"]++;
        address revoker = _actor(actorSeed);
        bytes32 data;
        if (offchainRevs.length != 0 && seed % 3 == 0) {
            data = offchainRevs[bound(seed, 0, offchainRevs.length - 1)].data; // same data, maybe same revoker
        } else {
            data = keccak256(abi.encodePacked("rev", seed));
        }
        bool isFresh = ghostOffchainAt[revoker][data] == 0;

        vm.prank(revoker);
        try eas.revokeOffchain(data) returns (uint64 t) {
            if (!isFresh) {
                _fail("INV-T1: same revoker re-revoked the same off-chain data");
            } else if (t != uint64(block.timestamp)) {
                _fail("INV-T2: revokeOffchain() returned a time other than block.timestamp");
            } else {
                ghostOffchainAt[revoker][data] = t;
                offchainRevs.push(OffchainRev(revoker, data, t));
            }
        } catch {
            if (isFresh) {
                _fail("INV-T1: first off-chain revocation for (revoker,data) reverted");
            }
        }
    }
}
