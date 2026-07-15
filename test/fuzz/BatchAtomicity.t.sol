// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { FuzzBase } from "./FuzzBase.sol";

import { EAS } from "@eas/EAS.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    MultiAttestationRequest,
    MultiRevocationRequest,
    RevocationRequestData
} from "@eas/IEAS.sol";
import { NotFound } from "@eas/Common.sol";

/// @notice Stateless fuzz properties for batch atomicity — INV-B1 in
///         spec/INVARIANTS.md: one bad item at ANY position wipes the whole
///         batch, including items already written to storage before the revert
///         (EAS writes `_db` before the refUID check and before resolver calls,
///         so these tests genuinely exercise rollback, not early validation).
contract BatchAtomicityFuzz is FuzzBase {
    address internal attester = makeAddr("attester");

    /// @dev Builds n distinguishable valid items for one schema.
    function _items(uint256 n) internal pure returns (AttestationRequestData[] memory items) {
        items = new AttestationRequestData[](n);
        for (uint256 i = 0; i < n; ++i) {
            items[i] = _requestData(abi.encodePacked("item", i));
        }
    }

    /// @dev Asserts that none of the given items exists in storage for the attester.
    function _assertNoneStored(bytes32 schema, AttestationRequestData[] memory items) internal view {
        for (uint256 i = 0; i < items.length; ++i) {
            bytes32 uid = _predictUID(schema, items[i], attester, uint64(block.timestamp));
            assertFalse(eas.isAttestationValid(uid), "reverted batch must leave zero state behind");
        }
    }

    /// INV-B1: an item with a bad (past, nonzero) expiration at position k
    /// reverts the entire multiAttest; items before k are rolled back.
    function testFuzz_B1_expiredItem_revertsWholeBatch(uint256 n, uint256 k, uint64 past) public {
        n = bound(n, 2, 6);
        k = bound(k, 0, n - 1);
        past = uint64(bound(past, 1, block.timestamp)); // nonzero and <= now => invalid

        AttestationRequestData[] memory items = _items(n);
        items[k].expirationTime = past;

        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: schemaPlain, data: items });

        vm.prank(attester);
        vm.expectRevert(EAS.InvalidExpirationTime.selector);
        eas.multiAttest(reqs);

        _assertNoneStored(schemaPlain, items);
    }

    /// INV-B1: a dangling refUID at position k reverts the entire batch. This
    /// is the strongest attest-side rollback probe: the offending item is
    /// already IN `_db` when the check fires (EAS.sol:464-471).
    function testFuzz_B1_danglingRefUID_revertsWholeBatch(uint256 n, uint256 k, bytes32 ghostRef) public {
        n = bound(n, 2, 6);
        k = bound(k, 0, n - 1);
        vm.assume(ghostRef != bytes32(0));
        vm.assume(!eas.isAttestationValid(ghostRef));

        AttestationRequestData[] memory items = _items(n);
        items[k].refUID = ghostRef;

        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: schemaPlain, data: items });

        vm.prank(attester);
        vm.expectRevert(NotFound.selector);
        eas.multiAttest(reqs);

        _assertNoneStored(schemaPlain, items);
    }

    /// INV-B1: value on an item under a resolver-less schema reverts the whole
    /// batch — by then every item of the batch is already written, so this
    /// pins the full-batch rollback of the payment check.
    function testFuzz_B1_unpayableValueItem_revertsWholeBatch(uint256 n, uint256 k, uint96 value) public {
        n = bound(n, 2, 6);
        k = bound(k, 0, n - 1);
        uint256 v = bound(uint256(value), 1, 100 ether);

        AttestationRequestData[] memory items = _items(n);
        items[k].value = v;

        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: schemaPlain, data: items });

        vm.deal(attester, v);
        vm.prank(attester);
        vm.expectRevert(EAS.NotPayable.selector);
        eas.multiAttest{ value: v }(reqs);

        _assertNoneStored(schemaPlain, items);
    }

    /// INV-B1: a second request block with an unregistered schema reverts the
    /// whole call, including the fully valid first block.
    function testFuzz_B1_unregisteredSchemaBlock_revertsWholeCall(uint256 n, bytes32 fakeSchema) public {
        n = bound(n, 1, 4);
        vm.assume(registry.getSchema(fakeSchema).uid == bytes32(0));

        AttestationRequestData[] memory good = _items(n);
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](2);
        reqs[0] = MultiAttestationRequest({ schema: schemaPlain, data: good });
        reqs[1] = MultiAttestationRequest({ schema: fakeSchema, data: _items(1) });

        vm.prank(attester);
        vm.expectRevert(EAS.InvalidSchema.selector);
        eas.multiAttest(reqs);

        _assertNoneStored(schemaPlain, good);
    }

    /// INV-B1: a resolver veto rejects the batch as a unit — every item was
    /// already written when the resolver answered false, and all are rolled back.
    function testFuzz_B1_resolverVeto_revertsWholeBatch(uint256 n) public {
        n = bound(n, 2, 6);

        AttestationRequestData[] memory items = _items(n);
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: schemaRejecting, data: items });

        vm.prank(attester);
        vm.expectRevert(EAS.InvalidAttestations.selector);
        eas.multiAttest(reqs);

        _assertNoneStored(schemaRejecting, items);
    }

    /// INV-B1 (revocation side): a duplicate UID inside one multiRevoke hits
    /// AlreadyRevoked on its second occurrence and rolls back EVERY revocation
    /// in the call — all attestations must come out still unrevoked.
    function testFuzz_B1_multiRevoke_duplicateUid_rollsBackAll(uint256 n, uint256 dup) public {
        n = bound(n, 2, 6);
        dup = bound(dup, 0, n - 1);

        // Create n real attestations first.
        AttestationRequestData[] memory items = _items(n);
        MultiAttestationRequest[] memory areqs = new MultiAttestationRequest[](1);
        areqs[0] = MultiAttestationRequest({ schema: schemaPlain, data: items });
        vm.prank(attester);
        bytes32[] memory uids = eas.multiAttest(areqs);

        // Revoke all n, plus a duplicate of uids[dup] appended at the end.
        RevocationRequestData[] memory rds = new RevocationRequestData[](n + 1);
        for (uint256 i = 0; i < n; ++i) {
            rds[i] = RevocationRequestData({ uid: uids[i], value: 0 });
        }
        rds[n] = RevocationRequestData({ uid: uids[dup], value: 0 });

        MultiRevocationRequest[] memory rreqs = new MultiRevocationRequest[](1);
        rreqs[0] = MultiRevocationRequest({ schema: schemaPlain, data: rds });

        vm.prank(attester);
        vm.expectRevert(EAS.AlreadyRevoked.selector);
        eas.multiRevoke(rreqs);

        for (uint256 i = 0; i < n; ++i) {
            assertEq(eas.getAttestation(uids[i]).revocationTime, 0, "reverted multiRevoke must leave every item unrevoked");
        }
    }
}
