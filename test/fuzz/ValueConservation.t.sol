// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { FuzzBase } from "./FuzzBase.sol";

import { EAS } from "@eas/EAS.sol";
import {
    AttestationRequest,
    AttestationRequestData,
    MultiAttestationRequest,
    RevocationRequest,
    RevocationRequestData
} from "@eas/IEAS.sol";

/// @notice Stateless fuzz properties for the resolver ETH path —
///         INV-V1..INV-V3 in spec/INVARIANTS.md.
contract ValueConservationFuzz is FuzzBase {
    address internal sender = makeAddr("sender");

    /// INV-V1: on a paid attest, every wei of msg.value is accounted for —
    /// exactly `value` reaches the resolver, the remainder returns to the
    /// sender, and EAS retains nothing.
    function testFuzz_V1_singleAttest_conservesValue(uint96 value, uint96 extra) public {
        uint256 v = bound(uint256(value), 0, 100 ether);
        uint256 m = v + bound(uint256(extra), 0, 100 ether);
        vm.deal(sender, m);

        uint256 resolverBefore = address(payableResolver).balance;

        AttestationRequestData memory d = _requestData("paid");
        d.value = v;
        vm.prank(sender);
        eas.attest{ value: m }(AttestationRequest({ schema: schemaPayable, data: d }));

        assertEq(address(payableResolver).balance - resolverBefore, v, "resolver must receive exactly `value`");
        assertEq(sender.balance, m - v, "sender must be refunded everything above `value`");
        assertEq(address(eas).balance, 0, "EAS must retain nothing");
    }

    /// INV-V1: the revocation path conserves value the same way.
    function testFuzz_V1_revoke_conservesValue(uint96 value, uint96 extra) public {
        uint256 v = bound(uint256(value), 0, 100 ether);
        uint256 m = v + bound(uint256(extra), 0, 100 ether);

        AttestationRequestData memory d = _requestData("to-revoke");
        vm.prank(sender);
        bytes32 uid = eas.attest(AttestationRequest({ schema: schemaPayable, data: d }));

        vm.deal(sender, m);
        uint256 resolverBefore = address(payableResolver).balance;

        vm.prank(sender);
        eas.revoke{ value: m }(
            RevocationRequest({ schema: schemaPayable, data: RevocationRequestData({ uid: uid, value: v }) })
        );

        assertEq(address(payableResolver).balance - resolverBefore, v, "resolver must receive exactly `value` on revoke");
        assertEq(sender.balance, m - v, "revoker must be refunded everything above `value`");
        assertEq(address(eas).balance, 0, "EAS must retain nothing");
    }

    /// INV-V2: sending value at a schema with NO resolver always reverts —
    /// money can never be sent into the void.
    function testFuzz_V2_valueWithoutResolver_reverts(uint96 value) public {
        uint256 v = bound(uint256(value), 1, 100 ether);
        vm.deal(sender, v);

        AttestationRequestData memory d = _requestData("void");
        d.value = v;
        vm.prank(sender);
        vm.expectRevert(EAS.NotPayable.selector);
        eas.attest{ value: v }(AttestationRequest({ schema: schemaPlain, data: d }));
    }

    /// INV-V2: sending value at a non-payable resolver always reverts.
    function testFuzz_V2_valueAtNonPayableResolver_reverts(uint96 value) public {
        uint256 v = bound(uint256(value), 1, 100 ether);
        vm.deal(sender, v);

        AttestationRequestData memory d = _requestData("void");
        d.value = v;
        vm.prank(sender);
        vm.expectRevert(EAS.NotPayable.selector);
        eas.attest{ value: v }(AttestationRequest({ schema: schemaNonPayable, data: d }));
    }

    /// INV-V3: across a multi-batch multiAttest, the resolver receives exactly
    /// sum(values), the single refund returns exactly the remainder, and EAS
    /// ends at zero.
    function testFuzz_V3_multiAttest_batchAccounting(uint96[4] memory rawValues, uint96 extra) public {
        uint256 total = 0;
        uint256[4] memory vs;
        for (uint256 i = 0; i < 4; ++i) {
            vs[i] = bound(uint256(rawValues[i]), 0, 25 ether);
            total += vs[i];
        }
        uint256 m = total + bound(uint256(extra), 0, 100 ether);
        vm.deal(sender, m);

        // Two batches of two items each, so the availableValue ratchet and the
        // last-batch-only refund are both exercised.
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](2);
        for (uint256 b = 0; b < 2; ++b) {
            AttestationRequestData[] memory items = new AttestationRequestData[](2);
            for (uint256 i = 0; i < 2; ++i) {
                items[i] = _requestData(abi.encodePacked("batch", b, i));
                items[i].value = vs[b * 2 + i];
            }
            reqs[b] = MultiAttestationRequest({ schema: schemaPayable, data: items });
        }

        uint256 resolverBefore = address(payableResolver).balance;
        vm.prank(sender);
        eas.multiAttest{ value: m }(reqs);

        assertEq(address(payableResolver).balance - resolverBefore, total, "resolver must receive exactly sum(values)");
        assertEq(sender.balance, m - total, "remainder must be refunded exactly once");
        assertEq(address(eas).balance, 0, "EAS must retain nothing");
    }

    /// INV-V3: a batch whose values sum to more than msg.value always reverts —
    /// the ratchet never lets resolver payouts exceed what the caller sent.
    function testFuzz_V3_overspendingBatch_reverts(uint96 v0, uint96 v1, uint96 shortfall) public {
        uint256 a = bound(uint256(v0), 0, 50 ether);
        uint256 b = bound(uint256(v1), 1, 50 ether);
        uint256 total = a + b;
        uint256 m = total - bound(uint256(shortfall), 1, total); // strictly less than needed
        vm.deal(sender, m);

        AttestationRequestData[] memory items = new AttestationRequestData[](2);
        items[0] = _requestData("over0");
        items[0].value = a;
        items[1] = _requestData("over1");
        items[1].value = b;
        MultiAttestationRequest[] memory reqs = new MultiAttestationRequest[](1);
        reqs[0] = MultiAttestationRequest({ schema: schemaPayable, data: items });

        vm.prank(sender);
        vm.expectRevert(EAS.InsufficientValue.selector);
        eas.multiAttest{ value: m }(reqs);
    }

    /// INV-V1 (force-fed pin): ETH forced into EAS is dead weight, not spendable
    /// headroom — the availableValue ratchet caps payouts at msg.value, so a
    /// request for more than msg.value reverts even when the balance could cover
    /// it, and the stuck amount never moves.
    function testFuzz_V1_forceFedEth_isNotSpendable(uint96 stuck, uint96 value) public {
        uint256 s = bound(uint256(stuck), 1, 100 ether);
        uint256 v = bound(uint256(value), 1, s); // covered by stuck balance, NOT by msg.value
        vm.deal(address(eas), s);

        AttestationRequestData memory d = _requestData("greedy");
        d.value = v;
        vm.prank(sender);
        vm.expectRevert(EAS.InsufficientValue.selector);
        eas.attest{ value: 0 }(AttestationRequest({ schema: schemaPayable, data: d }));

        // A normal paid flow leaves the stuck balance exactly where it was.
        uint256 m = 1 ether;
        vm.deal(sender, m);
        d = _requestData("normal");
        d.value = 0.25 ether;
        vm.prank(sender);
        eas.attest{ value: m }(AttestationRequest({ schema: schemaPayable, data: d }));

        assertEq(address(eas).balance, s, "force-fed ETH must stay stuck: never refunded, never forwarded");
        assertEq(sender.balance, m - 0.25 ether, "refund must come from msg.value only");
    }
}
