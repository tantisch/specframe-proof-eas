// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { FuzzBase } from "./FuzzBase.sol";

import { EAS } from "@eas/EAS.sol";
import { EIP1271Verifier } from "@eas/eip1271/EIP1271Verifier.sol";
import {
    AttestationRequestData,
    AttestationRequest,
    DelegatedAttestationRequest,
    DelegatedRevocationRequest,
    RevocationRequestData
} from "@eas/IEAS.sol";
import { Attestation, Signature, AccessDenied, DeadlineExpired, InvalidSignature, NO_EXPIRATION_TIME } from "@eas/Common.sol";

/// @notice Stateless fuzz properties for delegation & replay protection —
///         INV-D1..INV-D4 in spec/INVARIANTS.md.
contract DelegationFuzz is FuzzBase {
    /// INV-D1: increaseNonce only ever moves the nonce strictly upward; any
    /// non-increasing target reverts and leaves the nonce untouched.
    function testFuzz_D1_increaseNonce_strictlyMonotonic(uint256 pkSeed, uint256 up, uint256 down) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);

        uint256 start = eas.getNonce(signer);
        up = bound(up, start + 1, start + 1_000_000);

        vm.prank(signer);
        eas.increaseNonce(up);
        assertEq(eas.getNonce(signer), up, "nonce must land exactly on the requested value");

        down = bound(down, 0, up); // any value <= current, including equal
        vm.prank(signer);
        vm.expectRevert(EIP1271Verifier.InvalidNonce.selector);
        eas.increaseNonce(down);
        assertEq(eas.getNonce(signer), up, "failed decrease must not move the nonce");
    }

    /// INV-D1: a successful delegated attest consumes exactly one nonce.
    function testFuzz_D1_delegatedAttest_consumesExactlyOneNonce(uint256 pkSeed, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);
        uint256 before = eas.getNonce(signer);

        AttestationRequestData memory d = _requestData(data);
        eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schemaPlain,
                data: d,
                signature: _signAttest(pk, schemaPlain, d, NO_EXPIRATION_TIME),
                attester: signer,
                deadline: NO_EXPIRATION_TIME
            })
        );

        assertEq(eas.getNonce(signer), before + 1, "delegated attest must consume exactly one nonce");
    }

    /// INV-D2: an identical signature can never be consumed twice — the nonce
    /// baked into the digest has moved, so the replay fails signature checks.
    function testFuzz_D2_replay_alwaysReverts(uint256 pkSeed, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);

        AttestationRequestData memory d = _requestData(data);
        Signature memory sig = _signAttest(pk, schemaPlain, d, NO_EXPIRATION_TIME);
        DelegatedAttestationRequest memory req = DelegatedAttestationRequest({
            schema: schemaPlain,
            data: d,
            signature: sig,
            attester: signer,
            deadline: NO_EXPIRATION_TIME
        });

        eas.attestByDelegation(req);

        vm.expectRevert(InvalidSignature.selector);
        eas.attestByDelegation(req);
    }

    /// INV-D2: increaseNonce invalidates every signature signed under a lower
    /// nonce, for both delegated attests and delegated revokes.
    function testFuzz_D2_increaseNonce_invalidatesPendingSignatures(uint256 pkSeed, uint256 bump, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);

        // A pending revoke signature needs a real attestation to point at.
        AttestationRequestData memory d = _requestData(data);
        vm.prank(signer);
        bytes32 uid = eas.attest(AttestationRequest({ schema: schemaPlain, data: d }));

        Signature memory attestSig = _signAttest(pk, schemaPlain, d, NO_EXPIRATION_TIME);
        RevocationRequestData memory rd = RevocationRequestData({ uid: uid, value: 0 });
        Signature memory revokeSig = _signRevoke(pk, schemaPlain, rd, NO_EXPIRATION_TIME);

        uint256 current = eas.getNonce(signer);
        bump = bound(bump, current + 1, current + 1_000_000);
        vm.prank(signer);
        eas.increaseNonce(bump);

        vm.expectRevert(InvalidSignature.selector);
        eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schemaPlain,
                data: d,
                signature: attestSig,
                attester: signer,
                deadline: NO_EXPIRATION_TIME
            })
        );

        vm.expectRevert(InvalidSignature.selector);
        eas.revokeByDelegation(
            DelegatedRevocationRequest({
                schema: schemaPlain,
                data: rd,
                signature: revokeSig,
                revoker: signer,
                deadline: NO_EXPIRATION_TIME
            })
        );
    }

    /// INV-D3: the stored attester is the signature subject, never the relayer
    /// that paid for gas.
    function testFuzz_D3_attributionIsSignerExact(uint256 pkSeed, address relayer, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);
        vm.assume(relayer != signer && relayer != address(0));

        AttestationRequestData memory d = _requestData(data);
        vm.prank(relayer);
        bytes32 uid = eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schemaPlain,
                data: d,
                signature: _signAttest(pk, schemaPlain, d, NO_EXPIRATION_TIME),
                attester: signer,
                deadline: NO_EXPIRATION_TIME
            })
        );

        Attestation memory a = eas.getAttestation(uid);
        assertEq(a.attester, signer, "attribution must follow the signature subject");
        assertTrue(a.attester != relayer, "relayer must never be attributed");
    }

    /// INV-D3: claiming someone else as attester with a signature they did not
    /// produce always reverts — a valid signature by the WRONG key is useless.
    function testFuzz_D3_forgedAttesterClaim_reverts(uint256 pkSeed, uint256 victimSeed, bytes memory data) public {
        uint256 forgerPk = _boundPk(pkSeed);
        uint256 victimPk = _boundPk(victimSeed);
        address victim = vm.addr(victimPk);
        vm.assume(vm.addr(forgerPk) != victim);

        AttestationRequestData memory d = _requestData(data);
        // Forger signs the exact payload (including the victim's current nonce)
        // but the digest binds `attester = signer`, so substituting the victim fails.
        Signature memory sig = _signAttestAtNonce(forgerPk, schemaPlain, d, NO_EXPIRATION_TIME, eas.getNonce(victim));

        vm.expectRevert(InvalidSignature.selector);
        eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schemaPlain,
                data: d,
                signature: sig,
                attester: victim,
                deadline: NO_EXPIRATION_TIME
            })
        );
    }

    /// INV-D3 (revocation side): a perfectly valid delegated revoke signed by
    /// anyone who is not the original attester reverts with AccessDenied.
    function testFuzz_D3_delegatedRevoke_requiresOriginalAttester(uint256 attesterSeed, uint256 strangerSeed, bytes memory data)
        public
    {
        uint256 attesterPk = _boundPk(attesterSeed);
        uint256 strangerPk = _boundPk(strangerSeed);
        address attester = vm.addr(attesterPk);
        address stranger = vm.addr(strangerPk);
        vm.assume(attester != stranger);

        AttestationRequestData memory d = _requestData(data);
        vm.prank(attester);
        bytes32 uid = eas.attest(AttestationRequest({ schema: schemaPlain, data: d }));

        RevocationRequestData memory rd = RevocationRequestData({ uid: uid, value: 0 });
        // Signature computed BEFORE expectRevert: _signRevoke's staticcalls to
        // eas would otherwise be consumed as "the next call".
        Signature memory sig = _signRevoke(strangerPk, schemaPlain, rd, NO_EXPIRATION_TIME);
        vm.expectRevert(AccessDenied.selector);
        eas.revokeByDelegation(
            DelegatedRevocationRequest({
                schema: schemaPlain,
                data: rd,
                signature: sig,
                revoker: stranger,
                deadline: NO_EXPIRATION_TIME
            })
        );

        assertEq(eas.getAttestation(uid).revocationTime, 0, "stranger's delegated revoke must not stick");
    }

    /// INV-D4: an expired deadline always reverts AND the failed attempt does
    /// not burn the signer's nonce (the increment is rolled back).
    function testFuzz_D4_expiredDeadline_revertsWithoutBurningNonce(uint256 pkSeed, uint64 deadline, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);
        // block.timestamp is warped to 1_000_000 in setUp; pick a strictly past, nonzero deadline.
        deadline = uint64(bound(deadline, 1, block.timestamp - 1));

        AttestationRequestData memory d = _requestData(data);
        Signature memory sig = _signAttest(pk, schemaPlain, d, deadline);
        uint256 nonceBefore = eas.getNonce(signer);

        vm.expectRevert(DeadlineExpired.selector);
        eas.attestByDelegation(
            DelegatedAttestationRequest({ schema: schemaPlain, data: d, signature: sig, attester: signer, deadline: deadline })
        );

        assertEq(eas.getNonce(signer), nonceBefore, "expired-deadline attempt must not burn a nonce");
    }

    /// INV-D4: deadline == 0 means "never expires" — it verifies at any future time.
    function testFuzz_D4_zeroDeadline_neverExpires(uint256 pkSeed, uint64 warp, bytes memory data) public {
        uint256 pk = _boundPk(pkSeed);
        address signer = vm.addr(pk);

        AttestationRequestData memory d = _requestData(data);
        Signature memory sig = _signAttest(pk, schemaPlain, d, NO_EXPIRATION_TIME);

        warp = uint64(bound(warp, block.timestamp, type(uint64).max - 1));
        vm.warp(warp);

        bytes32 uid = eas.attestByDelegation(
            DelegatedAttestationRequest({
                schema: schemaPlain,
                data: d,
                signature: sig,
                attester: signer,
                deadline: NO_EXPIRATION_TIME
            })
        );
        assertEq(eas.getAttestation(uid).attester, signer, "zero-deadline signature must verify at any time");
    }
}
