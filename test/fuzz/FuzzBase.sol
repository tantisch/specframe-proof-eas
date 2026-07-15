// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { Test } from "forge-std/Test.sol";

import { EAS } from "@eas/EAS.sol";
import { SchemaRegistry } from "@eas/SchemaRegistry.sol";
import { IEAS, AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData } from "@eas/IEAS.sol";
import { ISchemaResolver } from "@eas/resolver/ISchemaResolver.sol";
import { SchemaResolver } from "@eas/resolver/SchemaResolver.sol";
import { Attestation, Signature, EMPTY_UID, NO_EXPIRATION_TIME } from "@eas/Common.sol";

/// @notice Resolver that accepts everything and accepts ETH (isPayable = true).
contract PayableResolver is SchemaResolver {
    constructor(IEAS eas) SchemaResolver(eas) {}

    function isPayable() public pure override returns (bool) {
        return true;
    }

    function onAttest(Attestation calldata, uint256) internal pure override returns (bool) {
        return true;
    }

    function onRevoke(Attestation calldata, uint256) internal pure override returns (bool) {
        return true;
    }
}

/// @notice Resolver that accepts everything but refuses ETH (isPayable = false,
///         the SchemaResolver default).
contract NonPayableResolver is SchemaResolver {
    constructor(IEAS eas) SchemaResolver(eas) {}

    function onAttest(Attestation calldata, uint256) internal pure override returns (bool) {
        return true;
    }

    function onRevoke(Attestation calldata, uint256) internal pure override returns (bool) {
        return true;
    }
}

/// @notice Resolver that vetoes everything — used to force mid-batch resolver
///         rejection for the atomicity properties (INV-B1).
contract RejectingResolver is SchemaResolver {
    constructor(IEAS eas) SchemaResolver(eas) {}

    function onAttest(Attestation calldata, uint256) internal pure override returns (bool) {
        return false;
    }

    function onRevoke(Attestation calldata, uint256) internal pure override returns (bool) {
        return false;
    }
}

/// @notice Shared deployment + EIP712 signing helpers for the stateless fuzz
///         suites (INV-D*, INV-V*, INV-B1). Every schema flavor the properties
///         need is registered once here.
abstract contract FuzzBase is Test {
    // secp256k1 group order; vm.sign requires 0 < pk < N.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    SchemaRegistry internal registry;
    EAS internal eas;

    PayableResolver internal payableResolver;
    NonPayableResolver internal nonPayableResolver;
    RejectingResolver internal rejectingResolver;

    bytes32 internal schemaPlain; // revocable, no resolver
    bytes32 internal schemaIrrevocable; // non-revocable, no resolver
    bytes32 internal schemaPayable; // revocable, payable resolver
    bytes32 internal schemaNonPayable; // revocable, non-payable resolver
    bytes32 internal schemaRejecting; // revocable, rejecting resolver

    function setUp() public virtual {
        registry = new SchemaRegistry();
        eas = new EAS(registry);

        payableResolver = new PayableResolver(eas);
        nonPayableResolver = new NonPayableResolver(eas);
        rejectingResolver = new RejectingResolver(eas);

        schemaPlain = registry.register("bool ok", ISchemaResolver(address(0)), true);
        schemaIrrevocable = registry.register("bool ok", ISchemaResolver(address(0)), false);
        schemaPayable = registry.register("bool ok", payableResolver, true);
        schemaNonPayable = registry.register("bool ok", nonPayableResolver, true);
        schemaRejecting = registry.register("bool ok", rejectingResolver, true);

        // Start at a realistic timestamp so expiration/deadline math has room
        // on both sides (the default block.timestamp of 1 does not).
        vm.warp(1_000_000);
    }

    // ---- EIP712 helpers (mirror EIP1271Verifier's digest construction) ------

    function _boundPk(uint256 pk) internal pure returns (uint256) {
        return bound(pk, 1, SECP256K1_N - 1);
    }

    /// @dev Signs a delegated-attest payload with the signer's CURRENT nonce,
    ///      exactly as EIP1271Verifier._verifyAttest will reconstruct it.
    function _signAttest(
        uint256 pk,
        bytes32 schema,
        AttestationRequestData memory d,
        uint64 deadline
    ) internal view returns (Signature memory) {
        return _signAttestAtNonce(pk, schema, d, deadline, eas.getNonce(vm.addr(pk)));
    }

    function _signAttestAtNonce(
        uint256 pk,
        bytes32 schema,
        AttestationRequestData memory d,
        uint64 deadline,
        uint256 nonce
    ) internal view returns (Signature memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                eas.getAttestTypeHash(),
                vm.addr(pk),
                schema,
                d.recipient,
                d.expirationTime,
                d.revocable,
                d.refUID,
                keccak256(d.data),
                d.value,
                nonce,
                deadline
            )
        );
        return _sign(pk, structHash);
    }

    /// @dev Signs a delegated-revoke payload with the signer's CURRENT nonce.
    function _signRevoke(
        uint256 pk,
        bytes32 schema,
        RevocationRequestData memory d,
        uint64 deadline
    ) internal view returns (Signature memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                eas.getRevokeTypeHash(),
                vm.addr(pk),
                schema,
                d.uid,
                d.value,
                eas.getNonce(vm.addr(pk)),
                deadline
            )
        );
        return _sign(pk, structHash);
    }

    function _sign(uint256 pk, bytes32 structHash) private view returns (Signature memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", eas.getDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return Signature({ v: v, r: r, s: s });
    }

    // ---- misc helpers --------------------------------------------------------

    function _requestData(bytes memory data) internal pure returns (AttestationRequestData memory) {
        return
            AttestationRequestData({
                recipient: address(0xBEEF),
                expirationTime: NO_EXPIRATION_TIME,
                revocable: true,
                refUID: EMPTY_UID,
                data: data,
                value: 0
            });
    }

    /// @dev Mirrors EAS._getUID at bump 0 — used to prove a would-have-been
    ///      attestation was NOT persisted after a reverted batch (INV-B1).
    function _predictUID(
        bytes32 schema,
        AttestationRequestData memory d,
        address attester,
        uint64 time
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(schema, d.recipient, attester, time, d.expirationTime, d.revocable, d.refUID, d.data, uint32(0))
            );
    }
}
