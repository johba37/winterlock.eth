// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibClone} from "solady/utils/LibClone.sol";
import {WinterlockOwner} from "./WinterlockOwner.sol";

/// @title WinterlockOwnerFactory
/// @notice Creates members' WinterlockOwners (v2) as minimal proxies of one implementation (one parameter set). A
///         member's owner is an ERC-1167 proxy with the member key, the member's stateless key, appended to its code
///         (Solady LibClone, clone with immutable args: [45-byte proxy][key: 32]), created with CREATE2 and the key as
///         the salt. Its address depends only on this factory, the implementation and the key. The factory and the implementation are
///         deployed through the deterministic deployment proxy (script/DeploySafeOwner.s.sol), so a member's owner has
///         the same address on every chain.
/// @dev    Anyone may create anyone's owner: the result is the same contract at the same address. A proxy holds no
///         admin and no upgrade path; its code is fixed at creation.
///         Status: research prototype. Unaudited. Not for real funds.
contract WinterlockOwnerFactory {
    /// The implementation every owner from this factory delegates to
    WinterlockOwner public immutable IMPLEMENTATION;

    event OwnerCreated(address indexed owner, bytes32 indexed key);

    error InvalidImplementation();
    error InvalidKey();

    constructor(WinterlockOwner implementation) {
        // an implementation, not a proxy of one: its IMPLEMENTATION is itself
        if (address(implementation).code.length == 0 || implementation.IMPLEMENTATION() != address(implementation)) {
            revert InvalidImplementation();
        }
        IMPLEMENTATION = implementation;
    }

    /// The owner address for `key`, deployed or not
    function predict(bytes32 key) public view returns (address) {
        return LibClone.predictDeterministicAddress(address(IMPLEMENTATION), abi.encodePacked(key), key, address(this));
    }

    /// Creates the owner for `key` unless it exists; returns its address either way.
    /// @param key the member key, a stateless public key: leanSphincs root (16 bytes) ‖ public parameter P (16 bytes)
    function deploy(bytes32 key) public returns (address owner) {
        // both halves set: a root and a public parameter
        if (uint256(key) >> 128 == 0 || uint128(uint256(key)) == 0) revert InvalidKey();
        bool existed;
        (existed, owner) = LibClone.createDeterministicClone(address(IMPLEMENTATION), abi.encodePacked(key), key);
        // the only external call is the proxy's creation, whose init code only returns the proxy's code
        // forge-lint: disable-next-line(reentrancy-events)
        if (!existed) emit OwnerCreated(owner, key);
    }

    /// Creates the owner for `key` unless it exists, then enrols an operation tree of device 0, the member key, for
    /// `safe` (WinterlockOwner.enroll), in one transaction. The certificate is signed by the member key for the
    /// owner's address, predict(key), which the signer knows in advance. Reverts as a whole if the certificate is
    /// refused. Device keys can only enrol once the member key has certified them, so after the owner exists.
    function deployAndEnroll(
        bytes32 key,
        address safe,
        bytes32 root,
        uint8 height,
        uint64 start,
        bytes calldata signature
    ) external returns (address owner) {
        owner = deploy(key);
        WinterlockOwner(owner).enroll(safe, 0, root, height, start, signature);
    }
}
