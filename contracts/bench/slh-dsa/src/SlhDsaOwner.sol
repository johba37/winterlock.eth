// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISlhDsaVerifier} from "./ISlhDsaVerifier.sol";

/// @title A minimal SLH-DSA owner, for the ERC-1271 benchmark
/// @notice What a Safe owner whose every signature is SLH-DSA would pay per check: `isValidSignature` verifies an
///         SLH-DSA signature (pure, empty context) over the 32-byte hash, through a shared verifier, as WinterlockOwner
///         v2 calls its stateless verifier. The key sits in the code.
/// @dev    Not an owner to deploy: it binds the hash to no Safe, chain or owner (WinterlockOwner's message digest does,
///         for a few hundred gas more) and has no devices or revocation.
contract SlhDsaOwner {
    address public immutable VERIFIER;
    /// PK.seed | PK.root
    bytes32 public immutable PUBLIC_KEY;

    constructor(address verifier, bytes32 publicKey) {
        VERIFIER = verifier;
        PUBLIC_KEY = publicKey;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magic) {
        address v = VERIFIER;
        bytes32 pk = PUBLIC_KEY;
        bytes4 selector = ISlhDsaVerifier.verify.selector;
        bool ok;
        assembly ("memory-safe") {
            // verify(bytes pk, bytes message, bytes signature), encoded by hand
            let m := mload(0x40)
            mstore(m, selector)
            mstore(add(m, 0x04), 0x60)
            mstore(add(m, 0x24), 0xa0)
            mstore(add(m, 0x44), 0xe0)
            mstore(add(m, 0x64), 32)
            mstore(add(m, 0x84), pk)
            mstore(add(m, 0xa4), 32)
            mstore(add(m, 0xc4), hash)
            mstore(add(m, 0xe4), signature.length)
            calldatacopy(add(m, 0x104), signature.offset, signature.length)
            let padded := and(add(signature.length, 31), not(31))
            mstore(add(add(m, 0x104), signature.length), 0) // zero the padding
            let success := staticcall(gas(), v, m, add(0x104, padded), 0x00, 0x20)
            ok := and(success, and(gt(returndatasize(), 0x1f), eq(mload(0x00), 1)))
        }
        magic = ok ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
