// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WotsParams, WotsKey, WotsTree, Ops} from "./WotsSigner.sol";

/// @notice Test only. Exposes the reference signer through eth_call, so tools outside Foundry (the bundler
///         acceptance driver) can produce WOTS signatures and install data. Keys are derived from a PUBLIC
///         tag, so anyone can sign with them: local tests only, never real funds.
///         Trees have height 20 with real leaves for key indices 0..3 (nonces 0 and 1, both slots).
contract WotsSignerHelper {
    uint256 internal constant HEIGHT = 20;
    uint256 internal constant REAL = 2;

    function _key(WotsParams memory p, string memory tag, uint256 member) internal pure returns (WotsKey memory) {
        return WotsTree.create(
            p,
            uint128(uint256(keccak256(abi.encode(tag, "seed", member)))),
            keccak256(abi.encode(tag, "sk", member)),
            HEIGHT,
            REAL
        );
    }

    /// Install data for an account whose members are derived from `tag`
    function installData(WotsParams memory p, string memory tag, uint256 members, uint8 threshold)
        external
        pure
        returns (bytes memory)
    {
        WotsKey[] memory keys = new WotsKey[](members);
        for (uint256 i; i < members; ++i) {
            keys[i] = _key(p, tag, i);
        }
        return Ops.installData(keys, threshold);
    }

    /// Signature entries of the given members (strictly increasing) for one key index
    function sign(
        WotsParams memory p,
        string memory tag,
        uint256[] memory signers,
        uint256 slot,
        uint256 keyIndex,
        bytes32 userOpHash
    ) external pure returns (bytes memory sig) {
        for (uint256 i; i < signers.length; ++i) {
            sig = bytes.concat(
                sig, Ops.memberSignature(_key(p, tag, signers[i]), signers[i], slot, keyIndex, userOpHash)
            );
        }
    }
}
