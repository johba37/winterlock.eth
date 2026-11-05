// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WotsParams, WotsKey, MemberKeys, Ops} from "./WotsSigner.sol";

/// @notice Test only. Exposes the reference signer through eth_call, so tools outside Foundry (the bundler
///         acceptance driver) can produce WOTS signatures and install data. Keys are derived from a PUBLIC
///         tag, so anyone can sign with them: tests only, never real funds.
///         Each member has a master tree (height 6) and operation trees of height 20 with real leaves for key
///         indices 0..3 (nonces 0 and 1, both slots). Operation tree t is certified by master key t from
///         sequence 0: give every chain its own t (D10).
///         The helper can run on any node: the certificate digest comes from the validator on the target chain
///         (WinterlockValidator.certificateDigest), passed in by the caller.
contract WotsSignerHelper {
    uint256 internal constant HEIGHT = 20;
    uint256 internal constant REAL = 2;

    function _keys(WotsParams memory p, string memory tag, uint256 member, uint256 treeIndex)
        internal
        pure
        returns (MemberKeys memory k)
    {
        string memory label = string(abi.encode(tag, member));
        k = Ops.keys(p, label, HEIGHT, REAL);
        if (treeIndex != 0) {
            k.ops = Ops.opsTree(p, label, treeIndex, HEIGHT, REAL);
            k.masterIndex = treeIndex;
        }
    }

    /// Install data for an account whose members are derived from `tag`
    function installData(WotsParams memory p, string memory tag, uint256 members, uint8 threshold)
        external
        pure
        returns (bytes memory)
    {
        WotsKey[] memory masters = new WotsKey[](members);
        for (uint256 i; i < members; ++i) {
            masters[i] = _keys(p, tag, i, 0).master;
        }
        return Ops.installData(masters, threshold);
    }

    /// A member's operation tree and the first sequence it covers, for WinterlockValidator.certificateDigest
    function tree(WotsParams memory p, string memory tag, uint256 member, uint256 treeIndex)
        external
        pure
        returns (bytes32 root, uint128 seed, uint8 height, uint64 start)
    {
        MemberKeys memory k = _keys(p, tag, member, treeIndex);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (k.ops.root, k.ops.seed, uint8(k.ops.height), k.start);
    }

    /// A member's certificate for its operation tree, given the digest from the target chain's validator
    function certificate(WotsParams memory p, string memory tag, uint256 member, uint256 treeIndex, bytes32 digest)
        external
        pure
        returns (bytes memory)
    {
        return Ops.certificateFor(_keys(p, tag, member, treeIndex), digest);
    }

    /// Signature entries of the given members (strictly increasing) for the operation at `sequence`;
    /// certs[i] is member signers[i]'s certificate, or empty once its tree is enrolled on the target chain
    function sign(
        WotsParams memory p,
        string memory tag,
        uint256 treeIndex,
        uint256[] memory signers,
        uint256 slot,
        uint256 sequence,
        bytes[] memory certs,
        bytes32 userOpHash
    ) external pure returns (bytes memory sig) {
        for (uint256 i; i < signers.length; ++i) {
            sig = bytes.concat(
                sig, Ops.entry(_keys(p, tag, signers[i], treeIndex), signers[i], slot, sequence, certs[i], userOpHash)
            );
        }
    }
}
