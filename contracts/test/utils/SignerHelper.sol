// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WotsParams, WotsKey, Ops} from "./WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "./StatelessSigner.sol";

/// @notice Test only. Exposes the reference signers through eth_call, so tools outside Foundry (the bundler
///         acceptance driver) can produce WOTS signatures, certificates and install data. Keys are derived from a
///         PUBLIC tag, so anyone can sign with them: tests only, never real funds.
///         Each member has a stateless leanSphincs key (its install data, D12) and operation trees of height 20 with
///         real leaves for key indices 0..3 (nonces 0 and 1, both slots). Operation tree t is certified by the
///         stateless key from sequence 0: give every chain its own t, so that no two chains share tree secrets.
///         The helper can run on any node: the tree seed and the certificate digest come from the validator on the
///         target chain (WinterlockValidator.statelessTreeSeed with start 0, statelessCertificateDigest), passed in
///         by the caller.
/// @dev    The stateless key is costly in gas: keygen about 50M, a signature about 55M. Call installData and
///         certificate with a high gas limit, on a node without an eth_call gas cap or time limit.
contract WotsSignerHelper {
    uint256 internal constant HEIGHT = 20;
    uint256 internal constant REAL = 2;

    function _label(string memory tag, uint256 member) internal pure returns (string memory) {
        return string(abi.encode(tag, member));
    }

    /// A member's operation tree `treeIndex` from sequence 0, built with the seed the target chain's validator
    /// derives for it
    function _tree(WotsParams memory p, string memory tag, uint256 member, uint256 treeIndex, uint128 seed)
        internal
        pure
        returns (WotsKey memory)
    {
        return Ops.opsTree(p, _label(tag, member), treeIndex, 0, seed, HEIGHT, REAL);
    }

    function _statelessKey(string memory tag, uint256 member) internal pure returns (StatelessKey memory) {
        return StatelessSigner.testKey(_label(tag, member));
    }

    /// Install data for an account whose members are derived from `tag`: their stateless public keys
    function installData(WotsParams memory, string memory tag, uint256 members, uint8 threshold)
        external
        pure
        returns (bytes memory)
    {
        bytes32[] memory keys = new bytes32[](members);
        for (uint256 i; i < members; ++i) {
            keys[i] = StatelessSigner.publicKey(_statelessKey(tag, i));
        }
        return Ops.installData(keys, threshold);
    }

    /// A member's operation tree and the first sequence it covers, for WinterlockValidator.statelessCertificateDigest
    function tree(WotsParams memory p, string memory tag, uint256 member, uint256 treeIndex, uint128 seed)
        external
        pure
        returns (bytes32 root, uint8 height, uint64 start)
    {
        WotsKey memory ops = _tree(p, tag, member, treeIndex, seed);
        // forge-lint: disable-next-line(unsafe-typecast)
        return (ops.root, uint8(ops.height), 0);
    }

    /// A member's certificate for its operation tree, given the digest from the target chain's validator
    function certificate(
        WotsParams memory p,
        string memory tag,
        uint256 member,
        uint256 treeIndex,
        uint128 seed,
        bytes32 digest
    ) external pure returns (bytes memory) {
        return Ops.certificateFor(_tree(p, tag, member, treeIndex, seed), 0, _statelessKey(tag, member), digest);
    }

    /// Signature entries of the given members (strictly increasing) for the operation at `sequence`;
    /// seeds[i] is WinterlockValidator.statelessTreeSeed (start 0) for member signers[i], and certs[i] its
    /// certificate, or empty once its tree is enrolled on the target chain
    function sign(
        WotsParams memory p,
        string memory tag,
        uint256 treeIndex,
        uint256[] memory signers,
        uint128[] memory seeds,
        uint256 slot,
        uint256 sequence,
        bytes[] memory certs,
        bytes32 userOpHash
    ) external pure returns (bytes memory sig) {
        for (uint256 i; i < signers.length; ++i) {
            sig = bytes.concat(
                sig,
                Ops.entry(
                    _tree(p, tag, signers[i], treeIndex, seeds[i]), 0, signers[i], slot, sequence, certs[i], userOpHash
                )
            );
        }
    }
}
