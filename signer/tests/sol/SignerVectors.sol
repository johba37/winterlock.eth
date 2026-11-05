// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WotsParams, WotsKey, WotsSigner, WotsTree} from "../../../contracts/test/utils/WotsSigner.sol";
import {StatelessKey, StatelessSigner} from "../../../contracts/test/utils/StatelessSigner.sol";

/// @notice Known answers for the Python signer (signer/), from the repository's Solidity reference signers
///         (contracts/test/utils/WotsSigner.sol and StatelessSigner.sol). Called with eth_call on a local anvil by
///         signer/tools/gen_vectors.py; nothing here is secret.
contract SignerVectors {
    /// D6: n = 24, target sum 431, w = 16, keccak
    function _p() internal pure returns (WotsParams memory) {
        return WotsParams(24, 431, 4, 0);
    }

    function wotsLeaf(uint128 seed, bytes32 skSeed, uint256 keyIndex) external pure returns (bytes32) {
        return WotsSigner.leaf(_p(), seed, skSeed, keyIndex);
    }

    function wotsSign(uint128 seed, bytes32 skSeed, uint256 keyIndex, bytes32 message)
        external
        pure
        returns (bytes memory)
    {
        return WotsSigner.sign(_p(), seed, skSeed, keyIndex, message);
    }

    /// Root of a tree of `height` whose first 2^k leaves are real (WotsTree.create), and the path of `index`
    function wotsTree(uint128 seed, bytes32 skSeed, uint256 height, uint256 k, uint256 index)
        external
        pure
        returns (bytes32 root, bytes memory path)
    {
        WotsKey memory t = WotsTree.create(_p(), seed, skSeed, height, k);
        return (t.root, WotsTree.path(t, index));
    }

    /// The stateless public key (root ‖ P) of a key with a kept subtree of height b
    function statelessKey(bytes32 seed, uint256 b) external pure returns (bytes32) {
        return StatelessSigner.publicKey(StatelessSigner.keygen(seed, b));
    }

    function statelessSign(bytes32 seed, uint256 b, bytes32 message) external pure returns (bytes memory) {
        return StatelessSigner.sign(StatelessSigner.keygen(seed, b), message);
    }
}
