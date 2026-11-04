// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice Reference signer in plain Solidity, written separately from the assembly verifier so the
///         two cross-check each other. Test and benchmark use only: secrets are derived from an
///         in-contract seed.
library WotsSigner {
    uint256 internal constant LEN = 67;

    function tweak(uint128 seed, uint256 typ, uint256 index, uint256 chainIdx, uint256 step)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((uint256(seed) << 128) | (typ << 120) | (index << 56) | (chainIdx << 48) | (step << 40));
    }

    function secret(bytes32 skSeed, uint256 keyIndex, uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode("winterlock.test.sk", skSeed, keyIndex, i));
    }

    function chain(uint128 seed, uint256 keyIndex, uint256 i, bytes32 x, uint256 from, uint256 to)
        internal
        pure
        returns (bytes32)
    {
        for (uint256 j = from; j < to; ++j) {
            x = keccak256(abi.encodePacked(tweak(seed, 0, keyIndex, i, j), x));
        }
        return x;
    }

    function digits(uint128 seed, uint256 keyIndex, bytes32 message) internal pure returns (uint256[67] memory a) {
        uint256 d = uint256(keccak256(abi.encodePacked(tweak(seed, 3, keyIndex, 0, 0), message)));
        uint256 csum;
        for (uint256 i; i < 64; ++i) {
            a[i] = (d >> (252 - 4 * i)) & 0xf;
            csum += 15 - a[i];
        }
        a[64] = (csum >> 8) & 0xf;
        a[65] = (csum >> 4) & 0xf;
        a[66] = csum & 0xf;
    }

    function leaf(uint128 seed, bytes32 skSeed, uint256 keyIndex) internal pure returns (bytes32) {
        bytes32[67] memory ends;
        for (uint256 i; i < LEN; ++i) {
            ends[i] = chain(seed, keyIndex, i, secret(skSeed, keyIndex, i), 0, 15);
        }
        return keccak256(abi.encodePacked(tweak(seed, 1, keyIndex, 0, 0), ends));
    }

    function sign(uint128 seed, bytes32 skSeed, uint256 keyIndex, bytes32 message)
        internal
        pure
        returns (bytes memory)
    {
        uint256[67] memory a = digits(seed, keyIndex, message);
        bytes32[67] memory s;
        for (uint256 i; i < LEN; ++i) {
            s[i] = chain(seed, keyIndex, i, secret(skSeed, keyIndex, i), 0, a[i]);
        }
        return abi.encodePacked(s);
    }

    function node(uint128 seed, uint256 level, uint256 index, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(tweak(seed, 2, index, 0, level), left, right));
    }
}

/// @notice A key tree whose leaves [0, 2^k) are real and whose levels above k use fixed pseudo-random
///         siblings. Verification cost depends only on the height, so a tall tree can be benchmarked
///         without generating 2^height keys.
struct WotsKey {
    uint128 seed;
    bytes32 skSeed;
    uint256 height;
    uint256 k;
    bytes32[][] levels;
    bytes32[] upper;
    bytes32 root;
}

library WotsTree {
    function create(uint128 seed, bytes32 skSeed, uint256 height, uint256 k) internal pure returns (WotsKey memory key) {
        require(k <= height, "k > height");
        key.seed = seed;
        key.skSeed = skSeed;
        key.height = height;
        key.k = k;
        key.levels = new bytes32[][](k + 1);
        uint256 n = 1 << k;
        key.levels[0] = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            key.levels[0][i] = WotsSigner.leaf(seed, skSeed, i);
        }
        for (uint256 l = 1; l <= k; ++l) {
            uint256 m = n >> l;
            key.levels[l] = new bytes32[](m);
            for (uint256 i; i < m; ++i) {
                key.levels[l][i] = WotsSigner.node(seed, l, i, key.levels[l - 1][2 * i], key.levels[l - 1][2 * i + 1]);
            }
        }
        key.upper = new bytes32[](height - k);
        bytes32 v = key.levels[k][0];
        for (uint256 l = k; l < height; ++l) {
            bytes32 sib = keccak256(abi.encode("winterlock.test.sibling", skSeed, l));
            key.upper[l - k] = sib;
            v = WotsSigner.node(seed, l + 1, 0, v, sib);
        }
        key.root = v;
    }

    function path(WotsKey memory key, uint256 index) internal pure returns (bytes memory p) {
        require(index < (1 << key.k), "index outside real subtree");
        for (uint256 l; l < key.k; ++l) {
            p = abi.encodePacked(p, key.levels[l][(index >> l) ^ 1]);
        }
        for (uint256 l = key.k; l < key.height; ++l) {
            p = abi.encodePacked(p, key.upper[l - key.k]);
        }
    }
}

library Ops {
    uint256 internal constant MAX_PRIORITY_FEE = 1 gwei;
    uint256 internal constant MAX_FEE = 10 gwei;

    function build(address sender, uint256 nonce, bytes memory callData, uint256 verificationGasLimit)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        op.sender = sender;
        op.nonce = nonce;
        op.callData = callData;
        op.accountGasLimits = bytes32((verificationGasLimit << 128) | 60_000);
        op.preVerificationGas = 60_000;
        op.gasFees = bytes32((MAX_PRIORITY_FEE << 128) | MAX_FEE);
    }

    /// [slot][WOTS signature][path] for the key at keyIndex
    function wotsSignature(WotsKey memory key, uint256 slot, uint256 keyIndex, bytes32 userOpHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(slot), WotsSigner.sign(key.seed, key.skSeed, keyIndex, userOpHash), WotsTree.path(key, keyIndex)
        );
    }
}
