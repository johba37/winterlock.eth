// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice A parameter set: hash size n (bytes) and targetSum (0 = checksum encoding).
struct WotsParams {
    uint256 n;
    uint256 targetSum;
}

/// @notice Reference signer in plain Solidity, written separately from the assembly verifier so the
///         two cross-check each other. Test and benchmark use only: secrets are derived from an
///         in-contract seed.
library WotsSigner {
    uint256 internal constant MAX_TRIES = 1_000_000;

    function chains(WotsParams memory p) internal pure returns (uint256) {
        return 2 * p.n + (p.targetSum == 0 ? 3 : 0);
    }

    function trunc(WotsParams memory p, bytes32 x) internal pure returns (bytes32) {
        return x & bytes32(~(type(uint256).max >> (8 * p.n)));
    }

    /// The first n bytes of x, as a byte string.
    function pack(WotsParams memory p, bytes32 x) internal pure returns (bytes memory b) {
        b = new bytes(p.n);
        assembly {
            mstore(add(b, 32), x)
        }
    }

    function tweak(uint128 seed, uint256 typ, uint256 index, uint256 chainIdx, uint256 step)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((uint256(seed) << 128) | (typ << 120) | (index << 56) | (chainIdx << 48) | (step << 40));
    }

    function secret(WotsParams memory p, bytes32 skSeed, uint256 keyIndex, uint256 i) internal pure returns (bytes32) {
        return trunc(p, keccak256(abi.encode("winterlock.test.sk", skSeed, keyIndex, i)));
    }

    function chain(WotsParams memory p, uint128 seed, uint256 keyIndex, uint256 i, bytes32 x, uint256 from, uint256 to)
        internal
        pure
        returns (bytes32)
    {
        for (uint256 j = from; j < to; ++j) {
            x = trunc(p, keccak256(abi.encodePacked(tweak(seed, 0, keyIndex, i, j), x)));
        }
        return x;
    }

    /// The value at position `steps` on chain i of key keyIndex.
    function chainValue(WotsParams memory p, uint128 seed, bytes32 skSeed, uint256 keyIndex, uint256 i, uint256 steps)
        internal
        pure
        returns (bytes32)
    {
        bytes32 s0 = secret(p, skSeed, keyIndex, i);
        return chain(p, seed, keyIndex, i, s0, 0, steps);
    }

    function digest(WotsParams memory p, uint128 seed, uint256 keyIndex, bytes32 r, bytes32 message)
        internal
        pure
        returns (bytes32)
    {
        return trunc(p, keccak256(abi.encodePacked(tweak(seed, 3, keyIndex, 0, 0), r, message)));
    }

    /// Digits for a digest: 2n message nibbles, then 3 checksum nibbles unless the target-sum encoding is used.
    function digits(WotsParams memory p, bytes32 d) internal pure returns (uint256[] memory a, uint256 sum) {
        uint256 len1 = 2 * p.n;
        a = new uint256[](chains(p));
        for (uint256 i; i < len1; ++i) {
            a[i] = (uint256(d) >> (252 - 4 * i)) & 0xf;
            sum += a[i];
        }
        if (p.targetSum == 0) {
            uint256 csum = 15 * len1 - sum;
            a[len1] = (csum >> 8) & 0xf;
            a[len1 + 1] = (csum >> 4) & 0xf;
            a[len1 + 2] = csum & 0xf;
        }
    }

    function randomizer(WotsParams memory p, bytes32 skSeed, uint256 keyIndex, bytes32 message, uint256 counter)
        internal
        pure
        returns (bytes32)
    {
        return trunc(p, keccak256(abi.encode("winterlock.test.R", skSeed, keyIndex, message, counter)));
    }

    /// Sum of the first `count` nibbles of d, without allocating.
    function nibbleSum(bytes32 d, uint256 count) internal pure returns (uint256 sum) {
        for (uint256 i; i < count; ++i) {
            sum += (uint256(d) >> (252 - 4 * i)) & 0xf;
        }
    }

    /// Picks the randomizer (retrying until the digits hit the target sum, if one is set) and returns
    /// the digits and the randomizer.
    function encode(WotsParams memory p, uint128 seed, bytes32 skSeed, uint256 keyIndex, bytes32 message)
        internal
        pure
        returns (uint256[] memory a, bytes32 r)
    {
        for (uint256 c; c < MAX_TRIES; ++c) {
            r = randomizer(p, skSeed, keyIndex, message, c);
            bytes32 d = digest(p, seed, keyIndex, r, message);
            if (p.targetSum == 0 || nibbleSum(d, 2 * p.n) == p.targetSum) {
                (a,) = digits(p, d);
                return (a, r);
            }
        }
        revert("target sum not reached");
    }

    function leaf(WotsParams memory p, uint128 seed, bytes32 skSeed, uint256 keyIndex) internal pure returns (bytes32) {
        uint256 len = chains(p);
        bytes32[] memory ends = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            ends[i] = chainValue(p, seed, skSeed, keyIndex, i, 15);
        }
        return trunc(p, keccak256(abi.encodePacked(tweak(seed, 1, keyIndex, 0, 0), ends)));
    }

    /// Chain values for given digits: [R][x_0]...[x_len-1], n bytes each.
    function signDigits(
        WotsParams memory p,
        uint128 seed,
        bytes32 skSeed,
        uint256 keyIndex,
        uint256[] memory a,
        bytes32 r
    ) internal pure returns (bytes memory sig) {
        sig = pack(p, r);
        for (uint256 i; i < a.length; ++i) {
            bytes32 x = chainValue(p, seed, skSeed, keyIndex, i, a[i]);
            sig = bytes.concat(sig, pack(p, x));
        }
    }

    function sign(WotsParams memory p, uint128 seed, bytes32 skSeed, uint256 keyIndex, bytes32 message)
        internal
        pure
        returns (bytes memory)
    {
        (uint256[] memory a, bytes32 r) = encode(p, seed, skSeed, keyIndex, message);
        return signDigits(p, seed, skSeed, keyIndex, a, r);
    }

    function node(WotsParams memory p, uint128 seed, uint256 level, uint256 index, bytes32 left, bytes32 right)
        internal
        pure
        returns (bytes32)
    {
        return trunc(p, keccak256(abi.encodePacked(tweak(seed, 2, index, 0, level), left, right)));
    }
}

/// @notice A key tree whose leaves [0, 2^k) are real and whose levels above k use fixed pseudo-random
///         siblings. Verification cost depends only on the height, so a tall tree can be benchmarked
///         without generating 2^height keys.
struct WotsKey {
    WotsParams p;
    uint128 seed;
    bytes32 skSeed;
    uint256 height;
    uint256 k;
    bytes32[][] levels;
    bytes32[] upper;
    bytes32 root;
}

library WotsTree {
    function create(WotsParams memory p, uint128 seed, bytes32 skSeed, uint256 height, uint256 k)
        internal
        pure
        returns (WotsKey memory key)
    {
        require(k <= height, "k > height");
        key.p = p;
        key.seed = seed;
        key.skSeed = skSeed;
        key.height = height;
        key.k = k;
        key.levels = new bytes32[][](k + 1);
        uint256 n = 1 << k;
        key.levels[0] = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            key.levels[0][i] = WotsSigner.leaf(p, seed, skSeed, i);
        }
        for (uint256 l = 1; l <= k; ++l) {
            uint256 m = n >> l;
            key.levels[l] = new bytes32[](m);
            for (uint256 i; i < m; ++i) {
                key.levels[l][i] =
                    WotsSigner.node(p, seed, l, i, key.levels[l - 1][2 * i], key.levels[l - 1][2 * i + 1]);
            }
        }
        key.upper = new bytes32[](height - k);
        bytes32 v = key.levels[k][0];
        for (uint256 l = k; l < height; ++l) {
            bytes32 sib = WotsSigner.trunc(p, keccak256(abi.encode("winterlock.test.sibling", skSeed, l)));
            key.upper[l - k] = sib;
            v = WotsSigner.node(p, seed, l + 1, 0, v, sib);
        }
        key.root = v;
    }

    function path(WotsKey memory key, uint256 index) internal pure returns (bytes memory out) {
        require(index < (1 << key.k), "index outside real subtree");
        for (uint256 l; l < key.k; ++l) {
            out = bytes.concat(out, WotsSigner.pack(key.p, key.levels[l][(index >> l) ^ 1]));
        }
        for (uint256 l = key.k; l < key.height; ++l) {
            out = bytes.concat(out, WotsSigner.pack(key.p, key.upper[l - key.k]));
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
            uint8(slot),
            WotsSigner.sign(key.p, key.seed, key.skSeed, keyIndex, userOpHash),
            WotsTree.path(key, keyIndex)
        );
    }
}
