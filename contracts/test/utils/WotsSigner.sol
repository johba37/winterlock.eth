// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {WotsVerifier} from "../../src/WotsVerifier.sol";

/// @notice A parameter set: hash size n (bytes), targetSum (0 = checksum encoding), log2(w), and the
///         hash function (0 = keccak256, 1 = SHA-256).
struct WotsParams {
    uint256 n;
    uint256 targetSum;
    uint256 logW;
    uint256 hashFn;
}

/// @notice Reference signer in plain Solidity, written separately from the assembly verifier so the
///         two cross-check each other. Test and benchmark use only: secrets are derived from an
///         in-contract seed.
library WotsSigner {
    uint256 internal constant MAX_TRIES = 1_000_000;

    function wm1(WotsParams memory p) internal pure returns (uint256) {
        return (1 << p.logW) - 1;
    }

    function messageDigits(WotsParams memory p) internal pure returns (uint256) {
        return 8 * p.n / p.logW;
    }

    function checksumDigits(WotsParams memory p) internal pure returns (uint256 count) {
        uint256 max = messageDigits(p) * wm1(p);
        count = 1;
        while ((1 << (p.logW * count)) <= max) ++count;
    }

    function chains(WotsParams memory p) internal pure returns (uint256) {
        return messageDigits(p) + (p.targetSum == 0 ? checksumDigits(p) : 0);
    }

    /// The tweakable hash: keccak256 or SHA-256, truncated to n bytes
    function H(WotsParams memory p, bytes memory data) internal pure returns (bytes32) {
        return trunc(p, p.hashFn == 0 ? keccak256(data) : sha256(data));
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
            x = H(p, abi.encodePacked(tweak(seed, 0, keyIndex, i, j), x));
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
        return H(p, abi.encodePacked(tweak(seed, 3, keyIndex, 0, 0), r, message));
    }

    /// Digits for a digest: 8n/log2(w) message digits, then checksum digits unless a target sum is used.
    function digits(WotsParams memory p, bytes32 d) internal pure returns (uint256[] memory a, uint256 sum) {
        uint256 len1 = messageDigits(p);
        a = new uint256[](chains(p));
        for (uint256 i; i < len1; ++i) {
            a[i] = (uint256(d) >> (256 - (i + 1) * p.logW)) & wm1(p);
            sum += a[i];
        }
        if (p.targetSum == 0) {
            uint256 csum = wm1(p) * len1 - sum;
            uint256 len2 = checksumDigits(p);
            for (uint256 j; j < len2; ++j) {
                a[len1 + j] = (csum >> (p.logW * (len2 - 1 - j))) & wm1(p);
            }
        }
    }

    function randomizer(WotsParams memory p, bytes32 skSeed, uint256 keyIndex, bytes32 message, uint256 counter)
        internal
        pure
        returns (bytes32)
    {
        return trunc(p, keccak256(abi.encode("winterlock.test.R", skSeed, keyIndex, message, counter)));
    }

    /// Sum of the message digits of d, without allocating.
    function digitSum(WotsParams memory p, bytes32 d) internal pure returns (uint256 sum) {
        uint256 len1 = messageDigits(p);
        for (uint256 i; i < len1; ++i) {
            sum += (uint256(d) >> (256 - (i + 1) * p.logW)) & wm1(p);
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
            if (p.targetSum == 0 || digitSum(p, d) == p.targetSum) {
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
            ends[i] = chainValue(p, seed, skSeed, keyIndex, i, wm1(p));
        }
        return H(p, abi.encodePacked(tweak(seed, 1, keyIndex, 0, 0), ends));
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
        return H(p, abi.encodePacked(tweak(seed, 2, index, 0, level), left, right));
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

/// D10 keys of one member: a master tree (in the install data, the same on every chain) and an operation tree
/// for one chain, certified by master key `masterIndex` for sequence numbers from `start` on.
struct MemberKeys {
    WotsKey master;
    WotsKey ops;
    uint256 masterIndex;
    uint64 start;
}

library Ops {
    uint256 internal constant MAX_PRIORITY_FEE = 1 gwei;
    uint256 internal constant MAX_FEE = 10 gwei;

    /// Packed parameter word for WotsVerifier and WinterlockValidator
    function params(WotsParams memory p) internal pure returns (uint256) {
        return WotsVerifier.encodeParams(p.n, p.logW, p.hashFn, p.targetSum);
    }

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

    /// Master tree height for tests and tools (D10: 64 certificates)
    uint256 internal constant MASTER_HEIGHT = 6;

    /// Test keys for one member, derived from a public label: a master tree of height 6 with 4 real keys, and an
    /// operation tree of height h with 2^k real keys, certified by master key 0 from sequence 0.
    function keys(WotsParams memory p, string memory label, uint256 h, uint256 k)
        internal
        pure
        returns (MemberKeys memory m)
    {
        m.master = WotsTree.create(
            p,
            uint128(uint256(keccak256(abi.encode(label, "master seed")))),
            keccak256(abi.encode(label, "master sk")),
            MASTER_HEIGHT,
            2
        );
        m.ops = opsTree(p, label, 0, h, k);
    }

    /// The label's operation tree number `epoch`
    function opsTree(WotsParams memory p, string memory label, uint256 epoch, uint256 h, uint256 k)
        internal
        pure
        returns (WotsKey memory)
    {
        return WotsTree.create(
            p,
            uint128(uint256(keccak256(abi.encode(label, "ops seed", epoch)))),
            keccak256(abi.encode(label, "ops sk", epoch)),
            h,
            k
        );
    }

    /// The certificate for `k`'s operation tree on `val`'s chain
    function certificate(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory k)
        internal
        view
        returns (bytes memory)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest =
            val.certificateDigest(account, memberIndex, k.ops.root, k.ops.seed, uint8(k.ops.height), k.start);
        return certificateFor(k, digest);
    }

    /// [master index: 2][root: 32][seed: 16][height: 1][start: 8][master WOTS signature][master path], with the
    /// master key signing `digest` (WinterlockValidator.certificateDigest on the target chain)
    function certificateFor(MemberKeys memory k, bytes32 digest) internal pure returns (bytes memory) {
        return abi.encodePacked(
            // forge-lint: disable-next-line(unsafe-typecast)
            uint16(k.masterIndex),
            k.ops.root,
            k.ops.seed,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(k.ops.height),
            k.start,
            WotsSigner.sign(k.master.p, k.master.seed, k.master.skSeed, k.masterIndex, digest),
            WotsTree.path(k.master, k.masterIndex)
        );
    }

    /// One member's entry: [member index][flags][certificate?][WOTS signature][path] for the operation at `sequence`
    function entry(
        MemberKeys memory k,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes memory cert,
        bytes32 userOpHash
    ) internal pure returns (bytes memory) {
        uint256 keyIndex = (sequence - k.start) * 2 + slot;
        return abi.encodePacked(
            uint8(memberIndex),
            uint8(slot | (cert.length == 0 ? 0 : 0x80)),
            cert,
            WotsSigner.sign(k.ops.p, k.ops.seed, k.ops.skSeed, keyIndex, userOpHash),
            WotsTree.path(k.ops, keyIndex)
        );
    }

    /// One member's entry, with a certificate if the validator doesn't have this operation tree for the member
    /// yet (first operation on this chain, or a rotation)
    function memberSignature(
        WinterlockValidator val,
        address account,
        MemberKeys memory k,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes32 userOpHash
    ) internal view returns (bytes memory) {
        bytes memory cert;
        if (val.tree(account, memberIndex).root != k.ops.root) cert = certificate(val, account, memberIndex, k);
        return entry(k, memberIndex, slot, sequence, cert, userOpHash);
    }

    /// Signature of a 1-of-1 account (member 0) for `op`
    function wotsSignature(
        WinterlockValidator val,
        MemberKeys memory k,
        uint256 slot,
        PackedUserOperation memory op,
        bytes32 userOpHash
    ) internal view returns (bytes memory) {
        return memberSignature(val, op.sender, k, 0, slot, uint64(op.nonce), userOpHash);
    }

    /// Master trees of the members, for install data
    function masters(MemberKeys[] memory ks) internal pure returns (WotsKey[] memory out) {
        out = new WotsKey[](ks.length);
        for (uint256 i; i < ks.length; ++i) {
            out[i] = ks[i].master;
        }
    }

    function asMember(WotsKey memory key) internal pure returns (WinterlockValidator.Member memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return WinterlockValidator.Member(key.root, key.seed, uint8(key.height));
    }

    /// Install data for a 1-of-1 account on nonce lane 0 (key: the master tree)
    function installData(WotsKey memory key) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](1);
        members[0] = asMember(key);
        return abi.encode(uint192(0), uint8(1), members);
    }

    /// Install data for a threshold account on nonce lane 0 (keys: the members' master trees)
    function installData(WotsKey[] memory trees, uint8 threshold) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](trees.length);
        for (uint256 i; i < trees.length; ++i) {
            members[i] = asMember(trees[i]);
        }
        return abi.encode(uint192(0), threshold, members);
    }
}
