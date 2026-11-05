// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {WinterlockValidator} from "../../src/WinterlockValidator.sol";
import {WotsVerifier} from "../../src/WotsVerifier.sol";
import {IStatelessVerifier} from "../../src/interfaces/IStatelessVerifier.sol";
import {StatelessKey, StatelessSigner} from "./StatelessSigner.sol";

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

/// Keys of one member (D12): a stateless key, whose public key is all the install data holds (the same on every chain,
/// D10), and an operation tree for one account on one chain, certified by the stateless key for sequence numbers
/// from `start` on.
/// The operation tree's public seed comes from the validator (statelessTreeSeed), so `ops` is built for an account
/// and a chain: Ops.forAccount, which the signing helpers call.
/// The stateless key's keygen is costly (about 0.25 s in Forge), so tests that use a key often generate it once,
/// keep it in storage, and pass it to Ops.keys.
struct MemberKeys {
    WotsParams p;
    string label; // operation tree secrets derive from it
    uint256 h; // operation tree height
    uint256 k; // log2 of its real keys
    uint256 tree; // which of the member's operation trees: a signer gives every chain its own
    uint64 start; // first sequence number the operation tree signs for
    StatelessKey sk; // the stateless key; its public key is the member's install data
    WotsKey ops; // the operation tree, once built for an account and a chain (forAccount)
}

library Ops {
    uint256 internal constant MAX_PRIORITY_FEE = 1 gwei;
    uint256 internal constant MAX_FEE = 10 gwei;
    /// The vendored leanSphincs verifier, compiled with via-IR (foundry.toml: compilation_restrictions). Deployed
    /// from its artifact, so that nothing else imports it and it is compiled once.
    string internal constant STATELESS_VERIFIER_ARTIFACT = "LeanSphincsAsm.sol:LeanSphincsAsm";
    uint256 internal constant FLAG_CERTIFICATE = 0x80;
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// Deploys a stateless verifier (tests and local scripts; deterministic deployments use ValidatorDeployment)
    function deployStatelessVerifier() internal returns (IStatelessVerifier) {
        return IStatelessVerifier(VM.deployCode(STATELESS_VERIFIER_ARTIFACT));
    }

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

    /// Test keys for one member, derived from a public label: the stateless key (keygen of a kept subtree of height
    /// 10) and the parameters of its operation trees (height h, 2^k real keys), tree 0 from sequence 0
    function keys(WotsParams memory p, string memory label, uint256 h, uint256 k)
        internal
        pure
        returns (MemberKeys memory)
    {
        return keys(p, label, h, k, StatelessSigner.testKey(label));
    }

    /// The same with a stateless key generated before (StatelessSigner.testKey)
    function keys(WotsParams memory p, string memory label, uint256 h, uint256 k, StatelessKey memory sk)
        internal
        pure
        returns (MemberKeys memory m)
    {
        m.p = p;
        m.label = label;
        m.h = h;
        m.k = k;
        m.sk = sk;
    }

    /// The member's stateless public key (root ‖ P): its install data
    function publicKey(MemberKeys memory m) internal pure returns (bytes32) {
        return StatelessSigner.publicKey(m.sk);
    }

    /// m with an operation tree certified from sequence `start`: a rotation, or a fresh tree after a loss of state
    function startingAt(MemberKeys memory m, uint64 start) internal pure returns (MemberKeys memory) {
        m.start = start;
        return m;
    }

    /// Operation tree `tree` of the label, certified from `start`, with the public seed the validator derives for it
    function opsTree(
        WotsParams memory p,
        string memory label,
        uint256 tree,
        uint64 start,
        uint128 seed,
        uint256 h,
        uint256 k
    ) internal pure returns (WotsKey memory) {
        return WotsTree.create(p, seed, keccak256(abi.encode(label, "ops sk", tree, start)), h, k);
    }

    /// m with its operation tree built for member `memberIndex` of `account` on this chain
    function forAccount(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory m)
        internal
        view
        returns (MemberKeys memory)
    {
        m.ops = opsTree(m.p, m.label, m.tree, m.start, val.statelessTreeSeed(account, memberIndex, m.start), m.h, m.k);
        return m;
    }

    /// The certificate for m's operation tree (from m.start) for `account` on `val`'s chain
    function certificate(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory m)
        internal
        view
        returns (bytes memory)
    {
        return _certificate(val, account, memberIndex, forAccount(val, account, memberIndex, m));
    }

    /// The certificate for m's operation tree; m.ops must be built
    function _certificate(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory m)
        private
        view
        returns (bytes memory)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest = val.statelessCertificateDigest(account, memberIndex, m.ops.root, uint8(m.ops.height), m.start);
        return certificateFor(m, digest);
    }

    /// [root: 32][height: 1][start: 8][stateless signature], with the stateless key signing `digest`
    /// (WinterlockValidator.statelessCertificateDigest on the target chain). m.ops must be built.
    function certificateFor(MemberKeys memory m, bytes32 digest) internal pure returns (bytes memory) {
        return certificateFor(m.ops, m.start, m.sk, digest);
    }

    function certificateFor(WotsKey memory ops, uint64 start, StatelessKey memory sk, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(ops.root, uint8(ops.height), start, StatelessSigner.sign(sk, digest));
    }

    /// One member's entry: [member index][flags][certificate?][WOTS signature][path] for the operation at `sequence`;
    /// m.ops must be built (forAccount)
    function entry(
        MemberKeys memory m,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes memory cert,
        bytes32 userOpHash
    ) internal pure returns (bytes memory) {
        return entry(m.ops, m.start, memberIndex, slot, sequence, cert, userOpHash);
    }

    function entry(
        WotsKey memory ops,
        uint64 start,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes memory cert,
        bytes32 userOpHash
    ) internal pure returns (bytes memory) {
        uint256 keyIndex = (sequence - start) * 2 + slot;
        return abi.encodePacked(
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(memberIndex),
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(slot | (cert.length == 0 ? 0 : FLAG_CERTIFICATE)),
            cert,
            WotsSigner.sign(ops.p, ops.seed, ops.skSeed, keyIndex, userOpHash),
            WotsTree.path(ops, keyIndex)
        );
    }

    /// One member's entry, with a certificate if the validator doesn't have this operation tree for the member
    /// yet (first operation on this chain, a rotation, or a fresh tree after a loss of state)
    function memberSignature(
        WinterlockValidator val,
        address account,
        MemberKeys memory m,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes32 userOpHash
    ) internal view returns (bytes memory) {
        m = forAccount(val, account, memberIndex, m);
        bytes memory cert;
        if (val.tree(account, memberIndex).root != m.ops.root) cert = _certificate(val, account, memberIndex, m);
        return entry(m, memberIndex, slot, sequence, cert, userOpHash);
    }

    /// One member's ERC-1271 entry for `hash` checked by `account`:
    /// [member index: 1][stateless signature of messageDigest]
    function messageEntry(
        WinterlockValidator val,
        address account,
        MemberKeys memory m,
        uint256 memberIndex,
        bytes32 hash
    ) internal view returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(uint8(memberIndex), StatelessSigner.sign(m.sk, val.messageDigest(account, hash)));
    }

    /// Signature of a 1-of-1 account (member 0) for `op`
    function wotsSignature(
        WinterlockValidator val,
        MemberKeys memory m,
        uint256 slot,
        PackedUserOperation memory op,
        bytes32 userOpHash
    ) internal view returns (bytes memory) {
        return memberSignature(val, op.sender, m, 0, slot, uint64(op.nonce), userOpHash);
    }

    /// The members' stateless public keys
    function publicKeys(MemberKeys[] memory ms) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](ms.length);
        for (uint256 i; i < ms.length; ++i) {
            out[i] = publicKey(ms[i]);
        }
    }

    /// Install data on nonce lane 0: the members' stateless public keys and the threshold
    function installData(bytes32[] memory statelessKeys, uint8 threshold) internal pure returns (bytes memory) {
        return abi.encode(uint192(0), threshold, statelessKeys);
    }

    /// Install data for a 1-of-1 account on nonce lane 0
    function installData(MemberKeys memory m) internal pure returns (bytes memory) {
        bytes32[] memory statelessKeys = new bytes32[](1);
        statelessKeys[0] = publicKey(m);
        return installData(statelessKeys, 1);
    }

    /// Install data for a threshold account on nonce lane 0
    function installData(MemberKeys[] memory ms, uint8 threshold) internal pure returns (bytes memory) {
        return installData(publicKeys(ms), threshold);
    }
}
