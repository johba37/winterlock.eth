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

/// Keys of one member: a master tree and a stateless public key (in the install data, the same on every chain,
/// D10 and D11), and an operation tree for one account on one chain, certified for sequence numbers from `start` on
/// by master key `masterIndex` or, if `stateless`, by the stateless key.
/// The operation tree's public seed comes from the validator (treeSeed, statelessTreeSeed), so `ops` is built for
/// an account and a chain: Ops.forAccount, which the signing helpers call.
/// The stateless secret key (StatelessKey) is kept apart, since its keygen is costly: Ops.keys sets a placeholder
/// public key that nobody can sign for, and Ops.withStateless replaces it with a real one.
struct MemberKeys {
    WotsKey master;
    WotsKey ops;
    uint256 masterIndex;
    uint64 start;
    string label; // keys derive from it
    uint256 h; // operation tree height
    uint256 k; // log2 of its real keys
    bytes32 statelessKey; // the stateless public key in the install data: root ‖ P
    bool stateless; // the operation tree is certified by the stateless key
}

library Ops {
    uint256 internal constant MAX_PRIORITY_FEE = 1 gwei;
    uint256 internal constant MAX_FEE = 10 gwei;
    /// The vendored leanSphincs verifier, compiled with via-IR (foundry.toml: compilation_restrictions). Deployed
    /// from its artifact, so that nothing else imports it and it is compiled once.
    string internal constant STATELESS_VERIFIER_ARTIFACT = "LeanSphincsAsm.sol:LeanSphincsAsm";
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

    /// Master tree height for tests and tools (D10: 64 certificates)
    uint256 internal constant MASTER_HEIGHT = 6;

    /// Test keys for one member, derived from a public label: a master tree of height 6 with 4 real keys, and the
    /// parameters of its operation trees (height h, 2^k real keys), certified by master key 0 from sequence 0
    function keys(WotsParams memory p, string memory label, uint256 h, uint256 k)
        internal
        pure
        returns (MemberKeys memory m)
    {
        m.master = master(p, label);
        m.label = label;
        m.h = h;
        m.k = k;
        m.statelessKey = placeholderStatelessKey(m.master);
    }

    /// A stateless public key for members whose tests never sign with it: a hash, so no one has its secret key
    function placeholderStatelessKey(WotsKey memory masterKey) internal pure returns (bytes32) {
        return keccak256(abi.encode("winterlock.test.stateless placeholder", masterKey.root));
    }

    /// m with a real stateless key
    function withStateless(MemberKeys memory m, StatelessKey memory sk) internal pure returns (MemberKeys memory) {
        m.statelessKey = StatelessSigner.publicKey(sk);
        return m;
    }

    /// m with an operation tree certified by its stateless key from sequence `start`
    function statelessTree(MemberKeys memory m, uint64 start) internal pure returns (MemberKeys memory) {
        m.stateless = true;
        m.start = start;
        return m;
    }

    /// What the validator computes for m's master tree (WinterlockValidator.masterCommitment)
    function masterCommitment(MemberKeys memory m) internal pure returns (bytes32) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return keccak256(abi.encode(m.master.root, m.master.seed, uint8(m.master.height)));
    }

    function master(WotsParams memory p, string memory label) internal pure returns (WotsKey memory) {
        return WotsTree.create(
            p,
            uint128(uint256(keccak256(abi.encode(label, "master seed")))),
            keccak256(abi.encode(label, "master sk")),
            MASTER_HEIGHT,
            2
        );
    }

    /// The label's operation tree for master key `masterIndex`, with the public seed the validator derives
    function opsTree(WotsParams memory p, string memory label, uint256 masterIndex, uint128 seed, uint256 h, uint256 k)
        internal
        pure
        returns (WotsKey memory)
    {
        return WotsTree.create(p, seed, keccak256(abi.encode(label, "ops sk", masterIndex)), h, k);
    }

    /// m with its operation tree built for member `memberIndex` of `account` on this chain
    function forAccount(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory m)
        internal
        view
        returns (MemberKeys memory)
    {
        if (m.stateless) {
            uint128 seed = val.statelessTreeSeed(account, memberIndex, m.start);
            m.ops = WotsTree.create(
                m.master.p, seed, keccak256(abi.encode(m.label, "stateless ops sk", m.start)), m.h, m.k
            );
        } else {
            uint128 seed = val.treeSeed(account, memberIndex, m.masterIndex);
            m.ops = opsTree(m.master.p, m.label, m.masterIndex, seed, m.h, m.k);
        }
        return m;
    }

    /// The certificate for `k`'s operation tree for `account` on `val`'s chain
    function certificate(WinterlockValidator val, address account, uint256 memberIndex, MemberKeys memory k)
        internal
        view
        returns (bytes memory)
    {
        k = forAccount(val, account, memberIndex, k);
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest = val.certificateDigest(account, memberIndex, k.ops.root, uint8(k.ops.height), k.start);
        return certificateFor(k, digest);
    }

    /// [master index: 2][root: 32][height: 1][start: 8][master seed: 16][master height: 1][stateless key: 32]
    /// [master WOTS signature][master path], with the master key signing `digest`
    /// (WinterlockValidator.certificateDigest on the target chain). k.ops must be built.
    function certificateFor(MemberKeys memory k, bytes32 digest) internal pure returns (bytes memory) {
        return abi.encodePacked(
            // forge-lint: disable-next-line(unsafe-typecast)
            uint16(k.masterIndex),
            k.ops.root,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(k.ops.height),
            k.start,
            k.master.seed,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(k.master.height),
            k.statelessKey,
            WotsSigner.sign(k.master.p, k.master.seed, k.master.skSeed, k.masterIndex, digest),
            WotsTree.path(k.master, k.masterIndex)
        );
    }

    /// The stateless certificate for `k`'s operation tree (k.stateless, from k.start) for `account` on `val`'s chain
    function statelessCertificate(
        WinterlockValidator val,
        address account,
        uint256 memberIndex,
        MemberKeys memory k,
        StatelessKey memory sk
    ) internal view returns (bytes memory) {
        require(k.stateless, "not a stateless-certified tree");
        k = forAccount(val, account, memberIndex, k);
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 digest = val.statelessCertificateDigest(account, memberIndex, k.ops.root, uint8(k.ops.height), k.start);
        return statelessCertificateFor(k, sk, digest);
    }

    /// [root: 32][height: 1][start: 8][master commitment: 32][stateless key: 32][stateless signature], with the
    /// stateless key signing `digest` (WinterlockValidator.statelessCertificateDigest). k.ops must be built.
    function statelessCertificateFor(MemberKeys memory k, StatelessKey memory sk, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            k.ops.root,
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8(k.ops.height),
            k.start,
            masterCommitment(k),
            StatelessSigner.publicKey(sk),
            StatelessSigner.sign(sk, digest)
        );
    }

    /// One member's entry: [member index][flags][certificate?][WOTS signature][path] for the operation at `sequence`;
    /// k.ops must be built (forAccount)
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
            uint8(slot | (cert.length == 0 ? 0 : k.stateless ? 0x40 : 0x80)),
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
        k = forAccount(val, account, memberIndex, k);
        bytes memory cert;
        if (val.tree(account, memberIndex).root != k.ops.root) {
            require(!k.stateless, "a stateless certificate needs the secret key: statelessMemberSignature");
            cert = certificate(val, account, memberIndex, k);
        }
        return entry(k, memberIndex, slot, sequence, cert, userOpHash);
    }

    /// One member's entry for a tree certified by the stateless key, with the certificate if the validator doesn't
    /// have the tree yet
    function statelessMemberSignature(
        WinterlockValidator val,
        address account,
        MemberKeys memory k,
        StatelessKey memory sk,
        uint256 memberIndex,
        uint256 slot,
        uint256 sequence,
        bytes32 userOpHash
    ) internal view returns (bytes memory) {
        k = forAccount(val, account, memberIndex, k);
        bytes memory cert;
        if (val.tree(account, memberIndex).root != k.ops.root) {
            cert = statelessCertificate(val, account, memberIndex, k, sk);
        }
        return entry(k, memberIndex, slot, sequence, cert, userOpHash);
    }

    /// One member's ERC-1271 entry for `hash` checked by `account`:
    /// [member index: 1][master commitment: 32][stateless key: 32][stateless signature of messageDigest]
    function messageEntry(
        WinterlockValidator val,
        address account,
        MemberKeys memory k,
        StatelessKey memory sk,
        uint256 memberIndex,
        bytes32 hash
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint8(memberIndex),
            masterCommitment(k),
            StatelessSigner.publicKey(sk),
            StatelessSigner.sign(sk, val.messageDigest(account, hash))
        );
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

    /// A member with this master tree and the placeholder stateless key (as Ops.keys sets it)
    function asMember(WotsKey memory key) internal pure returns (WinterlockValidator.Member memory) {
        // forge-lint: disable-next-line(unsafe-typecast)
        return WinterlockValidator.Member(key.root, key.seed, uint8(key.height), placeholderStatelessKey(key));
    }

    function asMember(MemberKeys memory k) internal pure returns (WinterlockValidator.Member memory m) {
        m = asMember(k.master);
        m.statelessKey = k.statelessKey;
    }

    /// Install data for a 1-of-1 account on nonce lane 0 (key: the master tree; placeholder stateless key)
    function installData(WotsKey memory key) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](1);
        members[0] = asMember(key);
        return abi.encode(uint192(0), uint8(1), members);
    }

    /// Install data for a threshold account on nonce lane 0 (keys: the members' master trees; placeholder stateless
    /// keys)
    function installData(WotsKey[] memory trees, uint8 threshold) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](trees.length);
        for (uint256 i; i < trees.length; ++i) {
            members[i] = asMember(trees[i]);
        }
        return abi.encode(uint192(0), threshold, members);
    }

    /// Install data for a 1-of-1 account on nonce lane 0, with the member's stateless key
    function installData(MemberKeys memory k) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](1);
        members[0] = asMember(k);
        return abi.encode(uint192(0), uint8(1), members);
    }

    /// Install data for a threshold account on nonce lane 0, with the members' stateless keys
    function installData(MemberKeys[] memory ks, uint8 threshold) internal pure returns (bytes memory) {
        WinterlockValidator.Member[] memory members = new WinterlockValidator.Member[](ks.length);
        for (uint256 i; i < ks.length; ++i) {
            members[i] = asMember(ks[i]);
        }
        return abi.encode(uint192(0), threshold, members);
    }
}
