// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579Module.sol";
import {WotsVerifier} from "./WotsVerifier.sol";

/// @title WinterlockValidator
/// @notice ERC-7579 validator for UserOperations signed with WOTS+ one-time keys. Each account configures
///         one or more members and a threshold. A private wallet is the 1-of-1 case.
///
///         Two levels of key trees per member (decision D10):
///         - The master tree is part of the install data, which is identical on every chain, so the account
///           has the same address everywhere. Master keys sign nothing but certificates.
///         - An operation tree signs UserOperations on one chain. A certificate, signed by one master key,
///           binds it to this chain, this validator, the account and the member. The first operation a
///           member signs on a chain carries the certificate; the validator stores the tree in the account's
///           storage on that chain and verifies later operations against it. The same mechanism replaces an
///           exhausted tree.
///         Every operation key is bound to one nonce: keyIndex = (sequence - start) * SLOTS + slot, where
///         `start` is the first sequence number the certificate covers (decisions D2, D4).
///         Each deployment fixes one parameter set (hash size, w, hash function, encoding; see WotsVerifier).
///
/// Signature: one entry per signing member, in strictly increasing member index order (proves the
///            signers are distinct):
///              [member index: 1][flags: 1][certificate, if flagged][WOTS signature][path: tree height * n]
///            flags: bit 0 = slot, bit 7 = a certificate follows. Certificate:
///              [master index: 2][root: 32][height: 1][start: 8][master seed: 16][master height: 1]
///              [master WOTS signature][master path: master height * n]
///            Valid when every entry verifies, there are at least `threshold` of them, and no bytes are left
///            over. Every well-formed entry is verified even after one fails, so a dummy signature (used for
///            gas estimation) costs as much gas as a real one with the same signers. For an operation that
///            carries a certificate, the dummy should carry the real certificate too: it does not depend on
///            the operation, and only a valid certificate stores its tree.
///
/// Storage:   all per-account data sits in the account's own mapping entry (fixed-size arrays), so
///            validation only touches storage associated with the account (ERC-7562). New storage is costly
///            (more so under Glamsterdam's pricing), so it is packed:
///            - a master tree is one slot, a commitment to its root, seed and height;
///            - an operation tree is one slot for hash sizes up to 24 bytes: the root in the high bytes, then
///              start (40 bits), master index (16 bits) and height (8 bits). With 32-byte hashes the root
///              fills its slot and the rest takes a second one. An operation tree's public seed is derived
///              (treeSeed), not stored.
///
/// @dev Status: research prototype. Unaudited. Not for real funds.
contract WinterlockValidator is IValidator {
    /// Keys per nonce: slot 0 signs, slot 1 is reserved for a replacement or cancellation.
    uint256 public constant SLOTS = 2;
    uint256 public constant MAX_MEMBERS = 16;
    /// Largest operation tree.
    uint256 public constant MAX_HEIGHT = 40;
    /// Largest master tree: master indices are 16 bits in the certificate.
    uint256 public constant MAX_MASTER_HEIGHT = 16;
    /// A certificate's start sequence must fit in 40 bits.
    uint256 public constant MAX_START = (1 << 40) - 1;
    /// Domain of the message a master key signs.
    bytes32 public constant CERTIFICATE_DOMAIN = keccak256("Winterlock.certificate.v2");
    /// Domain of an operation tree's public seed.
    bytes32 public constant TREE_SEED_DOMAIN = keccak256("Winterlock.tree-seed.v1");

    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;
    uint256 internal constant FLAG_SLOT = 0x01;
    uint256 internal constant FLAG_CERTIFICATE = 0x80;
    /// Certificate fields before the master signature: master index, root, height, start, master seed and height.
    uint256 internal constant CERTIFICATE_HEADER = 2 + 32 + 1 + 8 + 16 + 1;
    /// Low 64 bits of a packed operation tree: start << 24 | master index << 8 | height
    uint256 internal constant META_MASK = (1 << 64) - 1;

    /// Packed parameter set (WotsVerifier.encodeParams): hash size, w, hash function, encoding.
    uint256 public immutable PARAMS;
    /// Hash size in bytes (16, 24 or 32).
    uint256 public immutable N;
    /// 0 for checksum encoding, otherwise the required digit sum.
    uint256 public immutable TARGET_SUM;
    /// WOTS signature length for this parameter set (randomizer + chain values).
    uint256 internal immutable SIG_LEN;
    /// Whether an operation tree fits one storage slot (hash size up to 24 bytes).
    bool internal immutable PACKED;

    /// A member's master tree, as given in the install data. Stored as masterCommitment(root, seed, height).
    struct Member {
        bytes32 root;
        uint128 seed;
        uint8 height;
    }

    /// A member's operation tree on this chain, as certified by a master key (view and memory form).
    struct Tree {
        bytes32 root;
        uint128 seed; // derived: treeSeed(account, member, master index)
        uint8 height;
        uint64 start; // first sequence number the tree signs for
        uint32 nextMaster; // a later certificate on this chain must use at least this master index
    }

    struct Config {
        uint192 nonceKey; // the only EntryPoint nonce lane this validator signs on
        uint8 threshold;
        uint8 memberCount;
        bytes32[MAX_MEMBERS] masters; // masterCommitment of each member's master tree
        uint256[2][MAX_MEMBERS] trees; // packed operation trees on this chain; word 1 only for 32-byte hashes
    }

    mapping(address account => Config) internal _config;

    error AlreadyInitialized();
    error InvalidConfig();

    constructor(uint256 params) {
        WotsVerifier.checkParams(params);
        PARAMS = params;
        N = params & 0xff;
        TARGET_SUM = (params >> 32) & 0xffffffff;
        SIG_LEN = WotsVerifier.sigBytes(params);
        PACKED = N <= 24;
    }

    // --- ERC-7579 module ---

    /// @param data abi.encode(uint192 nonceKey, uint8 threshold, Member[] members), with each member's master tree
    function onInstall(bytes calldata data) external {
        (uint192 nonceKey, uint8 threshold, Member[] memory members) = abi.decode(data, (uint192, uint8, Member[]));
        Config storage c = _config[msg.sender];
        if (c.memberCount != 0) revert AlreadyInitialized();
        uint256 count = members.length;
        if (count == 0 || count > MAX_MEMBERS || threshold == 0 || threshold > count) revert InvalidConfig();
        for (uint256 i; i < count; ++i) {
            Member memory m = members[i];
            if (m.root == bytes32(0) || m.height == 0 || m.height > MAX_MASTER_HEIGHT) revert InvalidConfig();
            for (uint256 j; j < i; ++j) {
                if (members[j].root == m.root) revert InvalidConfig(); // one tree, one vote
            }
            c.masters[i] = masterCommitment(m.root, m.seed, m.height);
        }
        c.nonceKey = nonceKey;
        c.threshold = threshold;
        c.memberCount = uint8(count);
    }

    function onUninstall(bytes calldata) external {
        delete _config[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view returns (bool) {
        return _config[account].memberCount != 0;
    }

    // --- views ---

    function settings(address account) external view returns (uint192 nonceKey, uint8 threshold, uint8 memberCount) {
        Config storage c = _config[account];
        return (c.nonceKey, c.threshold, c.memberCount);
    }

    /// The commitment to a member's master tree.
    function member(address account, uint256 index) external view returns (bytes32) {
        return _config[account].masters[index];
    }

    /// A member's operation tree on this chain (root 0 if none is enrolled yet).
    function tree(address account, uint256 index) external view returns (Tree memory) {
        return _loadTree(_config[account], account, index);
    }

    /// What the validator stores for a master tree.
    function masterCommitment(bytes32 root, uint128 seed, uint8 height) public pure returns (bytes32) {
        return keccak256(abi.encode(root, seed, height));
    }

    /// The public seed of the operation tree that master key `masterIndex` certifies for `account` on this chain.
    /// Unique per tree, because a master key certifies only one tree; the signer generates the tree with it.
    function treeSeed(address account, uint256 index, uint256 masterIndex) public view returns (uint128) {
        return uint128(
            bytes16(keccak256(abi.encode(TREE_SEED_DOMAIN, block.chainid, address(this), account, index, masterIndex)))
        );
    }

    /// The message a member's master key signs to certify an operation tree for `account` on this chain.
    function certificateDigest(address account, uint256 index, bytes32 root, uint8 height, uint64 start)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(CERTIFICATE_DOMAIN, block.chainid, address(this), account, index, root, height, start)
        );
    }

    // --- validation ---

    /// @dev Not a view: a valid certificate stores the operation tree it certifies. Storage is keyed by the
    ///      caller, so a call can only enrol trees for the caller itself, and only trees a master key signed.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256) {
        Config storage c = _config[msg.sender];
        // nonce = key (192 bits) || sequence (64 bits); both casts split it exactly
        // forge-lint: disable-next-line(unsafe-typecast)
        if (c.memberCount == 0 || uint192(userOp.nonce >> 64) != c.nonceKey) return VALIDATION_FAILED;
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 sequence = uint64(userOp.nonce);

        bytes calldata s = userOp.signature;
        uint256 offset;
        uint256 nextIndex; // entries must name members in strictly increasing order
        uint256 valid;
        bool invalid; // a well-formed entry failed: keep verifying the rest, so the gas matches a valid signature
        while (offset < s.length) {
            uint256 index = uint8(s[offset]);
            if (index < nextIndex || index >= c.memberCount) return VALIDATION_FAILED;
            (bool ok, uint256 used) = _verifyEntry(index, sequence, userOpHash, s[offset + 1:]);
            if (used == 0) return VALIDATION_FAILED; // malformed entry
            offset += 1 + used;
            nextIndex = index + 1;
            if (ok) ++valid;
            else invalid = true;
        }
        return !invalid && valid >= c.threshold ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /// @param e starts at the flags byte: [flags][certificate?][WOTS signature][path], possibly followed by more
    ///          entries
    /// @return ok   whether this member's entry verifies (certificate included)
    /// @return used bytes of `e` that belong to this member, 0 if the entry is malformed: unknown flags, too
    ///              short, no tree enrolled, certificate fields out of range, key outside the tree. Shape errors
    ///              stop validation at once; they don't depend on the signature's validity, so a dummy signature
    ///              of the right shape avoids them.
    function _verifyEntry(uint256 index, uint256 sequence, bytes32 userOpHash, bytes calldata e)
        internal
        returns (bool ok, uint256 used)
    {
        if (e.length == 0) return (false, 0);
        Config storage c = _config[msg.sender];
        uint256 flags = uint8(e[0]);
        if (flags & ~(FLAG_SLOT | FLAG_CERTIFICATE) != 0) return (false, 0);
        Tree memory t;
        bool certified = true;
        if (flags & FLAG_CERTIFICATE == 0) {
            t = _loadTree(c, msg.sender, index);
            if (t.root == bytes32(0)) return (false, 0); // no tree enrolled on this chain
            used = 1;
        } else {
            (certified, used, t) = _certificate(c, index, sequence, e);
            if (used == 0) return (false, 0);
            if (certified) _storeTree(c, index, t);
        }
        (ok, used) = _verifyOperation(t, sequence, flags & FLAG_SLOT, userOpHash, e, used);
        ok = ok && certified;
    }

    /// Parses and checks a certificate.
    /// @return certified whether the member's master key signed it
    /// @return used      bytes of `e` up to the end of the certificate (flags byte included), 0 if malformed
    /// @return t         the operation tree it certifies
    function _certificate(Config storage c, uint256 index, uint256 sequence, bytes calldata e)
        internal
        view
        returns (bool certified, uint256 used, Tree memory t)
    {
        if (e.length < 1 + CERTIFICATE_HEADER) return (false, 0, t);
        uint256 masterHeight = uint8(e[60]);
        used = 1 + CERTIFICATE_HEADER + SIG_LEN + N * masterHeight;
        if (e.length < used) return (false, 0, t);
        t = _parseCertificate(e);
        uint256 masterIndex = t.nextMaster - 1;
        if (
            masterHeight == 0 || masterHeight > MAX_MASTER_HEIGHT || masterIndex >> masterHeight != 0
                || masterIndex < _loadTree(c, msg.sender, index).nextMaster || t.root == bytes32(0)
                || uint256(t.root) << (8 * N) != 0 || t.height == 0 || t.height > MAX_HEIGHT || t.start > MAX_START
                || t.start > sequence
        ) return (false, 0, t);
        t.seed = treeSeed(msg.sender, index, masterIndex);
        bytes32 digest = certificateDigest(msg.sender, index, t.root, t.height, t.start);
        certified = _masterSigned(c.masters[index], masterIndex, digest, e[44:61], e[61:used]);
    }

    /// @param e starts at the flags byte, followed by [master index][root][height][start]
    /// @return t the certified tree, with nextMaster = master index + 1 and no seed yet
    function _parseCertificate(bytes calldata e) internal pure returns (Tree memory t) {
        t.root = bytes32(e[3:35]);
        t.height = uint8(e[35]);
        t.start = uint64(bytes8(e[36:44]));
        t.nextMaster = uint32(uint16(bytes2(e[1:3]))) + 1;
    }

    /// @param master        the member's master commitment
    /// @param seedAndHeight [master seed: 16][master height: 1]
    /// @param sigAndPath    [master WOTS signature][master path]
    function _masterSigned(
        bytes32 master,
        uint256 masterIndex,
        bytes32 digest,
        bytes calldata seedAndHeight,
        bytes calldata sigAndPath
    ) internal view returns (bool) {
        uint128 seed = uint128(bytes16(seedAndHeight[:16]));
        bytes32 root =
            WotsVerifier.computeRoot(PARAMS, seed, masterIndex, digest, sigAndPath[:SIG_LEN], sigAndPath[SIG_LEN:]);
        return root != bytes32(0) && masterCommitment(root, seed, uint8(seedAndHeight[16])) == master;
    }

    /// Verifies the operation signature that starts at `e[offset]` under tree `t`.
    /// @return ok   whether the signature verifies under `t`
    /// @return used bytes of `e` up to the end of the path, 0 if malformed
    function _verifyOperation(
        Tree memory t,
        uint256 sequence,
        uint256 slot,
        bytes32 userOpHash,
        bytes calldata e,
        uint256 offset
    ) internal view returns (bool ok, uint256 used) {
        if (sequence < t.start) return (false, 0);
        uint256 keyIndex = (sequence - t.start) * SLOTS + slot;
        if (keyIndex >> t.height != 0) return (false, 0); // tree exhausted
        used = offset + SIG_LEN + N * t.height;
        if (e.length < used) return (false, 0);
        bytes32 root = WotsVerifier.computeRoot(
            PARAMS, t.seed, keyIndex, userOpHash, e[offset:offset + SIG_LEN], e[offset + SIG_LEN:used]
        );
        ok = root != bytes32(0) && root == t.root;
    }

    // --- packed operation trees ---

    function _storeTree(Config storage c, uint256 index, Tree memory t) internal {
        uint256 meta = (uint256(t.start) << 24) | (uint256(t.nextMaster - 1) << 8) | t.height;
        if (PACKED) {
            c.trees[index][0] = uint256(t.root) | meta; // the root's low 8 or more bytes are zero
        } else {
            c.trees[index][0] = uint256(t.root);
            c.trees[index][1] = meta;
        }
    }

    /// @return t the stored tree with its derived seed; all zero if none is enrolled
    function _loadTree(Config storage c, address account, uint256 index) internal view returns (Tree memory t) {
        uint256 word = c.trees[index][0];
        if (word == 0) return t;
        uint256 meta;
        if (PACKED) {
            meta = word & META_MASK;
            t.root = bytes32(word ^ meta);
        } else {
            t.root = bytes32(word);
            meta = c.trees[index][1];
        }
        uint256 masterIndex = (meta >> 8) & 0xffff;
        t.height = uint8(meta);
        // forge-lint: disable-next-line(unsafe-typecast)
        t.start = uint64(meta >> 24);
        // forge-lint: disable-next-line(unsafe-typecast)
        t.nextMaster = uint32(masterIndex + 1);
        t.seed = treeSeed(account, index, masterIndex);
    }

    /// Off-chain messages (ERC-1271) are an open question; until then this validator signs none.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
