// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579Module.sol";
import {IStatelessVerifier} from "./interfaces/IStatelessVerifier.sol";
import {WotsVerifier} from "./WotsVerifier.sol";

/// @title WinterlockValidator
/// @notice ERC-7579 validator for UserOperations signed with WOTS+ one-time keys. Each account configures
///         one or more members and a threshold. A private wallet is the 1-of-1 case.
///
///         Keys of a member:
///         - A master tree of WOTS keys (decision D10). Master keys sign nothing but certificates.
///         - A stateless hash-based key (decision D11): leanSphincs over keccak256, checked by a shared verifier
///           contract (STATELESS_VERIFIER). It signs certificates too, and off-chain messages (ERC-1271). Being
///           stateless, it needs no record of its use, so it also recovers a signer that lost its state.
///         - Per chain, an operation tree of WOTS keys that signs UserOperations. A certificate, signed by a master
///           key or by the stateless key, binds it to this chain, this validator, the account and the member. The
///           first operation a member signs on a chain carries the certificate; the validator stores the tree in
///           the account's storage on that chain and verifies later operations against it. The same mechanism
///           replaces an exhausted tree, and after a loss of signer state certifies a fresh one.
///         The install data holds only the master trees and stateless public keys, so it is identical on every
///         chain, and so is the account's address.
///         Every operation key is bound to one nonce: keyIndex = (sequence - start) * SLOTS + slot, where
///         `start` is the first sequence number the certificate covers (decisions D2, D4).
///         Each deployment fixes one WOTS parameter set (hash size, w, hash function, encoding; see WotsVerifier).
///
/// Signature: one entry per signing member, in strictly increasing member index order (proves the
///            signers are distinct):
///              [member index: 1][flags: 1][certificate, if flagged][WOTS signature][path: tree height * n]
///            flags: bit 0 = slot, bit 7 = a master certificate follows, bit 6 = a stateless certificate follows
///            (at most one of the two).
///            Master certificate:
///              [master index: 2][root: 32][height: 1][start: 8][master seed: 16][master height: 1]
///              [stateless key: 32][master WOTS signature][master path: master height * n]
///            Stateless certificate:
///              [root: 32][height: 1][start: 8][master commitment: 32][stateless key: 32]
///              [stateless signature: 5,684]
///            A certificate carries the member's other key material (stateless key or master commitment), so the
///            validator can check the member commitment.
///            Valid when every entry verifies, there are at least `threshold` of them, and no bytes are left
///            over. Every well-formed entry is verified even after one fails, so a dummy signature (used for
///            gas estimation) costs as much gas as a real one with the same signers. For an operation that
///            carries a certificate, the dummy must carry the real certificate too: it does not depend on
///            the operation, and only a valid certificate stores its tree (and the stateless verifier stops early
///            on some invalid signatures).
///
/// Rotation:  certificates on a chain are ordered by their start sequence: a new one must start after the stored
///            tree's start, whichever key signed either. A master certificate must also use a master index above
///            every master index used on this chain before (D10). So an old certificate of either kind can never
///            bring back a tree it was replaced by.
///
/// Messages:  isValidSignatureWithSender checks members' stateless signatures of a typed wrap of the hash (EIP-712,
///            domain "Winterlock" version 1 with this chain id and this validator, message
///            WinterlockMessage(address account, bytes32 hash)), so a signature counts for one account on one chain
///            under one validator. Signature: one entry per signing member, strictly increasing member index:
///              [member index: 1][master commitment: 32][stateless key: 32][stateless signature: 5,684]
///            Valid when every entry verifies and there are at least `threshold` of them.
///
/// Storage:   all per-account data sits in the account's own mapping entry (fixed-size arrays), so
///            validation only touches storage associated with the account (ERC-7562). New storage is costly
///            (more so under Glamsterdam's pricing), so it is packed:
///            - a member is one slot, a commitment to its master tree (root, seed, height) and its stateless key;
///            - an operation tree is one slot for hash sizes up to 24 bytes: the root in the high bytes, then
///              start (40 bits), next master index (17 bits), a stateless flag (1 bit) and height (6 bits). With
///              32-byte hashes the root fills its slot and the rest takes a second one. An operation tree's public
///              seed is derived (treeSeed or statelessTreeSeed), not stored.
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
    bytes32 public constant CERTIFICATE_DOMAIN = keccak256("Winterlock.certificate.v3");
    /// Domain of the message a stateless key signs to certify an operation tree.
    bytes32 public constant STATELESS_CERTIFICATE_DOMAIN = keccak256("Winterlock.stateless-certificate.v1");
    /// Domain of a master-certified operation tree's public seed.
    bytes32 public constant TREE_SEED_DOMAIN = keccak256("Winterlock.tree-seed.v1");
    /// Domain of a stateless-certified operation tree's public seed.
    bytes32 public constant STATELESS_TREE_SEED_DOMAIN = keccak256("Winterlock.stateless-tree-seed.v1");
    /// Length of a stateless signature (leanSphincs: n = 16, h = 26, FORS k = 24, a = 10).
    uint256 public constant STATELESS_SIG_LEN = 5684;
    /// EIP-712 type of the wrap around an ERC-1271 hash.
    bytes32 public constant MESSAGE_TYPEHASH = keccak256("WinterlockMessage(address account,bytes32 hash)");

    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant NAME_HASH = keccak256("Winterlock");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;
    bytes4 internal constant ERC1271_SUCCESS = 0x1626ba7e;
    bytes4 internal constant ERC1271_FAILED = 0xffffffff;
    uint256 internal constant FLAG_SLOT = 0x01;
    uint256 internal constant FLAG_STATELESS_CERTIFICATE = 0x40;
    uint256 internal constant FLAG_CERTIFICATE = 0x80;
    /// Master certificate fields before the master signature: master index, root, height, start, master seed,
    /// master height, stateless key.
    uint256 internal constant CERTIFICATE_HEADER = 2 + 32 + 1 + 8 + 16 + 1 + 32;
    /// Stateless certificate fields before its signature: root, height, start, master commitment, stateless key.
    uint256 internal constant STATELESS_CERTIFICATE_HEADER = 32 + 1 + 8 + 32 + 32;
    /// A message signature entry: member index, master commitment, stateless key, stateless signature.
    uint256 internal constant MESSAGE_ENTRY = 1 + 32 + 32 + STATELESS_SIG_LEN;
    /// Low 64 bits of a packed operation tree: start << 24 | next master << 7 | stateless << 6 | height
    uint256 internal constant META_MASK = (1 << 64) - 1;
    uint256 internal constant META_STATELESS = 1 << 6;
    uint256 internal constant HIGH_128 = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

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
    /// Verifier of the members' stateless keys, shared by all accounts.
    IStatelessVerifier public immutable STATELESS_VERIFIER;

    /// A member's keys, as given in the install data: the master tree and the stateless public key.
    /// Stored as memberCommitment(masterCommitment(root, seed, height), statelessKey).
    struct Member {
        bytes32 root;
        uint128 seed;
        uint8 height;
        bytes32 statelessKey; // leanSphincs public key: root (16 bytes) ‖ public parameter P (16 bytes)
    }

    /// A member's operation tree on this chain, as certified by a master key or the stateless key (view and
    /// memory form).
    struct Tree {
        bytes32 root;
        uint128 seed; // derived: treeSeed(account, member, master index) or statelessTreeSeed(account, member, start)
        uint8 height;
        uint64 start; // first sequence number the tree signs for
        uint32 nextMaster; // a later master certificate on this chain must use at least this master index
        bool stateless; // certified by the stateless key
    }

    struct Config {
        uint192 nonceKey; // the only EntryPoint nonce lane this validator signs on
        uint8 threshold;
        uint8 memberCount;
        bytes32[MAX_MEMBERS] members; // memberCommitment of each member
        uint256[2][MAX_MEMBERS] trees; // packed operation trees on this chain; word 1 only for 32-byte hashes
    }

    mapping(address account => Config) internal _config;

    error AlreadyInitialized();
    error InvalidConfig();

    constructor(uint256 params, IStatelessVerifier statelessVerifier) {
        WotsVerifier.checkParams(params);
        if (address(statelessVerifier).code.length == 0) revert InvalidConfig();
        PARAMS = params;
        N = params & 0xff;
        TARGET_SUM = (params >> 32) & 0xffffffff;
        SIG_LEN = WotsVerifier.sigBytes(params);
        PACKED = N <= 24;
        STATELESS_VERIFIER = statelessVerifier;
    }

    // --- ERC-7579 module ---

    /// @param data abi.encode(uint192 nonceKey, uint8 threshold, Member[] members): each member's master tree and
    ///             stateless public key
    function onInstall(bytes calldata data) external {
        (uint192 nonceKey, uint8 threshold, Member[] memory members) = abi.decode(data, (uint192, uint8, Member[]));
        Config storage c = _config[msg.sender];
        if (c.memberCount != 0) revert AlreadyInitialized();
        uint256 count = members.length;
        if (count == 0 || count > MAX_MEMBERS || threshold == 0 || threshold > count) revert InvalidConfig();
        for (uint256 i; i < count; ++i) {
            Member memory m = members[i];
            if (m.root == bytes32(0) || m.height == 0 || m.height > MAX_MASTER_HEIGHT) revert InvalidConfig();
            // both halves of the stateless key set: a root and a public parameter
            if (uint256(m.statelessKey) >> 128 == 0 || uint128(uint256(m.statelessKey)) == 0) revert InvalidConfig();
            for (uint256 j; j < i; ++j) {
                // one key, one vote
                if (members[j].root == m.root || members[j].statelessKey == m.statelessKey) revert InvalidConfig();
            }
            c.members[i] = memberCommitment(masterCommitment(m.root, m.seed, m.height), m.statelessKey);
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

    /// The commitment to a member's keys.
    function member(address account, uint256 index) external view returns (bytes32) {
        return _config[account].members[index];
    }

    /// A member's operation tree on this chain (root 0 if none is enrolled yet).
    function tree(address account, uint256 index) external view returns (Tree memory) {
        return _loadTree(_config[account], account, index);
    }

    /// The commitment to a master tree.
    function masterCommitment(bytes32 root, uint128 seed, uint8 height) public pure returns (bytes32) {
        return keccak256(abi.encode(root, seed, height));
    }

    /// What the validator stores for a member: its master tree's commitment and its stateless key.
    function memberCommitment(bytes32 master, bytes32 statelessKey) public pure returns (bytes32) {
        return keccak256(abi.encode(master, statelessKey));
    }

    /// The public seed of the operation tree that master key `masterIndex` certifies for `account` on this chain.
    /// Unique per tree, because a master key certifies only one tree; the signer generates the tree with it.
    function treeSeed(address account, uint256 index, uint256 masterIndex) public view returns (uint128) {
        return uint128(
            bytes16(keccak256(abi.encode(TREE_SEED_DOMAIN, block.chainid, address(this), account, index, masterIndex)))
        );
    }

    /// The public seed of the operation tree that the stateless key certifies from `start` for `account` on this
    /// chain. Unique per stored tree, because start sequences on a chain only grow.
    function statelessTreeSeed(address account, uint256 index, uint64 start) public view returns (uint128) {
        return uint128(
            bytes16(
                keccak256(abi.encode(STATELESS_TREE_SEED_DOMAIN, block.chainid, address(this), account, index, start))
            )
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

    /// The message a member's stateless key signs to certify an operation tree for `account` on this chain.
    /// It can't equal a messageDigest: that one is an EIP-712 hash, with a different preimage format.
    function statelessCertificateDigest(address account, uint256 index, bytes32 root, uint8 height, uint64 start)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(STATELESS_CERTIFICATE_DOMAIN, block.chainid, address(this), account, index, root, height, start)
        );
    }

    /// EIP-712 domain of the ERC-1271 wrap: this validator on this chain.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// What members' stateless keys sign for an ERC-1271 check of `hash` by `account`: the EIP-712 hash of
    /// WinterlockMessage(account, hash) in this validator's domain.
    function messageDigest(address account, bytes32 hash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(MESSAGE_TYPEHASH, account, hash)))
        );
    }

    // --- validation ---

    /// @dev Not a view: a valid certificate stores the operation tree it certifies. Storage is keyed by the
    ///      caller, so a call can only enrol trees for the caller itself, and only trees a member's key signed.
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
    ///              short, no tree enrolled, certificate fields out of range or not after the stored tree, key
    ///              outside the tree. Shape errors stop validation at once; they don't depend on the signature's
    ///              validity, so a dummy signature of the right shape avoids them.
    function _verifyEntry(uint256 index, uint256 sequence, bytes32 userOpHash, bytes calldata e)
        internal
        returns (bool ok, uint256 used)
    {
        if (e.length == 0) return (false, 0);
        Config storage c = _config[msg.sender];
        uint256 flags = uint8(e[0]);
        if (flags & ~(FLAG_SLOT | FLAG_CERTIFICATE | FLAG_STATELESS_CERTIFICATE) != 0) return (false, 0);
        uint256 kind = flags & (FLAG_CERTIFICATE | FLAG_STATELESS_CERTIFICATE);
        Tree memory t;
        bool certified = true;
        if (kind == 0) {
            t = _loadTree(c, msg.sender, index);
            if (t.root == bytes32(0)) return (false, 0); // no tree enrolled on this chain
            used = 1;
        } else {
            if (kind == FLAG_CERTIFICATE) {
                (certified, used, t) = _certificate(c, index, sequence, e);
            } else if (kind == FLAG_STATELESS_CERTIFICATE) {
                (certified, used, t) = _statelessCertificate(c, index, sequence, e);
            } else {
                return (false, 0); // both kinds
            }
            if (used == 0) return (false, 0);
            if (certified) _storeTree(c, index, t);
        }
        (ok, used) = _verifyOperation(t, sequence, flags & FLAG_SLOT, userOpHash, e, used);
        ok = ok && certified;
    }

    /// Parses and checks a master certificate.
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
        Tree memory stored = _loadTree(c, msg.sender, index);
        t = _parseCertificate(e);
        uint256 masterIndex = t.nextMaster - 1;
        if (
            masterHeight == 0 || masterHeight > MAX_MASTER_HEIGHT || masterIndex >> masterHeight != 0
                || masterIndex < stored.nextMaster || !_follows(t, stored, sequence)
        ) return (false, 0, t);
        t.seed = treeSeed(msg.sender, index, masterIndex);
        bytes32 digest = certificateDigest(msg.sender, index, t.root, t.height, t.start);
        certified = _masterSigned(c.members[index], masterIndex, digest, e[44:93], e[93:used]);
    }

    /// @param e starts at the flags byte, followed by [master index][root][height][start]
    /// @return t the certified tree, with nextMaster = master index + 1 and no seed yet
    function _parseCertificate(bytes calldata e) internal pure returns (Tree memory t) {
        t.root = bytes32(e[3:35]);
        t.height = uint8(e[35]);
        t.start = uint64(bytes8(e[36:44]));
        t.nextMaster = uint32(uint16(bytes2(e[1:3]))) + 1;
    }

    /// @param commitment the member's commitment
    /// @param keys       [master seed: 16][master height: 1][stateless key: 32]
    /// @param sigAndPath [master WOTS signature][master path]
    function _masterSigned(
        bytes32 commitment,
        uint256 masterIndex,
        bytes32 digest,
        bytes calldata keys,
        bytes calldata sigAndPath
    ) internal view returns (bool) {
        uint128 seed = uint128(bytes16(keys[:16]));
        bytes32 root =
            WotsVerifier.computeRoot(PARAMS, seed, masterIndex, digest, sigAndPath[:SIG_LEN], sigAndPath[SIG_LEN:]);
        return root != bytes32(0)
            && memberCommitment(masterCommitment(root, seed, uint8(keys[16])), bytes32(keys[17:49])) == commitment;
    }

    /// Parses and checks a stateless certificate.
    /// @param e starts at the flags byte: [flags][root][height][start][master commitment][stateless key][signature]
    /// @return certified whether the member's stateless key signed it
    /// @return used      bytes of `e` up to the end of the certificate (flags byte included), 0 if malformed
    /// @return t         the operation tree it certifies
    function _statelessCertificate(Config storage c, uint256 index, uint256 sequence, bytes calldata e)
        internal
        view
        returns (bool certified, uint256 used, Tree memory t)
    {
        used = 1 + STATELESS_CERTIFICATE_HEADER + STATELESS_SIG_LEN;
        if (e.length < used) return (false, 0, t);
        Tree memory stored = _loadTree(c, msg.sender, index);
        t.root = bytes32(e[1:33]);
        t.height = uint8(e[33]);
        t.start = uint64(bytes8(e[34:42]));
        t.nextMaster = stored.nextMaster; // master keys used on this chain stay used
        t.stateless = true;
        if (!_follows(t, stored, sequence)) return (false, 0, t);
        t.seed = statelessTreeSeed(msg.sender, index, t.start);
        bytes32 key = bytes32(e[74:106]);
        certified = memberCommitment(bytes32(e[42:74]), key) == c.members[index]
            && _statelessSigned(
                key, statelessCertificateDigest(msg.sender, index, t.root, t.height, t.start), e[106:used]
            );
    }

    /// Whether `t` is a well-formed tree that may replace `stored` at `sequence`: the root is n bytes, high-aligned
    /// (it shares its slot with the packed fields), the height and start are in range, the start isn't in the
    /// future, and it comes after the stored tree's start.
    function _follows(Tree memory t, Tree memory stored, uint256 sequence) internal view returns (bool) {
        return t.root != bytes32(0) && uint256(t.root) << (8 * N) == 0 && t.height != 0 && t.height <= MAX_HEIGHT
            && t.start <= MAX_START && t.start <= sequence && (stored.root == bytes32(0) || t.start > stored.start);
    }

    /// Whether `sig` is the stateless key's signature of `message`. The key is root ‖ P; the verifier takes both
    /// halves high-aligned. A call that reverts counts as an invalid signature.
    function _statelessSigned(bytes32 key, bytes32 message, bytes calldata sig) internal view returns (bool valid) {
        address verifier = address(STATELESS_VERIFIER);
        bytes4 selector = IStatelessVerifier.verify.selector;
        assembly ("memory-safe") {
            // verify(pkSeed, pkRoot, message, sig), encoded in scratch memory beyond the free memory pointer
            let m := mload(0x40)
            mstore(m, selector)
            mstore(add(m, 0x04), shl(128, key))
            mstore(add(m, 0x24), and(key, HIGH_128))
            mstore(add(m, 0x44), message)
            mstore(add(m, 0x64), 0x80)
            mstore(add(m, 0x84), sig.length)
            let padded := and(add(sig.length, 31), not(31))
            // zero padding
            if padded {
                mstore(add(add(m, 0xa4), sub(padded, 0x20)), 0)
            }
            calldatacopy(add(m, 0xa4), sig.offset, sig.length)
            let ok := staticcall(gas(), verifier, m, add(0xa4, padded), 0x00, 0x20)
            valid := and(ok, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
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
        uint256 meta =
            (uint256(t.start) << 24) | (uint256(t.nextMaster) << 7) | (t.stateless ? META_STATELESS : 0) | t.height;
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
        t.height = uint8(meta & 0x3f);
        // forge-lint: disable-next-line(unsafe-typecast)
        t.start = uint64(meta >> 24);
        // forge-lint: disable-next-line(unsafe-typecast)
        t.nextMaster = uint32((meta >> 7) & 0x1ffff);
        t.stateless = meta & META_STATELESS != 0;
        t.seed = t.stateless ? statelessTreeSeed(account, index, t.start) : treeSeed(account, index, t.nextMaster - 1);
    }

    // --- off-chain messages ---

    /// ERC-1271 for the account (msg.sender): members' stateless signatures of messageDigest(account, hash).
    /// @param data one entry per signing member, strictly increasing member index:
    ///             [member index: 1][master commitment: 32][stateless key: 32][stateless signature: 5,684]
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata data) external view returns (bytes4) {
        Config storage c = _config[msg.sender];
        if (c.memberCount == 0 || data.length == 0 || data.length % MESSAGE_ENTRY != 0) return ERC1271_FAILED;
        bytes32 digest = messageDigest(msg.sender, hash);
        uint256 nextIndex;
        for (uint256 offset; offset < data.length; offset += MESSAGE_ENTRY) {
            uint256 index = uint8(data[offset]);
            if (index < nextIndex || index >= c.memberCount) return ERC1271_FAILED;
            bytes32 key = bytes32(data[offset + 33:offset + 65]);
            if (memberCommitment(bytes32(data[offset + 1:offset + 33]), key) != c.members[index]) {
                return ERC1271_FAILED;
            }
            if (!_statelessSigned(key, digest, data[offset + 65:offset + MESSAGE_ENTRY])) return ERC1271_FAILED;
            nextIndex = index + 1;
        }
        return data.length / MESSAGE_ENTRY >= c.threshold ? ERC1271_SUCCESS : ERC1271_FAILED;
    }
}
