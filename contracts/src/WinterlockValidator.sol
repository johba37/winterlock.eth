// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator, MODULE_TYPE_VALIDATOR} from "./interfaces/IERC7579Module.sol";
import {WotsVerifier} from "./WotsVerifier.sol";

/// @title WinterlockValidator
/// @notice ERC-7579 validator for UserOperations signed with WOTS+ one-time keys. Each account configures
///         one or more members (each with their own Merkle tree of one-time keys) and a threshold. A
///         private wallet is the 1-of-1 case.
///         Every key is bound to one nonce: keyIndex = sequence * SLOTS + slot (decisions D2, D4). Members
///         use their own trees, so they pick their slots independently.
///         Each deployment fixes one parameter set (hash size, w, hash function, encoding; see WotsVerifier).
///
/// Signature: one entry per signing member, in strictly increasing member index order (proves the
///            signers are distinct):
///              [member index: 1][slot: 1][WOTS signature: WotsVerifier.sigBytes][path: height * n]
///            Valid when at least `threshold` entries verify and no bytes are left over.
///
/// Storage:   all per-account data sits in the account's own mapping entry (fixed-size member array),
///            so validation only touches storage associated with the account (ERC-7562).
///
/// @dev Status: research prototype. Unaudited. Not for real funds.
contract WinterlockValidator is IValidator {
    /// Keys per nonce: slot 0 signs, slot 1 is reserved for a replacement or cancellation.
    uint256 public constant SLOTS = 2;
    uint256 public constant MAX_MEMBERS = 16;
    uint256 public constant MAX_HEIGHT = 40;

    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;

    /// Packed parameter set (WotsVerifier.encodeParams): hash size, w, hash function, encoding.
    uint256 public immutable PARAMS;
    /// Hash size in bytes (16, 24 or 32).
    uint256 public immutable N;
    /// 0 for checksum encoding, otherwise the required digit sum.
    uint256 public immutable TARGET_SUM;
    /// WOTS signature length for this parameter set (randomizer + chain values).
    uint256 internal immutable SIG_LEN;

    struct Member {
        bytes32 root; // Merkle root of the member's one-time keys for this account
        uint128 seed; // public seed of that tree
        uint8 height; // tree height
    }

    struct Config {
        uint192 nonceKey; // the only EntryPoint nonce lane this validator signs on
        uint8 threshold;
        uint8 memberCount;
        Member[MAX_MEMBERS] members;
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
    }

    // --- ERC-7579 module ---

    /// @param data abi.encode(uint192 nonceKey, uint8 threshold, Member[] members)
    function onInstall(bytes calldata data) external {
        (uint192 nonceKey, uint8 threshold, Member[] memory members) = abi.decode(data, (uint192, uint8, Member[]));
        Config storage c = _config[msg.sender];
        if (c.memberCount != 0) revert AlreadyInitialized();
        uint256 count = members.length;
        if (count == 0 || count > MAX_MEMBERS || threshold == 0 || threshold > count) revert InvalidConfig();
        for (uint256 i; i < count; ++i) {
            Member memory m = members[i];
            if (m.root == bytes32(0) || m.height == 0 || m.height > MAX_HEIGHT) revert InvalidConfig();
            for (uint256 j; j < i; ++j) {
                if (members[j].root == m.root) revert InvalidConfig(); // one tree, one vote
            }
            c.members[i] = m;
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

    function member(address account, uint256 index) external view returns (Member memory) {
        return _config[account].members[index];
    }

    // --- validation ---

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        returns (uint256)
    {
        Config storage c = _config[msg.sender];
        uint256 memberCount = c.memberCount;
        // nonce = key (192 bits) || sequence (64 bits); both casts split it exactly
        // forge-lint: disable-next-line(unsafe-typecast)
        if (memberCount == 0 || uint192(userOp.nonce >> 64) != c.nonceKey) return VALIDATION_FAILED;
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 sequence = uint64(userOp.nonce);

        bytes calldata s = userOp.signature;
        uint256 offset;
        uint256 nextIndex; // entries must name members in strictly increasing order
        uint256 valid;
        while (offset < s.length) {
            uint256 index = uint8(s[offset]);
            if (index < nextIndex || index >= memberCount) return VALIDATION_FAILED;
            (bool ok, uint256 used) = _verifyMember(c.members[index], sequence, userOpHash, s[offset + 1:]);
            if (!ok) return VALIDATION_FAILED;
            offset += 1 + used;
            nextIndex = index + 1;
            ++valid;
        }
        return valid >= c.threshold ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /// @param entry starts at the slot byte: [slot][WOTS signature][path], possibly followed by more entries
    /// @return ok   whether this member's signature verifies
    /// @return used bytes of `entry` that belong to this member
    function _verifyMember(Member storage m, uint256 sequence, bytes32 userOpHash, bytes calldata entry)
        internal
        view
        returns (bool ok, uint256 used)
    {
        uint256 keyIndex;
        {
            uint256 height = m.height;
            used = 1 + SIG_LEN + N * height;
            if (entry.length < used) return (false, 0);
            uint256 slot = uint8(entry[0]);
            if (slot >= SLOTS) return (false, 0);
            keyIndex = sequence * SLOTS + slot;
            if (keyIndex >> height != 0) return (false, 0); // tree exhausted
        }
        ok = _rootMatches(m, keyIndex, userOpHash, entry[1:used]);
    }

    /// @param sigAndPath [WOTS signature][path]
    function _rootMatches(Member storage m, uint256 keyIndex, bytes32 userOpHash, bytes calldata sigAndPath)
        internal
        view
        returns (bool)
    {
        bytes32 root =
            WotsVerifier.computeRoot(PARAMS, m.seed, keyIndex, userOpHash, sigAndPath[:SIG_LEN], sigAndPath[SIG_LEN:]);
        return root != bytes32(0) && root == m.root;
    }

    /// Off-chain messages (ERC-1271) are an open question; until then this validator signs none.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
